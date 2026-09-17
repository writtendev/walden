// WALD-25: the object-storage conformance suite. Every other test in this
// package (client_test.go, list_test.go, storetest_client_test.go) drives
// store.Client against a fake or a from-scratch httptest.Server that only
// knows what its author remembered to enforce. This file drives the real
// store.Client against a real S3-compatible bucket, so a pass here is
// evidence about spec/journal/v1 section 11.1's contract - conditional
// PUT, a create/get/list round trip, and the outcome-unknown/no-resend
// rule - as some real provider actually implements it, not as the fake
// assumes it.
//
// WALDEN_CONFORMANCE_JOURNAL is a test-only environment variable, read
// only from this _test.go file, exactly like WALDEN_LEAK_ITERATIONS in
// journal_leak_test.go. It is not one of walden's five knobs
// (ARCHITECTURE.md's "Configuration surface"): nothing outside `go test`
// ever reads it. Unset or empty, every TestConformance* test below skips,
// so `go test ./...` stays green with no bucket in reach. Set to a journal
// URL walden can resolve, every test runs for real; set to something
// store.ResolveJournal cannot parse, conformanceClient calls t.Fatal, not
// t.Skip - a broken URL is a broken test run, not something to silently
// wave through.
//
// The store.Client has no arbitrary-key DELETE (by design: see client.go
// and journal.go's file comments), so nothing here cleans up after
// itself. Every test asks conformanceClient for its own random prefix - a
// timestamp plus 8 bytes of crypto/rand - so repeated and concurrent runs
// against the same bucket never collide and never need to. The CI bucket
// dies with the job; a real provider's bucket needs a lifecycle rule,
// which is WALD-113's job, not this file's.
package store_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/store"
)

// envConformanceJournal is the test-only env var this file reads. See the
// file comment above: it is not a walden knob.
const envConformanceJournal = "WALDEN_CONFORMANCE_JOURNAL"

// conformanceClient resolves WALDEN_CONFORMANCE_JOURNAL into a
// store.Client scoped to a prefix unique to this call, and returns the
// resolved Journal it built. It calls t.Skip when the env var is unset or
// empty, and t.Fatal when it is set but store.ResolveJournal cannot
// resolve it. name distinguishes one test's prefix from another's, since
// more than one test in this file runs in the same process.
func conformanceClient(t *testing.T, name string) (*store.Client, *store.Journal) {
	t.Helper()

	raw, ok := os.LookupEnv(envConformanceJournal)
	if !ok || raw == "" {
		t.Skipf("%s is not set; skipping conformance suite", envConformanceJournal)
	}

	j, err := store.ResolveJournal(raw, os.LookupEnv)
	if err != nil {
		// err is already a *refusal.Refusal scrubbed of the raw URL (see
		// journal.go's guardCredentials); never log raw here either.
		t.Fatalf("resolve %s: %v", envConformanceJournal, err)
	}

	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatalf("crypto/rand.Read: %v", err)
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	j.Prefix = path.Join(j.Prefix, "conformance-"+stamp+"-"+hex.EncodeToString(suffix[:]), name)

	t.Logf("conformance: endpoint=%s bucket=%s prefix=%s", j.Endpoint, j.Bucket, j.Prefix)
	return store.NewClient(j), j
}

// 1. A PutIfAbsent on a new key succeeds. A second PutIfAbsent at the same
// key, with different bytes, is refused with ErrPrecondition (and not
// ErrOutcomeUnknown), and the original bytes are untouched
// (spec/journal/v1 section 11.1, items 2-3).
func TestConformancePutIfAbsentCreatesThenRefuses(t *testing.T) {
	c, _ := conformanceClient(t, "put-if-absent")
	ctx := context.Background()
	const key = "put-if-absent/k"

	first := []byte("first-value")
	if err := c.PutIfAbsent(ctx, key, bytes.NewReader(first), int64(len(first))); err != nil {
		t.Fatalf("first PutIfAbsent: %v", err)
	}

	second := []byte("second-value-is-different")
	err := c.PutIfAbsent(ctx, key, bytes.NewReader(second), int64(len(second)))
	if !errors.Is(err, store.ErrPrecondition) {
		t.Fatalf("second PutIfAbsent: errors.Is(_, ErrPrecondition) = false, err = %v", err)
	}
	if errors.Is(err, store.ErrOutcomeUnknown) {
		t.Fatalf("second PutIfAbsent: errors.Is(_, ErrOutcomeUnknown) = true, want false")
	}

	got := mustGet(ctx, t, c, key)
	if !bytes.Equal(got, first) {
		t.Fatalf("Get after refused PutIfAbsent = %q, want %q (untouched)", got, first)
	}
}

// 2. 8 goroutines race PutIfAbsent on one key, each with a distinct body.
// Exactly one wins (nil error); the rest see ErrPrecondition. Any other
// error fails the test outright: this is a property of atomic creation,
// not a count that tolerates noise. Get returns the winner's body.
func TestConformancePutIfAbsentConcurrentSingleWinner(t *testing.T) {
	c, _ := conformanceClient(t, "concurrent-winner")
	ctx := context.Background()
	const key = "concurrent-winner/k"
	const n = 8

	bodies := make([][]byte, n)
	for i := range bodies {
		bodies[i] = []byte(fmt.Sprintf("racer-%d-of-%d", i, n))
	}

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = c.PutIfAbsent(ctx, key, bytes.NewReader(bodies[i]), int64(len(bodies[i])))
		}(i)
	}
	wg.Wait()

	winner := -1
	refused := 0
	for i, err := range errs {
		switch {
		case err == nil:
			if winner != -1 {
				t.Fatalf("racer %d and racer %d both won PutIfAbsent(%s)", winner, i, key)
			}
			winner = i
		case errors.Is(err, store.ErrPrecondition):
			refused++
		default:
			t.Fatalf("racer %d: unexpected error: %v", i, err)
		}
	}
	if winner == -1 {
		t.Fatalf("no racer won PutIfAbsent(%s): errs = %v", key, errs)
	}
	if refused != n-1 {
		t.Fatalf("refused = %d, want %d: errs = %v", refused, n-1, errs)
	}

	got := mustGet(ctx, t, c, key)
	if !bytes.Equal(got, bodies[winner]) {
		t.Fatalf("Get = %q, want racer %d's body %q", got, winner, bodies[winner])
	}
}

// 3. Put then Get is byte-equal at three sizes, including one that
// straddles several 64 KiB aws-chunked frames without dividing evenly. A
// second Put to the same key replaces the bytes (spec/journal/v1 section
// 6.4). Get on a key this test never wrote gives ErrObjectNotFound.
func TestConformanceRoundTrip(t *testing.T) {
	c, _ := conformanceClient(t, "round-trip")
	ctx := context.Background()

	for _, size := range []int{0, 5, 200<<10 + 7} {
		key := fmt.Sprintf("round-trip/%d", size)

		body := make([]byte, size)
		if _, err := rand.Read(body); err != nil {
			t.Fatalf("crypto/rand.Read: %v", err)
		}
		if err := c.Put(ctx, key, bytes.NewReader(body), int64(size)); err != nil {
			t.Fatalf("Put(size=%d): %v", size, err)
		}
		if got := mustGet(ctx, t, c, key); !bytes.Equal(got, body) {
			t.Fatalf("Get(size=%d) = %d bytes, want %d bytes (mismatch)", size, len(got), len(body))
		}

		replacement := append([]byte("replaced:"), body...)
		if err := c.Put(ctx, key, bytes.NewReader(replacement), int64(len(replacement))); err != nil {
			t.Fatalf("replacing Put(size=%d): %v", size, err)
		}
		if got := mustGet(ctx, t, c, key); !bytes.Equal(got, replacement) {
			t.Fatalf("Get after replacing Put(size=%d) = %d bytes, want %d bytes (mismatch)", size, len(got), len(replacement))
		}
	}

	if _, err := c.Get(ctx, "round-trip/never-written"); !errors.Is(err, store.ErrObjectNotFound) {
		t.Fatalf("Get on unwritten key: errors.Is(_, ErrObjectNotFound) = false, err = %v", err)
	}
}

// 4. 1001 keys, written with PutIfAbsent through 8 workers, force a real
// continuation token at the 1000-key provider default. A decoy under a
// sibling prefix and a decoy one level up prove List(prefix) filters, and
// this test's own random Journal.Prefix proves List("") sees only what
// this test wrote (prefix isolation).
func TestConformanceListPagesInOrder(t *testing.T) {
	c, _ := conformanceClient(t, "list-pages")
	ctx := context.Background()

	const n = 1001
	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprintf("tx/%020d.json", i)
	}

	const workers = 8
	work := make(chan int)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				body := []byte("v")
				if err := c.PutIfAbsent(ctx, keys[i], bytes.NewReader(body), int64(len(body))); err != nil {
					errs <- fmt.Errorf("PutIfAbsent(%s): %w", keys[i], err)
				}
			}
		}()
	}
	for i := range keys {
		work <- i
	}
	close(work)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if t.Failed() {
		t.FailNow()
	}

	decoy := []byte("decoy")
	if err := c.PutIfAbsent(ctx, "txx/decoy", bytes.NewReader(decoy), int64(len(decoy))); err != nil {
		t.Fatalf("PutIfAbsent(txx/decoy): %v", err)
	}
	if err := c.PutIfAbsent(ctx, "tx-sibling", bytes.NewReader(decoy), int64(len(decoy))); err != nil {
		t.Fatalf("PutIfAbsent(tx-sibling): %v", err)
	}

	listed := mustListAll(ctx, t, c, "tx/", "")
	if len(listed) != n {
		t.Fatalf("List(tx/, \"\") returned %d keys, want %d", len(listed), n)
	}
	for i, key := range listed {
		if key != keys[i] {
			t.Fatalf("List(tx/, \"\")[%d] = %q, want %q", i, key, keys[i])
		}
	}

	if _, err := c.Get(ctx, listed[0]); err != nil {
		t.Fatalf("Get(%s): %v", listed[0], err)
	}

	startAfter := keys[499]
	page := mustListAll(ctx, t, c, "tx/", startAfter)
	want := keys[500:]
	if len(page) != len(want) {
		t.Fatalf("List(tx/, startAfter=%s) returned %d keys, want %d", startAfter, len(page), len(want))
	}
	for i, key := range page {
		if key != want[i] {
			t.Fatalf("List(tx/, startAfter=%s)[%d] = %q, want %q", startAfter, i, key, want[i])
		}
	}

	all := mustListAll(ctx, t, c, "", "")
	if len(all) != n+2 {
		t.Fatalf("List(\"\", \"\") returned %d keys, want %d (prefix isolation)", len(all), n+2)
	}
}

// 5. A conditional PUT whose response is dropped after the request fully
// lands must not be resent: PutIfAbsent returns ErrOutcomeUnknown (never
// ErrPrecondition), the proxy in front of the real bucket saw exactly one
// PUT, and the write is provably there - a direct Get returns the bytes,
// and a direct PutIfAbsent on the same key gets a real ErrPrecondition
// (spec/journal/v1 section 11.4, item 6).
//
// This only runs when the resolved endpoint is plain http and path-style:
// a proxy in front of anything else can forward nothing, since it can't
// terminate TLS or stand in for a virtual host.
func TestConformanceOutcomeUnknownIsNotResent(t *testing.T) {
	c, j := conformanceClient(t, "outcome-unknown")
	ctx := context.Background()
	const key = "outcome-unknown/k"

	upstream, err := url.Parse(j.Endpoint)
	if err != nil {
		t.Fatalf("parse resolved endpoint %q: %v", j.Endpoint, err)
	}
	if upstream.Scheme != "http" || !j.PathStyle {
		t.Skip("conformance endpoint is not plain http/path-style; a proxy here can't re-sign TLS or a virtual host")
	}

	var puts atomic.Int64
	transport := &http.Transport{}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			puts.Add(1)
		}

		out := r.Clone(r.Context())
		out.RequestURI = ""
		out.URL.Scheme = upstream.Scheme
		out.URL.Host = upstream.Host
		out.Host = r.Host // keep the proxy's Host header: it is what was signed.

		if resp, err := transport.RoundTrip(out); err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}

		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		if conn, _, err := hj.Hijack(); err == nil {
			conn.Close()
		}
	}))
	defer proxy.Close()

	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	proxyJournal := *j
	proxyJournal.Endpoint = proxyURL.Scheme + "://" + proxyURL.Host
	proxyClient := store.NewClient(&proxyJournal)

	body := []byte("dropped-response-but-landed")
	err = proxyClient.PutIfAbsent(ctx, key, bytes.NewReader(body), int64(len(body)))
	if !errors.Is(err, store.ErrOutcomeUnknown) {
		t.Fatalf("PutIfAbsent through dropped-response proxy: errors.Is(_, ErrOutcomeUnknown) = false, err = %v", err)
	}
	if errors.Is(err, store.ErrPrecondition) {
		t.Fatalf("PutIfAbsent through dropped-response proxy: errors.Is(_, ErrPrecondition) = true, want false")
	}
	if got := puts.Load(); got != 1 {
		t.Fatalf("proxy saw %d PUTs, want exactly 1 (a resend would mean this rule failed)", got)
	}

	if got := mustGet(ctx, t, c, key); !bytes.Equal(got, body) {
		t.Fatalf("direct Get after dropped-response PutIfAbsent = %q, want %q (write landed)", got, body)
	}

	resend := []byte("a-resend-would-see-this-refused")
	resendErr := c.PutIfAbsent(ctx, key, bytes.NewReader(resend), int64(len(resend)))
	if !errors.Is(resendErr, store.ErrPrecondition) {
		t.Fatalf("direct PutIfAbsent on the landed key: errors.Is(_, ErrPrecondition) = false, err = %v", resendErr)
	}
}

// mustGet Gets key through c and returns its bytes, failing t on any
// error.
func mustGet(ctx context.Context, t *testing.T, c *store.Client, key string) []byte {
	t.Helper()
	rc, err := c.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get(%s): %v", key, err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read Get(%s) body: %v", key, err)
	}
	return got
}

// mustListAll lists every key under prefix, journal-relative and in the
// order List delivers them, failing t on any error.
func mustListAll(ctx context.Context, t *testing.T, c *store.Client, prefix, startAfter string) []string {
	t.Helper()
	var keys []string
	if err := c.List(ctx, prefix, startAfter, func(key string) error {
		keys = append(keys, key)
		return nil
	}); err != nil {
		t.Fatalf("List(%q, startAfter=%q): %v", prefix, startAfter, err)
	}
	return keys
}
