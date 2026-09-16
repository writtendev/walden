package store_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/store"
)

// -----------------------------------------------------------------------
// Test scaffolding: a minimal ListObjectsV2 XML page builder. Everything
// else (newFakeServer, testJournal, fixedClock, verifySignature, xmlError)
// is shared with client_test.go.
// -----------------------------------------------------------------------

// listKeys returns count journal-relative tx keys under prefix, formatted
// the way spec/journal/v1 §7.5 and §12 format a transaction sequence:
// prefix + a 20-digit zero-padded sequence number + ".json".
func listKeys(prefix string, start, count int) []string {
	keys := make([]string, count)
	for i := range keys {
		keys[i] = fmt.Sprintf("%s%020d.json", prefix, start+i)
	}
	return keys
}

// listPageXML renders one ListObjectsV2 page.
func listPageXML(keys []string, truncated bool, nextToken string) []byte {
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult>`)
	for _, k := range keys {
		buf.WriteString("<Contents><Key>" + k + "</Key></Contents>")
	}
	fmt.Fprintf(&buf, "<IsTruncated>%v</IsTruncated>", truncated)
	if nextToken != "" {
		buf.WriteString("<NextContinuationToken>" + nextToken + "</NextContinuationToken>")
	}
	buf.WriteString(`</ListBucketResult>`)
	return buf.Bytes()
}

// -----------------------------------------------------------------------
// 1. Several pages: 2,537 keys, 100 per page (26 pages). fn sees every key
//    exactly once, ascending, with the journal prefix stripped. Request 1
//    carries start-after and no token; every later request carries the
//    previous NextContinuationToken byte for byte, and the fake mints
//    tokens containing '+', '/', and '=' to prove the query encoding
//    round-trips through the wire intact.
// -----------------------------------------------------------------------

func TestListManyPagesInOrder(t *testing.T) {
	const total = 2537
	const pageSize = 100
	const fullPrefix = "v1/streams/repo-alpha/tx/"
	const startAfter = "streams/repo-alpha/tx/00000000000000000099.json"
	const fullStartAfter = "v1/" + startAfter

	allKeys := listKeys(fullPrefix, 0, total)
	numPages := (total + pageSize - 1) / pageSize
	mintedTokens := make([]string, numPages-1)
	for i := range mintedTokens {
		// '+', '/', and '=' are exactly the characters a base64
		// continuation token may contain and a plain query-string encoder
		// must not mangle.
		mintedTokens[i] = fmt.Sprintf("tok/%d+%d=", i, i)
	}

	var reqCount int32
	var mu sync.Mutex
	var seenStartAfter []string
	var seenToken []string

	handler := func(w http.ResponseWriter, r *http.Request) {
		n := int(atomic.AddInt32(&reqCount, 1))
		q := r.URL.Query()
		mu.Lock()
		seenStartAfter = append(seenStartAfter, q.Get("start-after"))
		seenToken = append(seenToken, q.Get("continuation-token"))
		mu.Unlock()

		if q.Get("list-type") != "2" {
			t.Errorf("request %d: list-type = %q, want 2", n, q.Get("list-type"))
		}
		if q.Get("prefix") != fullPrefix {
			t.Errorf("request %d: prefix = %q, want %q", n, q.Get("prefix"), fullPrefix)
		}
		// LIST must address the bucket root, never an object path formed
		// by joining Journal.Prefix onto the request - that would route a
		// real S3 provider to GetObject instead of ListObjectsV2 (see
		// objectURL in client.go and the path-style/virtual-hosted
		// assertions in TestListVirtualHostedAddressesBucketRoot).
		if r.URL.Path != "/test-bucket" {
			t.Errorf("request %d: path = %q, want %q (LIST must address the bucket root, not the journal prefix)", n, r.URL.Path, "/test-bucket")
		}

		page := n - 1
		start := page * pageSize
		end := start + pageSize
		if end > total {
			end = total
		}
		truncated := end < total
		next := ""
		if truncated {
			next = mintedTokens[page]
		}
		w.WriteHeader(http.StatusOK)
		w.Write(listPageXML(allKeys[start:end], truncated, next))
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	var got []string
	err := c.List(context.Background(), "streams/repo-alpha/tx/", startAfter, func(key string) error {
		got = append(got, key)
		return nil
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if int(reqCount) != numPages {
		t.Fatalf("server saw %d requests, want %d", reqCount, numPages)
	}
	if len(got) != total {
		t.Fatalf("fn saw %d keys, want %d", len(got), total)
	}
	for i, key := range got {
		want := fmt.Sprintf("streams/repo-alpha/tx/%020d.json", i)
		if key != want {
			t.Fatalf("key %d = %q, want %q (journal prefix must be stripped, order must be ascending)", i, key, want)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if seenStartAfter[0] != fullStartAfter {
		t.Errorf("request 1 start-after = %q, want %q", seenStartAfter[0], fullStartAfter)
	}
	if seenToken[0] != "" {
		t.Errorf("request 1 continuation-token = %q, want none", seenToken[0])
	}
	for i := 1; i < numPages; i++ {
		if seenStartAfter[i] != "" {
			t.Errorf("request %d start-after = %q, want none (only request 1 sends it)", i+1, seenStartAfter[i])
		}
		want := mintedTokens[i-1]
		if seenToken[i] != want {
			t.Errorf("request %d continuation-token = %q, want %q byte for byte", i+1, seenToken[i], want)
		}
	}
}

// -----------------------------------------------------------------------
// 2. No whole-set buffering (the ticket's gate): the fake blocks page 2
//    until it has seen fn called for every page-1 key. A collect-everything
//    implementation would have to fetch every page before calling fn at
//    all, so it deadlocks here and the test fails on timeout.
// -----------------------------------------------------------------------

func TestListNoWholeSetBuffering(t *testing.T) {
	const pageSize = 50
	const fullPrefix = "v1/streams/repo-alpha/tx/"

	page1 := listKeys(fullPrefix, 0, pageSize)
	page2 := listKeys(fullPrefix, pageSize, pageSize)

	unblockPage2 := make(chan struct{})
	var reqCount int32

	handler := func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&reqCount, 1)
		switch n {
		case 1:
			w.WriteHeader(http.StatusOK)
			w.Write(listPageXML(page1, true, "tok1"))
		case 2:
			select {
			case <-unblockPage2:
			case <-time.After(3 * time.Second):
				t.Errorf("page 2 was requested before fn saw every page-1 key: List is buffering more than one page")
			}
			w.WriteHeader(http.StatusOK)
			w.Write(listPageXML(page2, false, ""))
		default:
			t.Errorf("unexpected request %d", n)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	var got []string
	err := c.List(context.Background(), "streams/repo-alpha/tx/", "", func(key string) error {
		got = append(got, key)
		if len(got) == len(page1) {
			close(unblockPage2)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != len(page1)+len(page2) {
		t.Fatalf("fn saw %d keys, want %d", len(got), len(page1)+len(page2))
	}
}

// -----------------------------------------------------------------------
// 3. Early stop: fn returns an error on key 150. List returns that error
//    and page 3 is never requested.
// -----------------------------------------------------------------------

func TestListEarlyStopOnCallbackError(t *testing.T) {
	const pageSize = 100
	const fullPrefix = "v1/streams/repo-alpha/tx/"

	page1 := listKeys(fullPrefix, 0, pageSize)
	page2 := listKeys(fullPrefix, pageSize, pageSize)
	page3 := listKeys(fullPrefix, 2*pageSize, pageSize)

	var reqCount int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&reqCount, 1)
		w.WriteHeader(http.StatusOK)
		switch n {
		case 1:
			w.Write(listPageXML(page1, true, "tok1"))
		case 2:
			w.Write(listPageXML(page2, true, "tok2"))
		case 3:
			w.Write(listPageXML(page3, false, ""))
		default:
			t.Errorf("unexpected request %d", n)
		}
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	stopErr := errors.New("caller stopped")
	var seen int
	err := c.List(context.Background(), "streams/repo-alpha/tx/", "", func(key string) error {
		seen++
		if seen == 150 {
			return stopErr
		}
		return nil
	})
	if !errors.Is(err, stopErr) {
		t.Fatalf("List error = %v, want %v", err, stopErr)
	}
	if seen != 150 {
		t.Fatalf("fn was called %d times, want 150", seen)
	}
	if reqCount != 2 {
		t.Fatalf("server saw %d requests, want 2 (page 3 must never be requested)", reqCount)
	}
}

// -----------------------------------------------------------------------
// 4. Resume: startAfter yields keys from the following sequence number on.
// -----------------------------------------------------------------------

func TestListResumeWithStartAfter(t *testing.T) {
	const fullPrefix = "v1/streams/repo-alpha/tx/"
	allKeys := listKeys(fullPrefix, 1000, 5) // 1000..1004

	var gotStartAfter string
	handler := func(w http.ResponseWriter, r *http.Request) {
		gotStartAfter = r.URL.Query().Get("start-after")
		w.WriteHeader(http.StatusOK)
		w.Write(listPageXML(allKeys, false, ""))
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	const startAfter = "streams/repo-alpha/tx/00000000000000000999.json"
	var got []string
	err := c.List(context.Background(), "streams/repo-alpha/tx/", startAfter, func(key string) error {
		got = append(got, key)
		return nil
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if gotStartAfter != "v1/"+startAfter {
		t.Errorf("start-after = %q, want %q", gotStartAfter, "v1/"+startAfter)
	}
	if len(got) != 5 || got[0] != "streams/repo-alpha/tx/00000000000000001000.json" {
		t.Fatalf("got %v, want keys from sequence 1000 on", got)
	}
}

// -----------------------------------------------------------------------
// 5. Refusals: truncated with no token, a repeated token, out-of-order
//    keys (within a page and across pages), and a foreign-prefix key each
//    return an error where errors.Is(err, ErrListInconsistent) holds and
//    the message is one line.
// -----------------------------------------------------------------------

func TestListRefusalsInconsistentPagination(t *testing.T) {
	const fullPrefix = "v1/streams/repo-alpha/tx/"

	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "truncated-with-no-token",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write(listPageXML(listKeys(fullPrefix, 0, 2), true, ""))
			},
		},
		{
			name: "repeated-token",
			handler: func() http.HandlerFunc {
				var n int32
				return func(w http.ResponseWriter, r *http.Request) {
					if atomic.AddInt32(&n, 1) == 1 {
						w.WriteHeader(http.StatusOK)
						w.Write(listPageXML(listKeys(fullPrefix, 0, 1), true, "tok1"))
						return
					}
					w.WriteHeader(http.StatusOK)
					w.Write(listPageXML(listKeys(fullPrefix, 1, 1), true, "tok1"))
				}
			}(),
		},
		{
			name: "out-of-order-within-page",
			handler: func(w http.ResponseWriter, r *http.Request) {
				keys := []string{fullPrefix + "b.json", fullPrefix + "a.json"}
				w.WriteHeader(http.StatusOK)
				w.Write(listPageXML(keys, false, ""))
			},
		},
		{
			name: "out-of-order-across-pages",
			handler: func() http.HandlerFunc {
				var n int32
				return func(w http.ResponseWriter, r *http.Request) {
					if atomic.AddInt32(&n, 1) == 1 {
						w.WriteHeader(http.StatusOK)
						w.Write(listPageXML([]string{fullPrefix + "005.json"}, true, "tok1"))
						return
					}
					w.WriteHeader(http.StatusOK)
					w.Write(listPageXML([]string{fullPrefix + "003.json"}, false, ""))
				}
			}(),
		},
		{
			name: "foreign-prefix-key",
			handler: func(w http.ResponseWriter, r *http.Request) {
				keys := []string{"v1/streams/other-repo/tx/00000000000000000000.json"}
				w.WriteHeader(http.StatusOK)
				w.Write(listPageXML(keys, false, ""))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newFakeServer(t, false, tt.handler)
			j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
			c := store.NewClientForTest(j, client, fixedClock(time.Now()))

			err := c.List(context.Background(), "streams/repo-alpha/tx/", "", func(key string) error {
				return nil
			})
			if err == nil {
				t.Fatal("List succeeded, want an inconsistency refusal")
			}
			if !errors.Is(err, store.ErrListInconsistent) {
				t.Errorf("errors.Is(err, ErrListInconsistent) = false, err = %v", err)
			}
			if strings.ContainsAny(err.Error(), "\n\r") {
				t.Errorf("error message is not one line: %q", err.Error())
			}
		})
	}
}

// -----------------------------------------------------------------------
// 6. Failures come from WALD-20: a 503 on page 2 is retried per its policy
//    and the listing completes with no duplicate keys. A 403 surfaces as
//    its permanent error. A cancelled ctx between pages returns ctx.Err().
// -----------------------------------------------------------------------

func TestListRetriesTransientFailureOnAPage(t *testing.T) {
	restore := store.SetBackoffForTest(time.Millisecond, 5*time.Millisecond)
	defer restore()

	const fullPrefix = "v1/streams/repo-alpha/tx/"
	page1 := listKeys(fullPrefix, 0, 2)
	page2 := listKeys(fullPrefix, 2, 2)

	var reqCount int32
	var page2Attempts int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&reqCount, 1)
		if n == 1 {
			w.WriteHeader(http.StatusOK)
			w.Write(listPageXML(page1, true, "tok1"))
			return
		}
		// Every request from here on is an attempt at page 2.
		attempt := atomic.AddInt32(&page2Attempts, 1)
		if attempt <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write(xmlError("SlowDown"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(listPageXML(page2, false, ""))
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	var got []string
	err := c.List(context.Background(), "streams/repo-alpha/tx/", "", func(key string) error {
		got = append(got, key)
		return nil
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := append(append([]string{}, page1...), page2...)
	for i := range want {
		want[i] = strings.TrimPrefix(want[i], "v1/")
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v (no duplicate keys from the retried page)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if page2Attempts != 3 {
		t.Errorf("page 2 was attempted %d times, want 3 (2 failures then success)", page2Attempts)
	}
}

func TestListPermanentFailureSurfacesErrStorageRefused(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write(xmlError("AccessDenied"))
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	err := c.List(context.Background(), "streams/repo-alpha/tx/", "", func(key string) error {
		return nil
	})
	if !errors.Is(err, store.ErrStorageRefused) {
		t.Fatalf("errors.Is(err, ErrStorageRefused) = false, err = %v", err)
	}
	if errors.Is(err, store.ErrStorageUnavailable) {
		t.Errorf("a permanent 403 must not also be ErrStorageUnavailable: %v", err)
	}
	// The refusal must name the listing, not do's "GET <key>" wording -
	// key is always "" for a listing, so an unfixed refusal reads "GET :
	// ..." with neither the verb nor the prefix an operator needs.
	if !strings.HasPrefix(err.Error(), "LIST streams/repo-alpha/tx/:") {
		t.Errorf("error = %q, want it to start with %q", err.Error(), "LIST streams/repo-alpha/tx/:")
	}
	if strings.HasPrefix(err.Error(), "GET") {
		t.Errorf("error = %q, must not surface do's bare GET naming", err.Error())
	}
}

func TestListContextCancelledBetweenPages(t *testing.T) {
	const fullPrefix = "v1/streams/repo-alpha/tx/"
	page1 := listKeys(fullPrefix, 0, 2)

	var reqCount int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		w.WriteHeader(http.StatusOK)
		w.Write(listPageXML(page1, true, "tok1"))
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	ctx, cancel := context.WithCancel(context.Background())
	var seen int
	err := c.List(ctx, "streams/repo-alpha/tx/", "", func(key string) error {
		seen++
		if seen == len(page1) {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("errors.Is(err, context.Canceled) = false, err = %v", err)
	}
	if !errors.Is(err, store.ErrStorageUnavailable) {
		t.Errorf("errors.Is(err, ErrStorageUnavailable) = false, err = %v", err)
	}
	if reqCount != 1 {
		t.Errorf("server saw %d requests, want 1 (page 2 must never be requested once ctx is cancelled)", reqCount)
	}
}

// -----------------------------------------------------------------------
// 7. Signing: every request carries Authorization and
//    X-Amz-Content-Sha256: e3b0…b855 (empty body), verified through the
//    WALD-19 test hooks the same way client_test.go's PUT/GET tests do.
// -----------------------------------------------------------------------

func TestListRequestsAreSigned(t *testing.T) {
	const fullPrefix = "v1/streams/repo-alpha/tx/"
	page1 := listKeys(fullPrefix, 0, 1)

	var sigErr error
	var gotSha256 string
	var reqCount int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		sigErr = verifySignature(t, r)
		gotSha256 = r.Header.Get("X-Amz-Content-Sha256")
		w.WriteHeader(http.StatusOK)
		w.Write(listPageXML(page1, false, ""))
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)))

	err := c.List(context.Background(), "streams/repo-alpha/tx/", "", func(key string) error {
		return nil
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if reqCount != 1 {
		t.Fatalf("server saw %d requests, want 1", reqCount)
	}
	if sigErr != nil {
		t.Errorf("signature verification failed: %v", sigErr)
	}
	if gotSha256 != store.EmptySHA256ForTest {
		t.Errorf("X-Amz-Content-Sha256 = %q, want %q", gotSha256, store.EmptySHA256ForTest)
	}
}

// TestListContinuationTokenRoundTripsWithReservedCharacters confirms the
// bytes a continuation token is sent with are the same bytes the signature
// covers: the token below contains '+', '/', and '=', and the fake server
// reads it back from the actual wire query string (via Go's own request
// parser, not a value List computed) and checks it against the literal
// token verifySignature also recomputed the signature from.
func TestListContinuationTokenRoundTripsWithReservedCharacters(t *testing.T) {
	const fullPrefix = "v1/streams/repo-alpha/tx/"
	const token = "AB+C/D=EF=="
	page1 := listKeys(fullPrefix, 0, 1)
	page2 := listKeys(fullPrefix, 1, 1)

	var gotToken string
	var sigErr error
	var reqCount int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&reqCount, 1)
		if n == 2 {
			gotToken = r.URL.Query().Get("continuation-token")
			sigErr = verifySignature(t, r)
		}
		w.WriteHeader(http.StatusOK)
		if n == 1 {
			w.Write(listPageXML(page1, true, token))
		} else {
			w.Write(listPageXML(page2, false, ""))
		}
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)))

	err := c.List(context.Background(), "streams/repo-alpha/tx/", "", func(key string) error {
		return nil
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if gotToken != token {
		t.Errorf("continuation-token round-tripped as %q, want %q", gotToken, token)
	}
	if sigErr != nil {
		t.Errorf("signature verification failed: %v", sigErr)
	}
}

// -----------------------------------------------------------------------
// 8. LIST addresses the bucket root in both addressing styles, never an
//    object path formed by joining Journal.Prefix - the path-style half
//    of this is asserted inline in TestListManyPagesInOrder above.
// -----------------------------------------------------------------------

func TestListVirtualHostedAddressesBucketRoot(t *testing.T) {
	const fullPrefix = "v1/streams/repo-alpha/tx/"
	page := listKeys(fullPrefix, 0, 1)

	var gotPath, gotHost, gotPrefix string
	var reqCount int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		gotPath = r.URL.Path
		gotHost = r.Host
		gotPrefix = r.URL.Query().Get("prefix")
		w.WriteHeader(http.StatusOK)
		w.Write(listPageXML(page, false, ""))
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", false) // virtual-hosted
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	err := c.List(context.Background(), "streams/repo-alpha/tx/", "", func(key string) error {
		return nil
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if reqCount != 1 {
		t.Fatalf("server saw %d requests, want 1", reqCount)
	}
	if gotHost != "test-bucket.s3.fake.test" {
		t.Errorf("host = %q, want %q", gotHost, "test-bucket.s3.fake.test")
	}
	if gotPath != "/" {
		t.Errorf("path = %q, want %q (bucket root, not the journal prefix)", gotPath, "/")
	}
	if gotPrefix != fullPrefix {
		t.Errorf("prefix param = %q, want %q", gotPrefix, fullPrefix)
	}
}

// -----------------------------------------------------------------------
// 9. Listing the whole journal (prefix == "") must not also return a
//    sibling journal's keys sharing the same bucket, e.g. "v1-staging"
//    next to "v1". The S3 prefix= sent must be the journal prefix with a
//    trailing "/", and any key not starting with that is refused.
// -----------------------------------------------------------------------

func TestListEmptyPrefixExcludesSiblingJournal(t *testing.T) {
	var gotPrefix string
	handler := func(w http.ResponseWriter, r *http.Request) {
		gotPrefix = r.URL.Query().Get("prefix")
		w.WriteHeader(http.StatusOK)
		// Simulates what a real S3 prefix of bare "v1" (no trailing
		// slash) would additionally match: a sibling journal's key.
		w.Write(listPageXML([]string{"v1-staging/streams/repo-alpha/tx/00000000000000000000.json"}, false, ""))
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	var called bool
	err := c.List(context.Background(), "", "", func(key string) error {
		called = true
		return nil
	})
	if gotPrefix != "v1/" {
		t.Errorf("prefix param = %q, want %q (trailing slash, so it cannot match a sibling journal)", gotPrefix, "v1/")
	}
	if err == nil {
		t.Fatal("List succeeded, want a refusal for a key outside the journal")
	}
	if !errors.Is(err, store.ErrListInconsistent) {
		t.Errorf("errors.Is(err, ErrListInconsistent) = false, err = %v", err)
	}
	if called {
		t.Error("fn was called with a sibling journal's key")
	}
}

// -----------------------------------------------------------------------
// 10. A 2xx response whose XML root is not ListBucketResult must not be
//     silently treated as a complete, empty listing.
// -----------------------------------------------------------------------

func TestListWrongXMLRootIsRefused(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult></ListAllMyBucketsResult>`))
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	var called bool
	err := c.List(context.Background(), "streams/repo-alpha/tx/", "", func(key string) error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("List succeeded on a non-ListBucketResult root, want a refusal")
	}
	if !errors.Is(err, store.ErrStorageUnavailable) {
		t.Errorf("errors.Is(err, ErrStorageUnavailable) = false, err = %v", err)
	}
	if called {
		t.Error("fn was called from a page that never decoded as ListBucketResult")
	}
}

// -----------------------------------------------------------------------
// 11. A page body over the bound, or a single key over S3's own key-length
//     limit, is refused instead of decoded and handed to fn.
// -----------------------------------------------------------------------

func TestListPageBodyOverBoundIsRefused(t *testing.T) {
	hugeKey := "v1/streams/repo-alpha/tx/" + strings.Repeat("x", 9<<20) // 9 MiB, over the 8 MiB bound
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(listPageXML([]string{hugeKey}, false, ""))
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	var called bool
	err := c.List(context.Background(), "streams/repo-alpha/tx/", "", func(key string) error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("List succeeded on an oversized page, want a refusal")
	}
	if !errors.Is(err, store.ErrStorageUnavailable) {
		t.Errorf("errors.Is(err, ErrStorageUnavailable) = false, err = %v", err)
	}
	if called {
		t.Error("fn was called with a key from an oversized page")
	}
}

func TestListKeyLongerThanS3LimitIsRefused(t *testing.T) {
	const fullPrefix = "v1/streams/repo-alpha/tx/"
	longKey := fullPrefix + strings.Repeat("x", 1025) // over S3's 1024-byte key limit, well under the page-body bound
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(listPageXML([]string{longKey}, false, ""))
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	var called bool
	err := c.List(context.Background(), "streams/repo-alpha/tx/", "", func(key string) error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("List succeeded on a key over S3's length limit, want a refusal")
	}
	if !errors.Is(err, store.ErrListInconsistent) {
		t.Errorf("errors.Is(err, ErrListInconsistent) = false, err = %v", err)
	}
	if called {
		t.Error("fn was called with a key over S3's length limit")
	}
}

// -----------------------------------------------------------------------
// 12. A continuation token that repeats one from an earlier page - not
//     just the immediately preceding one - is refused instead of spinning:
//     a provider alternating "A, B, A, B" across empty truncated pages
//     passes the immediate-repeat check and the key-ordering check (there
//     are no keys), so only remembering every token seen closes the loop.
// -----------------------------------------------------------------------

func TestListNonAdjacentRepeatedTokenIsRefused(t *testing.T) {
	const fullPrefix = "v1/streams/repo-alpha/tx/"
	var reqCount int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&reqCount, 1)
		w.WriteHeader(http.StatusOK)
		if n%2 == 1 {
			w.Write(listPageXML(nil, true, "A"))
		} else {
			w.Write(listPageXML(nil, true, "B"))
		}
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	err := c.List(context.Background(), "streams/repo-alpha/tx/", "", func(key string) error {
		return nil
	})
	if err == nil {
		t.Fatal("List succeeded on a cycling continuation token, want a refusal")
	}
	if !errors.Is(err, store.ErrListInconsistent) {
		t.Errorf("errors.Is(err, ErrListInconsistent) = false, err = %v", err)
	}
	// Must stop within a handful of requests, not spin: token "A" (request
	// 1), "B" (request 2), then "A" again (request 3) is where the repeat
	// is detected.
	if reqCount > 4 {
		t.Errorf("server saw %d requests, want at most 4 (List must stop as soon as a token repeats, not spin)", reqCount)
	}
}
