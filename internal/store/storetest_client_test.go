// WALD-24: store.Client driven against storetest.Fake, a stateful in-memory
// S3 fake with fault injection (internal/store/storetest). Unlike
// client_test.go and list_test.go, which dial per-test http.HandlerFuncs
// that assert wire details (signature, headers, chunk framing), these
// tests exercise the client end to end against something that actually
// enforces spec/journal/v1's compare-and-swap contract: a pass here means
// the client's retry/classify rules (client.go) did the right thing
// against a real conditional PUT, not a mock that only knows what a test
// author remembered to assert.
//
// Every test below builds its own Fake and its own key (or its own
// sub-test's key), so nothing here depends on another test's state or
// ordering; SetBackoffForTest is package state, so - as every other test
// in this package already does - none of these run under t.Parallel().
//
// Two tests (TestDelayedGetContextDeadline, TestTruncatedPutRetries) send
// a client-side abort or a mid-transfer drop while the fake's handler
// goroutine is still finishing its own work server-side. Per this
// package's existing lesson about a TLS-teardown timing flake, neither
// asserts an exact server-side count in that situation: only the
// client-observed error, or state that is provably settled by the time
// the client call returns.
package store_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/store"
	"github.com/writtendev/walden/internal/store/storetest"
)

// testPrefix is the Journal.Prefix these tests share, so every full
// (bucket-relative) key used to seed the fake or to Inject a Rule is
// testPrefix + "/" + the journal-relative key the client itself uses.
const testPrefix = "v1"

func fullKey(key string) string {
	return testPrefix + "/" + key
}

// newFakeClient starts a Fake and returns a store.Client pointed at it
// (path-style, no TLS, no real DNS) plus the Fake itself, with the
// package's retry backoff shrunk for the test's lifetime.
func newFakeClient(t *testing.T) (*store.Client, *storetest.Fake) {
	t.Helper()
	restore := store.SetBackoffForTest(time.Millisecond, 5*time.Millisecond)
	t.Cleanup(restore)

	fake := storetest.New(t)
	j := &store.Journal{
		Endpoint:    fake.URL(),
		Region:      "us-east-1",
		Bucket:      fake.Bucket(),
		Prefix:      testPrefix,
		PathStyle:   true,
		Credentials: store.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
	}
	return store.NewClient(j), fake
}

// 1. PutIfAbsent on a new key succeeds; the second call at the same key is
// a real ErrPrecondition.
func TestPutIfAbsentThenPrecondition(t *testing.T) {
	c, fake := newFakeClient(t)
	ctx := context.Background()
	body := []byte("first")

	if err := c.PutIfAbsent(ctx, "k", bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatalf("first PutIfAbsent: %v", err)
	}
	if err := c.PutIfAbsent(ctx, "k", bytes.NewReader([]byte("second")), 6); !errors.Is(err, store.ErrPrecondition) {
		t.Fatalf("second PutIfAbsent: errors.Is(_, ErrPrecondition) = false, err = %v", err)
	}
	if b, ok := fake.Object(fullKey("k")); !ok || string(b) != "first" {
		t.Errorf("Object(%q) = %q, %v, want %q, true (untouched)", fullKey("k"), b, ok, "first")
	}
}

// 2. A burst of two 503s (not landed) on PutIfAbsent is retried and
// succeeds: three calls total, the object present.
func TestPutIfAbsentRetriesThroughNotLandedBurst(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.Inject(storetest.Rule{
		Op: storetest.OpPutIfAbsent, Key: fullKey("k"), Call: 1, Count: 2,
		Fault: storetest.Fault{Status: http.StatusServiceUnavailable, Code: "SlowDown"},
	})

	body := []byte("eventually")
	if err := c.PutIfAbsent(context.Background(), "k", bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatalf("PutIfAbsent: %v", err)
	}

	calls := fake.Calls()
	if len(calls) != 3 {
		t.Fatalf("fake saw %d calls, want 3", len(calls))
	}
	for i, c := range calls[:2] {
		if !c.Faulted || c.Landed {
			t.Errorf("call %d: Faulted = %v, Landed = %v, want true, false", i+1, c.Faulted, c.Landed)
		}
	}
	if b, ok := fake.Object(fullKey("k")); !ok || string(b) != "eventually" {
		t.Errorf("Object(%q) = %q, %v, want %q, true", fullKey("k"), b, ok, "eventually")
	}
}

// 3. A burst of MaxAttemptsForTest 503s exhausts retries: ErrStorageUnavailable, object absent.
func TestPutIfAbsentRetryCapExhausted(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.Inject(storetest.Rule{
		Op: storetest.OpPutIfAbsent, Key: fullKey("k"), Call: 1, Count: store.MaxAttemptsForTest,
		Fault: storetest.Fault{Status: http.StatusServiceUnavailable, Code: "SlowDown"},
	})

	body := []byte("never")
	err := c.PutIfAbsent(context.Background(), "k", bytes.NewReader(body), int64(len(body)))
	if !errors.Is(err, store.ErrStorageUnavailable) {
		t.Fatalf("errors.Is(_, ErrStorageUnavailable) = false, err = %v", err)
	}
	if _, ok := fake.Object(fullKey("k")); ok {
		t.Errorf("Object(%q) exists, want absent", fullKey("k"))
	}
}

// 4. Land+Drop on PutIfAbsent: the write actually landed, then the
// connection was cut with no response. The client cannot tell that apart
// from a write that failed, so it must report ErrOutcomeUnknown - never
// ErrStorageUnavailable, and never a resend that would see its own write
// as a rival's 412 - after exactly one call.
func TestPutIfAbsentLandedThenDropped(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.Inject(storetest.Rule{
		Op: storetest.OpPutIfAbsent, Key: fullKey("k"), Call: 1,
		Fault: storetest.Fault{Land: true, Drop: true},
	})

	body := []byte("ambiguous")
	err := c.PutIfAbsent(context.Background(), "k", bytes.NewReader(body), int64(len(body)))
	if !errors.Is(err, store.ErrOutcomeUnknown) {
		t.Fatalf("errors.Is(_, ErrOutcomeUnknown) = false, err = %v", err)
	}
	if errors.Is(err, store.ErrStorageUnavailable) {
		t.Errorf("ErrOutcomeUnknown must not also be ErrStorageUnavailable: %v", err)
	}
	if b, ok := fake.Object(fullKey("k")); !ok || string(b) != "ambiguous" {
		t.Errorf("Object(%q) = %q, %v, want %q, true (the write landed)", fullKey("k"), b, ok, "ambiguous")
	}
	if calls := fake.Calls(); len(calls) != 1 {
		t.Errorf("fake saw %d calls, want exactly 1 (no resend)", len(calls))
	}
}

// 5. Land+500 and bare 500 both end in ErrOutcomeUnknown for a conditional
// PutIfAbsent - a 500 is not among the provably-unapplied statuses, so
// classify cannot tell it apart from one that landed - but only the Land
// case actually leaves the object behind.
func TestPutIfAbsent500IsAlwaysAmbiguous(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.Inject(storetest.Rule{
		Op: storetest.OpPutIfAbsent, Key: fullKey("landed"), Call: 1,
		Fault: storetest.Fault{Land: true, Status: http.StatusInternalServerError, Code: "InternalError"},
	})
	fake.Inject(storetest.Rule{
		Op: storetest.OpPutIfAbsent, Key: fullKey("notlanded"), Call: 1,
		Fault: storetest.Fault{Status: http.StatusInternalServerError, Code: "InternalError"},
	})

	err1 := c.PutIfAbsent(context.Background(), "landed", bytes.NewReader([]byte("x")), 1)
	if !errors.Is(err1, store.ErrOutcomeUnknown) {
		t.Fatalf("landed case: errors.Is(_, ErrOutcomeUnknown) = false, err = %v", err1)
	}
	if b, ok := fake.Object(fullKey("landed")); !ok || string(b) != "x" {
		t.Errorf("Object(%q) = %q, %v, want %q, true", fullKey("landed"), b, ok, "x")
	}

	err2 := c.PutIfAbsent(context.Background(), "notlanded", bytes.NewReader([]byte("y")), 1)
	if !errors.Is(err2, store.ErrOutcomeUnknown) {
		t.Fatalf("not-landed case: errors.Is(_, ErrOutcomeUnknown) = false, err = %v", err2)
	}
	if _, ok := fake.Object(fullKey("notlanded")); ok {
		t.Errorf("Object(%q) exists, want absent", fullKey("notlanded"))
	}
}

// 6. A rival write at call 1 produces a real, non-fabricated 412: the
// fake seeds rival bytes at the key and then evaluates the conditional PUT
// normally, so the precondition failure is the actual check firing.
func TestPutIfAbsentRivalProducesRealPrecondition(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.Inject(storetest.Rule{
		Op: storetest.OpPutIfAbsent, Key: fullKey("k"), Call: 1,
		Fault: storetest.Fault{Rival: []byte("someone else got there first")},
	})

	err := c.PutIfAbsent(context.Background(), "k", bytes.NewReader([]byte("mine")), 4)
	if !errors.Is(err, store.ErrPrecondition) {
		t.Fatalf("errors.Is(_, ErrPrecondition) = false, err = %v", err)
	}
	if b, ok := fake.Object(fullKey("k")); !ok || string(b) != "someone else got there first" {
		t.Errorf("Object(%q) = %q, %v, want the rival bytes", fullKey("k"), b, ok)
	}
}

// 7. A truncated PUT (call 1 cut mid-transfer) is retried, since Put is
// unconditional and idempotent: it succeeds on the second attempt. The
// call log shows call 1 never landed, and the object was never a prefix
// of the final bytes at any point an observer could have read it.
func TestTruncatedPutRetries(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.Inject(storetest.Rule{
		Op: storetest.OpPut, Key: fullKey("k"), Call: 1,
		Fault: storetest.Fault{TruncateBody: 3},
	})

	body := []byte("hello world")
	if err := c.Put(context.Background(), "k", bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if b, ok := fake.Object(fullKey("k")); !ok || string(b) != "hello world" {
		t.Errorf("Object(%q) = %q, %v, want %q, true", fullKey("k"), b, ok, "hello world")
	}

	// Settled by the time Put returned: the retry that succeeded is call
	// 2, sent only after call 1's connection was already torn down.
	calls := fake.Calls()
	if len(calls) < 1 {
		t.Fatalf("fake saw %d calls, want at least 1", len(calls))
	}
	if calls[0].Landed {
		t.Errorf("call 1: Landed = %v (calls = %+v), want false", calls[0].Landed, calls)
	}
}

// 8. A GET truncated mid-stream (headers sent, then the connection is
// dropped after N body bytes) is not retried internally - do already
// committed to the 2xx response - so the failure surfaces as an
// ErrStorageUnavailable from the returned reader's Read, exactly the path
// getBody exists for.
func TestTruncatedGetFailsMidStream(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.SetObject(fullKey("k"), []byte("the quick brown fox"))
	fake.Inject(storetest.Rule{
		Op: storetest.OpGet, Key: fullKey("k"), Call: 1,
		Fault: storetest.Fault{TruncateBody: 5},
	})

	r, err := c.Get(context.Background(), "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer r.Close()

	_, err = io.ReadAll(r)
	if !errors.Is(err, store.ErrStorageUnavailable) {
		t.Fatalf("errors.Is(_, ErrStorageUnavailable) = false, err = %v", err)
	}
}

// 9. A delayed GET whose ctx ends first returns ErrStorageUnavailable
// wrapping context.DeadlineExceeded. This test does not look at the
// fake's state after Get returns: the fake's handler goroutine is still
// sleeping out its Delay when the client gives up, and asserting an exact
// call count against a goroutine that has not necessarily finished yet is
// exactly the timing flake this package has already been burned by once.
func TestDelayedGetContextDeadline(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.SetObject(fullKey("k"), []byte("v"))
	fake.Inject(storetest.Rule{
		Op: storetest.OpGet, Key: fullKey("k"), Call: 1,
		Fault: storetest.Fault{Delay: 200 * time.Millisecond},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := c.Get(ctx, "k")
	if !errors.Is(err, store.ErrStorageUnavailable) {
		t.Fatalf("errors.Is(_, ErrStorageUnavailable) = false, err = %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("errors.Is(_, context.DeadlineExceeded) = false, err = %v", err)
	}
}

// 10. List over paged fake state returns every key, journal-relative and
// ascending, exactly as Get would accept each one back.
func TestListOverPagedFakeState(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.PageSize = 4

	const n = 10
	var want []string
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("streams/repo-alpha/tx/%020d.json", i)
		want = append(want, key)
		fake.SetObject(fullKey(key), []byte("record"))
	}
	// A key outside the listed prefix must never appear in the results.
	fake.SetObject(fullKey("streams/repo-beta/tx/00000000000000000000.json"), []byte("record"))

	var got []string
	err := c.List(context.Background(), "streams/repo-alpha/tx", "", func(key string) error {
		got = append(got, key)
		return nil
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("List returned %d keys, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("key %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// 11. IgnoreCondition models a non-CAS provider (WALD-23's concern): a
// PutIfAbsent against an existing key overwrites silently instead of
// check-and-creating, and the client sees a plain success because the
// fake never sent a 412 at all.
func TestPutIfAbsentIgnoreConditionOverwrites(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.SetObject(fullKey("k"), []byte("old"))
	fake.Inject(storetest.Rule{
		Op: storetest.OpPutIfAbsent, Key: fullKey("k"), Call: 1,
		Fault: storetest.Fault{IgnoreCondition: true},
	})

	if err := c.PutIfAbsent(context.Background(), "k", bytes.NewReader([]byte("new")), 3); err != nil {
		t.Fatalf("PutIfAbsent: %v", err)
	}
	if b, ok := fake.Object(fullKey("k")); !ok || string(b) != "new" {
		t.Errorf("Object(%q) = %q, %v, want %q, true", fullKey("k"), b, ok, "new")
	}
}
