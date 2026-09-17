package journal_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/store"
	"github.com/writtendev/walden/internal/store/storetest"
)

// newLeaseClient starts a storetest.Fake and returns a store.Client pointed
// at it with no bucket-level key prefix, so a journal-relative key (what
// journal.TxKey returns) is exactly the fake's own full key - there is no
// second, unrelated "v1" to keep straight from the format version TxKey
// already bakes in.
func newLeaseClient(t *testing.T) (*store.Client, *storetest.Fake) {
	t.Helper()
	fake := storetest.New(t)
	j := &store.Journal{
		Endpoint:    fake.URL(),
		Region:      "us-east-1",
		Bucket:      fake.Bucket(),
		PathStyle:   true,
		Credentials: store.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
	}
	return store.NewClient(j), fake
}

// putBody is a small, reusable conditional-append payload; its bytes are
// never inspected by these tests, only its presence or absence at a key.
var putBody = []byte(`{}`)

func putIfAbsentAt(ctx context.Context, c *store.Client, key string) error {
	return c.PutIfAbsent(ctx, key, bytes.NewReader(putBody), int64(len(putBody)))
}

// 1. Open on an empty stream leases seq 0; open on a stream whose highest
// tx/ key is 00000000000000000004 leases 5.
func TestOpenEmptyStreamLeasesZero(t *testing.T) {
	c, _ := newLeaseClient(t)
	leases := journal.NewLeases(c)

	lease, err := leases.Open(context.Background(), "repo-empty")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	seq, err := lease.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if seq != 0 {
		t.Errorf("Next() = %d, want 0", seq)
	}
}

func TestOpenExistingStreamLeasesHeadPlusOne(t *testing.T) {
	c, fake := newLeaseClient(t)
	fake.SetObject(journal.TxKey("repo-alpha", 4), []byte(`{"seq":"4"}`))

	leases := journal.NewLeases(c)
	lease, err := leases.Open(context.Background(), "repo-alpha")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	seq, err := lease.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if seq != 5 {
		t.Errorf("Next() = %d, want 5 (head 4 + 1)", seq)
	}
}

// 2. Head discovery spanning more than one listing page (Fake.PageSize)
// still yields the true head.
func TestOpenHeadDiscoverySpansPages(t *testing.T) {
	c, fake := newLeaseClient(t)
	fake.PageSize = 2
	for seq := journal.Seq(0); seq < 5; seq++ {
		fake.SetObject(journal.TxKey("repo-alpha", seq), []byte(`{}`))
	}

	leases := journal.NewLeases(c)
	lease, err := leases.Open(context.Background(), "repo-alpha")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	seq, err := lease.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if seq != 5 {
		t.Errorf("Next() = %d, want 5 (head 4 + 1, discovered across %d-key pages)", seq, fake.PageSize)
	}
}

// 3. A 412 from PutIfAbsent on the leased key, reported through Failed,
// fences the stream: the error is exactly section 11.5 item 1's string,
// errors.Is(err, journal.ErrFenced) holds, and the next Next() and Open()
// refuse with section 11.5 item 2's string having made zero further
// requests - asserted against Fake.Calls().
func TestFailedPreconditionFencesStream(t *testing.T) {
	c, fake := newLeaseClient(t)
	leases := journal.NewLeases(c)
	ctx := context.Background()

	lease, err := leases.Open(ctx, "repo-alpha")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	seq, err := lease.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}

	// A rival writer's record already sits at the key this Next() promised,
	// so the conditional PUT below fails with a real, storage-proven 412 -
	// never a status this test fabricates without the fake actually
	// enforcing the condition.
	fake.SetObject(journal.TxKey("repo-alpha", seq), []byte(`{}`))
	putErr := putIfAbsentAt(ctx, c, journal.TxKey("repo-alpha", seq))
	if !errors.Is(putErr, store.ErrPrecondition) {
		t.Fatalf("PutIfAbsent: errors.Is(_, ErrPrecondition) = false, err = %v", putErr)
	}

	failErr := lease.Failed(seq, putErr)
	want := fmt.Sprintf("refusal: push failed: stream repo-alpha fenced by concurrent writer at seq %d (instance is fenced for this stream; restart or check active writer)", seq)
	if failErr == nil || failErr.Error() != want {
		t.Fatalf("Failed error:\ngot:  %v\nwant: %q", failErr, want)
	}
	if !errors.Is(failErr, journal.ErrFenced) {
		t.Errorf("expected Failed's error to match journal.ErrFenced")
	}

	callsBefore := len(fake.Calls())

	wantPerm := "refusal: push failed: stream repo-alpha is permanently fenced on this instance (restart walden process to re-materialize from journal)"
	if _, err := lease.Next(); err == nil || err.Error() != wantPerm {
		t.Errorf("Next() after fencing = %v, want %q", err, wantPerm)
	}
	if _, err := leases.Open(ctx, "repo-alpha"); err == nil || err.Error() != wantPerm {
		t.Errorf("Open() after fencing = %v, want %q", err, wantPerm)
	}

	if got := len(fake.Calls()); got != callsBefore {
		t.Errorf("fake saw %d further requests after fencing, want 0", got-callsBefore)
	}
}

// 4. A dropped response injected through storetest (store's
// ErrOutcomeUnknown path) fences the same stream the same way, with
// section 11.5 item 7's string.
func TestFailedOutcomeUnknownFencesStream(t *testing.T) {
	c, fake := newLeaseClient(t)
	leases := journal.NewLeases(c)
	ctx := context.Background()

	lease, err := leases.Open(ctx, "repo-beta")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	seq, err := lease.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}

	key := journal.TxKey("repo-beta", seq)
	// Land:true means the fake actually stores the write - it applied -
	// before Drop severs the connection with no response, the exact
	// ambiguity store.ErrOutcomeUnknown exists for.
	fake.Inject(storetest.Rule{
		Op:    storetest.OpPutIfAbsent,
		Key:   key,
		Call:  1,
		Fault: storetest.Fault{Drop: true, Land: true},
	})

	putErr := putIfAbsentAt(ctx, c, key)
	if !errors.Is(putErr, store.ErrOutcomeUnknown) {
		t.Fatalf("PutIfAbsent: errors.Is(_, ErrOutcomeUnknown) = false, err = %v", putErr)
	}

	failErr := lease.Failed(seq, putErr)
	want := fmt.Sprintf("refusal: push failed: stream repo-beta append at seq %d has unknown outcome (instance is fenced for this stream; restart walden process to re-materialize from journal)", seq)
	if failErr == nil || failErr.Error() != want {
		t.Fatalf("Failed error:\ngot:  %v\nwant: %q", failErr, want)
	}
	if !errors.Is(failErr, journal.ErrFenced) {
		t.Errorf("expected Failed's error to match journal.ErrFenced")
	}
	if !lease.Fencer().IsFenced("repo-beta") {
		t.Errorf("expected repo-beta to be fenced")
	}
}

// 5. Stream isolation: fencing repo-alpha leaves repo-beta and _meta
// leasing and appending normally, each on its own counter (section 9.1,
// section 11.4 item 5).
func TestStreamIsolationAcrossFencing(t *testing.T) {
	c, fake := newLeaseClient(t)
	leases := journal.NewLeases(c)
	ctx := context.Background()

	alpha, err := leases.Open(ctx, "repo-alpha")
	if err != nil {
		t.Fatalf("Open(repo-alpha): %v", err)
	}
	beta, err := leases.Open(ctx, "repo-beta")
	if err != nil {
		t.Fatalf("Open(repo-beta): %v", err)
	}
	meta, err := leases.Open(ctx, journal.MetaStreamID)
	if err != nil {
		t.Fatalf("Open(_meta): %v", err)
	}

	// Fence repo-alpha via a genuine 412.
	seqA, err := alpha.Next()
	if err != nil {
		t.Fatalf("alpha.Next: %v", err)
	}
	fake.SetObject(journal.TxKey("repo-alpha", seqA), []byte(`{}`))
	putErr := putIfAbsentAt(ctx, c, journal.TxKey("repo-alpha", seqA))
	if !errors.Is(putErr, store.ErrPrecondition) {
		t.Fatalf("PutIfAbsent(repo-alpha): errors.Is(_, ErrPrecondition) = false, err = %v", putErr)
	}
	if failErr := alpha.Failed(seqA, putErr); !errors.Is(failErr, journal.ErrFenced) {
		t.Fatalf("alpha.Failed: expected ErrFenced, got %v", failErr)
	}

	// repo-beta keeps writing and counting on its own, unaffected.
	seqB, err := beta.Next()
	if err != nil {
		t.Fatalf("beta.Next: %v", err)
	}
	if seqB != 0 {
		t.Errorf("beta.Next() = %d, want 0", seqB)
	}
	if err := putIfAbsentAt(ctx, c, journal.TxKey("repo-beta", seqB)); err != nil {
		t.Fatalf("PutIfAbsent(repo-beta): %v", err)
	}
	beta.Landed(seqB)
	if seqB2, err := beta.Next(); err != nil || seqB2 != 1 {
		t.Errorf("beta.Next() after Landed = (%d, %v), want (1, nil)", seqB2, err)
	}

	// _meta keeps writing and counting on its own too.
	seqM, err := meta.Next()
	if err != nil {
		t.Fatalf("meta.Next: %v", err)
	}
	if seqM != 0 {
		t.Errorf("meta.Next() = %d, want 0", seqM)
	}
	if err := putIfAbsentAt(ctx, c, journal.TxKey(journal.MetaStreamID, seqM)); err != nil {
		t.Fatalf("PutIfAbsent(_meta): %v", err)
	}
	meta.Landed(seqM)

	// alpha stays fenced throughout.
	if _, err := alpha.Next(); !errors.Is(err, journal.ErrFenced) {
		t.Errorf("expected repo-alpha to remain fenced, got %v", err)
	}
	if beta.Fencer().IsFenced("repo-beta") {
		t.Errorf("stream isolation violated: repo-beta fenced by repo-alpha's conflict")
	}
	if meta.Fencer().IsFenced(journal.MetaStreamID) {
		t.Errorf("stream isolation violated: _meta fenced by repo-alpha's conflict")
	}
}

// The _meta stream's own two refusals use the "meta operation failed"
// wording (section 11.5 items 3, 4), exercised the same way test 3 above
// exercises the repo-stream wording - through a genuine 412 reported to
// Failed.
func TestMetaStreamConflictRefusalWording(t *testing.T) {
	c, fake := newLeaseClient(t)
	leases := journal.NewLeases(c)
	ctx := context.Background()

	meta, err := leases.Open(ctx, journal.MetaStreamID)
	if err != nil {
		t.Fatalf("Open(_meta): %v", err)
	}
	seq, err := meta.Next()
	if err != nil {
		t.Fatalf("meta.Next: %v", err)
	}

	fake.SetObject(journal.TxKey(journal.MetaStreamID, seq), []byte(`{}`))
	putErr := putIfAbsentAt(ctx, c, journal.TxKey(journal.MetaStreamID, seq))
	if !errors.Is(putErr, store.ErrPrecondition) {
		t.Fatalf("PutIfAbsent(_meta): errors.Is(_, ErrPrecondition) = false, err = %v", putErr)
	}

	failErr := meta.Failed(seq, putErr)
	want := fmt.Sprintf("refusal: meta operation failed: stream _meta fenced by concurrent writer at seq %d (instance is fenced for this stream; restart or check active writer)", seq)
	if failErr == nil || failErr.Error() != want {
		t.Fatalf("Failed error:\ngot:  %v\nwant: %q", failErr, want)
	}

	wantPerm := "refusal: meta operation failed: stream _meta is permanently fenced on this instance (restart walden process to re-materialize from journal)"
	if _, err := meta.Next(); err == nil || err.Error() != wantPerm {
		t.Errorf("meta.Next() after fencing = %v, want %q", err, wantPerm)
	}
}

// The _meta stream's outcome-unknown refusal uses the "meta operation
// failed" wording too (section 11.5 item 8), the meta counterpart of test 4
// above.
func TestMetaStreamOutcomeUnknownRefusalWording(t *testing.T) {
	c, fake := newLeaseClient(t)
	leases := journal.NewLeases(c)
	ctx := context.Background()

	meta, err := leases.Open(ctx, journal.MetaStreamID)
	if err != nil {
		t.Fatalf("Open(_meta): %v", err)
	}
	seq, err := meta.Next()
	if err != nil {
		t.Fatalf("meta.Next: %v", err)
	}

	key := journal.TxKey(journal.MetaStreamID, seq)
	fake.Inject(storetest.Rule{
		Op:    storetest.OpPutIfAbsent,
		Key:   key,
		Call:  1,
		Fault: storetest.Fault{Drop: true, Land: true},
	})

	putErr := putIfAbsentAt(ctx, c, key)
	if !errors.Is(putErr, store.ErrOutcomeUnknown) {
		t.Fatalf("PutIfAbsent(_meta): errors.Is(_, ErrOutcomeUnknown) = false, err = %v", putErr)
	}

	failErr := meta.Failed(seq, putErr)
	want := fmt.Sprintf("refusal: meta operation failed: stream _meta append at seq %d has unknown outcome (instance is fenced for this stream; restart walden process to re-materialize from journal)", seq)
	if failErr == nil || failErr.Error() != want {
		t.Fatalf("Failed error:\ngot:  %v\nwant: %q", failErr, want)
	}
}

// 6. A retryable failure (ErrStorageUnavailable) neither fences nor
// consumes the sequence: the same seq is offered again.
func TestFailedRetryableDoesNotFenceOrConsumeSeq(t *testing.T) {
	c, fake := newLeaseClient(t)
	leases := journal.NewLeases(c)
	ctx := context.Background()

	lease, err := leases.Open(ctx, "repo-gamma")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	seq, err := lease.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}

	key := journal.TxKey("repo-gamma", seq)
	// Count 4 matches the client's own maxAttempts (client.go), so every
	// attempt the client makes fails the same way and it gives up with
	// ErrStorageUnavailable rather than retrying forever or succeeding.
	fake.Inject(storetest.Rule{
		Op:    storetest.OpPutIfAbsent,
		Key:   key,
		Call:  1,
		Count: 4,
		Fault: storetest.Fault{Status: 503, Code: "ServiceUnavailable"},
	})

	putErr := putIfAbsentAt(ctx, c, key)
	if !errors.Is(putErr, store.ErrStorageUnavailable) {
		t.Fatalf("PutIfAbsent: errors.Is(_, ErrStorageUnavailable) = false, err = %v", putErr)
	}

	failErr := lease.Failed(seq, putErr)
	if failErr != putErr {
		t.Errorf("Failed() = %v, want the original error returned unchanged", failErr)
	}
	if lease.Fencer().IsFenced("repo-gamma") {
		t.Errorf("expected repo-gamma to remain unfenced after a retryable failure")
	}

	seq2, err := lease.Next()
	if err != nil {
		t.Fatalf("Next after retryable failure: %v", err)
	}
	if seq2 != seq {
		t.Errorf("Next() after retryable failure = %d, want the same seq %d offered again", seq2, seq)
	}
}

// 7. Open twice for one stream returns the same lease and lists exactly
// once.
func TestOpenTwiceReturnsSameLeaseAndListsOnce(t *testing.T) {
	c, fake := newLeaseClient(t)
	fake.SetObject(journal.TxKey("repo-delta", 2), []byte(`{}`))

	leases := journal.NewLeases(c)
	ctx := context.Background()

	lease1, err := leases.Open(ctx, "repo-delta")
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	lease2, err := leases.Open(ctx, "repo-delta")
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	if lease1 != lease2 {
		t.Errorf("Open returned different *Lease values for the same stream")
	}

	listCalls := 0
	for _, call := range fake.Calls() {
		if call.Op == storetest.OpList {
			listCalls++
		}
	}
	if listCalls != 1 {
		t.Errorf("fake saw %d LIST calls across two Opens, want 1", listCalls)
	}
}

// 8. Under -race, many goroutines against one lease never see the same
// sequence issued twice: Next checks out the lease until the matching
// Landed or Failed, so concurrent callers are serialized here rather than
// left to race a real conditional PUT (and, on the loser's genuine 412,
// wrongly fence a perfectly healthy stream over its own concurrency).
func TestLeaseNextUnderConcurrencyNeverDuplicatesSequence(t *testing.T) {
	c, _ := newLeaseClient(t)
	leases := journal.NewLeases(c)
	ctx := context.Background()

	lease, err := leases.Open(ctx, "repo-epsilon")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	const n = 50
	var (
		mu   sync.Mutex
		seen = make(map[journal.Seq]bool)
	)
	errCh := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			seq, err := lease.Next()
			if err != nil {
				errCh <- fmt.Errorf("Next: %w", err)
				return
			}

			mu.Lock()
			dup := seen[seq]
			seen[seq] = true
			mu.Unlock()
			if dup {
				errCh <- fmt.Errorf("sequence %d issued twice", seq)
			}

			key := journal.TxKey("repo-epsilon", seq)
			if putErr := putIfAbsentAt(ctx, c, key); putErr != nil {
				if failErr := lease.Failed(seq, putErr); errors.Is(failErr, journal.ErrFenced) {
					// A real fencing failure here means two goroutines
					// raced the same seq against the fake - the exact bug
					// this test exists to catch.
					errCh <- fmt.Errorf("seq %d: unexpected fencing from %v: %w", seq, putErr, failErr)
				}
				return
			}
			lease.Landed(seq)
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
	if len(seen) != n {
		t.Errorf("saw %d distinct sequences, want %d", len(seen), n)
	}
}

// 9. A lease at the maximum 64-bit sequence refuses in one line instead of
// wrapping.
func TestLeaseAtMaxSequenceRefusesInsteadOfWrapping(t *testing.T) {
	c, fake := newLeaseClient(t)
	fake.SetObject(journal.TxKey("repo-zeta", journal.Seq(math.MaxUint64)), []byte(`{}`))

	leases := journal.NewLeases(c)
	lease, err := leases.Open(context.Background(), "repo-zeta")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	_, err = lease.Next()
	if err == nil {
		t.Fatalf("expected Next() to refuse once the stream is at the maximum sequence")
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
	want := "refusal: push failed: stream repo-zeta has exhausted its 64-bit sequence space"
	if err.Error() != want {
		t.Errorf("Next() error = %q, want %q", err.Error(), want)
	}
}

// The same exhaustion guard applies when a lease reaches the maximum
// sequence through Landed rather than through Open discovering it already
// there - Landed(math.MaxUint64) must not silently wrap next to 0, which
// would collide with that same stream's own already-written seq 0.
func TestLeaseLandedAtMaxSequenceRefusesInsteadOfWrapping(t *testing.T) {
	c, _ := newLeaseClient(t)
	leases := journal.NewLeases(c)
	ctx := context.Background()

	lease, err := leases.Open(ctx, "repo-eta")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Next's own returned seq is irrelevant here: Landed is called with
	// math.MaxUint64 regardless, to drive the lease straight to the
	// boundary this test exists to check, the same way a real caller's
	// Landed argument is whatever seq storage just acknowledged.
	if _, err := lease.Next(); err != nil {
		t.Fatalf("Next: %v", err)
	}
	lease.Landed(journal.Seq(math.MaxUint64))

	_, err = lease.Next()
	if err == nil {
		t.Fatalf("expected Next() to refuse after Landed(MaxUint64)")
	}
	want := "refusal: push failed: stream repo-eta has exhausted its 64-bit sequence space"
	if err.Error() != want {
		t.Errorf("Next() error = %q, want %q", err.Error(), want)
	}
}
