package journal_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"runtime"
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

// putBody is a small, reusable conditional-append payload for a prepare
// func to return; its bytes are never inspected by these tests, only its
// presence or absence at a key. As of WALD-118, Append itself issues the
// conditional PUT once prepare returns this, so tests no longer call
// PutIfAbsent themselves to exercise the write path - only to seed a
// conflicting object ahead of it (fake.SetObject) or to fault-inject
// against the key Append is about to use (fake.Inject).
var putBody = []byte(`{}`)

// panicOnPUTStore wraps a journal.TxStore and panics from PutIfAbsent
// itself, standing in for a storage client whose own write path panics.
// List is delegated unchanged. This is WALD-118's regression guard for the
// hard constraint the whole ticket exists to preserve: a panic that
// happens at or after Append's own PUT - after issued has been set - must
// still fence the stream exactly as a panic inside the old, caller-owned
// closure always did (spec/journal/v1 section 11.4 item 6). It is the
// sharpest way to exercise that without depending on any one storage
// implementation's own panic surface.
type panicOnPUTStore struct {
	journal.TxStore
}

func (panicOnPUTStore) PutIfAbsent(ctx context.Context, key string, body io.ReaderAt, size int64) error {
	panic("simulated panic from storage during PutIfAbsent")
}

// 1. Open on an empty stream leases seq 0; open on a stream whose highest
// tx/ key is 00000000000000000004 leases 5.
func TestOpenEmptyStreamLeasesZero(t *testing.T) {
	c, _ := newLeaseClient(t)
	leases := journal.NewLeases(c)
	ctx := context.Background()

	lease, err := leases.Open(ctx, "repo-empty")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	var seq journal.Seq
	if err := lease.Append(ctx, func(s journal.Seq) ([]byte, error) {
		seq = s
		return putBody, nil
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if seq != 0 {
		t.Errorf("Append handed out seq %d, want 0", seq)
	}
}

func TestOpenExistingStreamLeasesHeadPlusOne(t *testing.T) {
	c, fake := newLeaseClient(t)
	fake.SetObject(journal.TxKey("repo-alpha", 4), []byte(`{"seq":"4"}`))

	leases := journal.NewLeases(c)
	ctx := context.Background()
	lease, err := leases.Open(ctx, "repo-alpha")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	var seq journal.Seq
	if err := lease.Append(ctx, func(s journal.Seq) ([]byte, error) {
		seq = s
		return putBody, nil
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if seq != 5 {
		t.Errorf("Append handed out seq %d, want 5 (head 4 + 1)", seq)
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
	ctx := context.Background()
	lease, err := leases.Open(ctx, "repo-alpha")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	var seq journal.Seq
	if err := lease.Append(ctx, func(s journal.Seq) ([]byte, error) {
		seq = s
		return putBody, nil
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if seq != 5 {
		t.Errorf("Append handed out seq %d, want 5 (head 4 + 1, discovered across %d-key pages)", seq, fake.PageSize)
	}
}

// 3. A 412 from Append's own PUT at the leased key fences the stream: the
// error is exactly section 11.5 item 1's string, errors.Is(err,
// journal.ErrFenced) holds, and the next Append and Open refuse with
// section 11.5 item 2's string having made zero further requests -
// asserted against Fake.Calls().
func TestAppendPreconditionFencesStream(t *testing.T) {
	c, fake := newLeaseClient(t)
	leases := journal.NewLeases(c)
	ctx := context.Background()

	lease, err := leases.Open(ctx, "repo-alpha")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	var gotSeq journal.Seq
	appendErr := lease.Append(ctx, func(seq journal.Seq) ([]byte, error) {
		gotSeq = seq
		key := journal.TxKey("repo-alpha", seq)
		// A rival writer's record already sits at the key Append is about
		// to PUT to, so its conditional PUT fails with a real,
		// storage-proven 412 - never a status this test fabricates without
		// the fake actually enforcing the condition.
		fake.SetObject(key, []byte(`{}`))
		return putBody, nil
	})

	want := fmt.Sprintf("refusal: push failed: stream repo-alpha fenced by concurrent writer at seq %d (instance is fenced for this stream; restart or check active writer)", gotSeq)
	if appendErr == nil || appendErr.Error() != want {
		t.Fatalf("Append error:\ngot:  %v\nwant: %q", appendErr, want)
	}
	if !errors.Is(appendErr, journal.ErrFenced) {
		t.Errorf("expected Append's error to match journal.ErrFenced")
	}

	callsBefore := len(fake.Calls())

	wantPerm := "refusal: push failed: stream repo-alpha is permanently fenced on this instance (restart walden process to re-materialize from journal)"
	ranAfterFenced := false
	if err := lease.Append(ctx, func(journal.Seq) ([]byte, error) {
		ranAfterFenced = true
		return putBody, nil
	}); err == nil || err.Error() != wantPerm {
		t.Errorf("Append() after fencing = %v, want %q", err, wantPerm)
	}
	if ranAfterFenced {
		t.Errorf("fn ran on a fenced stream")
	}
	if _, err := leases.Open(ctx, "repo-alpha"); err == nil || err.Error() != wantPerm {
		t.Errorf("Open() after fencing = %v, want %q", err, wantPerm)
	}

	if got := len(fake.Calls()); got != callsBefore {
		t.Errorf("fake saw %d further requests after fencing, want 0", got-callsBefore)
	}
}

// 4. A dropped response injected through storetest (store's
// ErrOutcomeUnknown path), against the key Append's own PUT uses, fences
// the same stream the same way, with section 11.5 item 7's string.
func TestAppendOutcomeUnknownFencesStream(t *testing.T) {
	c, fake := newLeaseClient(t)
	leases := journal.NewLeases(c)
	ctx := context.Background()

	lease, err := leases.Open(ctx, "repo-beta")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	var gotSeq journal.Seq
	appendErr := lease.Append(ctx, func(seq journal.Seq) ([]byte, error) {
		gotSeq = seq
		key := journal.TxKey("repo-beta", seq)
		// Land:true means the fake actually stores the write - it applied
		// - before Drop severs the connection with no response, the exact
		// ambiguity store.ErrOutcomeUnknown exists for. Injected against
		// the key Append itself is about to PUT to, since Append now
		// issues that PUT itself rather than taking it on faith from this
		// closure.
		fake.Inject(storetest.Rule{
			Op:    storetest.OpPutIfAbsent,
			Key:   key,
			Call:  1,
			Fault: storetest.Fault{Drop: true, Land: true},
		})
		return putBody, nil
	})

	want := fmt.Sprintf("refusal: push failed: stream repo-beta append at seq %d has unknown outcome (instance is fenced for this stream; restart walden process to re-materialize from journal)", gotSeq)
	if appendErr == nil || appendErr.Error() != want {
		t.Fatalf("Append error:\ngot:  %v\nwant: %q", appendErr, want)
	}
	if !errors.Is(appendErr, journal.ErrFenced) {
		t.Errorf("expected Append's error to match journal.ErrFenced")
	}
	if !errors.Is(appendErr, journal.ErrOutcomeUnknown) {
		t.Errorf("expected Append's error to match journal.ErrOutcomeUnknown (fencing.go, WALD-118)")
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
	appendErr := alpha.Append(ctx, func(seq journal.Seq) ([]byte, error) {
		key := journal.TxKey("repo-alpha", seq)
		fake.SetObject(key, []byte(`{}`))
		return putBody, nil
	})
	if !errors.Is(appendErr, journal.ErrFenced) {
		t.Fatalf("alpha.Append: expected ErrFenced, got %v", appendErr)
	}

	// repo-beta keeps writing and counting on its own, unaffected.
	var seqB journal.Seq
	if err := beta.Append(ctx, func(seq journal.Seq) ([]byte, error) {
		seqB = seq
		return putBody, nil
	}); err != nil {
		t.Fatalf("beta.Append: %v", err)
	}
	if seqB != 0 {
		t.Errorf("beta's first Append got seq %d, want 0", seqB)
	}
	var seqB2 journal.Seq
	if err := beta.Append(ctx, func(seq journal.Seq) ([]byte, error) {
		seqB2 = seq
		return putBody, nil
	}); err != nil {
		t.Fatalf("beta.Append (second): %v", err)
	}
	if seqB2 != 1 {
		t.Errorf("beta's second Append got seq %d, want 1", seqB2)
	}

	// _meta keeps writing and counting on its own too.
	var seqM journal.Seq
	if err := meta.Append(ctx, func(seq journal.Seq) ([]byte, error) {
		seqM = seq
		return putBody, nil
	}); err != nil {
		t.Fatalf("meta.Append: %v", err)
	}
	if seqM != 0 {
		t.Errorf("meta's Append got seq %d, want 0", seqM)
	}

	// alpha stays fenced throughout.
	if err := alpha.Append(ctx, func(journal.Seq) ([]byte, error) { return putBody, nil }); !errors.Is(err, journal.ErrFenced) {
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
// exercises the repo-stream wording - through a genuine 412 from Append's
// own PUT.
func TestMetaStreamConflictRefusalWording(t *testing.T) {
	c, fake := newLeaseClient(t)
	leases := journal.NewLeases(c)
	ctx := context.Background()

	meta, err := leases.Open(ctx, journal.MetaStreamID)
	if err != nil {
		t.Fatalf("Open(_meta): %v", err)
	}

	var gotSeq journal.Seq
	appendErr := meta.Append(ctx, func(seq journal.Seq) ([]byte, error) {
		gotSeq = seq
		key := journal.TxKey(journal.MetaStreamID, seq)
		fake.SetObject(key, []byte(`{}`))
		return putBody, nil
	})
	want := fmt.Sprintf("refusal: meta operation failed: stream _meta fenced by concurrent writer at seq %d (instance is fenced for this stream; restart or check active writer)", gotSeq)
	if appendErr == nil || appendErr.Error() != want {
		t.Fatalf("Append error:\ngot:  %v\nwant: %q", appendErr, want)
	}

	wantPerm := "refusal: meta operation failed: stream _meta is permanently fenced on this instance (restart walden process to re-materialize from journal)"
	if err := meta.Append(ctx, func(journal.Seq) ([]byte, error) { return putBody, nil }); err == nil || err.Error() != wantPerm {
		t.Errorf("meta.Append() after fencing = %v, want %q", err, wantPerm)
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

	var gotSeq journal.Seq
	appendErr := meta.Append(ctx, func(seq journal.Seq) ([]byte, error) {
		gotSeq = seq
		key := journal.TxKey(journal.MetaStreamID, seq)
		fake.Inject(storetest.Rule{
			Op:    storetest.OpPutIfAbsent,
			Key:   key,
			Call:  1,
			Fault: storetest.Fault{Drop: true, Land: true},
		})
		return putBody, nil
	})
	want := fmt.Sprintf("refusal: meta operation failed: stream _meta append at seq %d has unknown outcome (instance is fenced for this stream; restart walden process to re-materialize from journal)", gotSeq)
	if appendErr == nil || appendErr.Error() != want {
		t.Fatalf("Append error:\ngot:  %v\nwant: %q", appendErr, want)
	}
}

// 6. A retryable failure (ErrStorageUnavailable) neither fences nor
// consumes the sequence: the same seq is offered again.
func TestAppendRetryableDoesNotFenceOrConsumeSeq(t *testing.T) {
	c, fake := newLeaseClient(t)
	leases := journal.NewLeases(c)
	ctx := context.Background()

	lease, err := leases.Open(ctx, "repo-gamma")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	var seq journal.Seq
	appendErr := lease.Append(ctx, func(s journal.Seq) ([]byte, error) {
		seq = s
		key := journal.TxKey("repo-gamma", s)
		// Count 4 matches the client's own maxAttempts (client.go), so
		// every attempt the client makes fails the same way and it gives
		// up with ErrStorageUnavailable rather than retrying forever or
		// succeeding.
		fake.Inject(storetest.Rule{
			Op:    storetest.OpPutIfAbsent,
			Key:   key,
			Call:  1,
			Count: 4,
			Fault: storetest.Fault{Status: 503, Code: "ServiceUnavailable"},
		})
		return putBody, nil
	})
	if !errors.Is(appendErr, store.ErrStorageUnavailable) {
		t.Fatalf("Append: errors.Is(_, ErrStorageUnavailable) = false, err = %v", appendErr)
	}
	if lease.Fencer().IsFenced("repo-gamma") {
		t.Errorf("expected repo-gamma to remain unfenced after a retryable failure")
	}

	var seq2 journal.Seq
	if err := lease.Append(ctx, func(s journal.Seq) ([]byte, error) {
		seq2 = s
		return putBody, nil
	}); err != nil {
		t.Fatalf("Append after retryable failure: %v", err)
	}
	if seq2 != seq {
		t.Errorf("Append after retryable failure offered seq %d, want the same seq %d offered again", seq2, seq)
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

// 8. Under -race, many goroutines appending against one lease never see the
// same sequence issued twice: at most one Append is ever running on a
// Lease at a time, and a second, concurrent Append refuses in one line -
// rather than block - while another is in flight (see refuseSeqBusy). Each
// goroutine here retries Append until it wins the turn, and its prepare
// performs the real conditional PUT (through Append itself) and reports
// the outcome, so this exercises the whole path end to end, not just
// sequence bookkeeping.
func TestAppendUnderConcurrencyNeverDuplicatesSequence(t *testing.T) {
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

			for {
				appendErr := lease.Append(ctx, func(seq journal.Seq) ([]byte, error) {
					mu.Lock()
					dup := seen[seq]
					seen[seq] = true
					mu.Unlock()
					if dup {
						errCh <- fmt.Errorf("sequence %d issued twice", seq)
					}
					return putBody, nil
				})
				if appendErr == nil {
					return
				}
				if errors.Is(appendErr, journal.ErrFenced) {
					// A real fencing failure here means two goroutines
					// raced the same seq against the fake - the exact bug
					// this test exists to catch.
					errCh <- fmt.Errorf("unexpected fencing: %w", appendErr)
					return
				}
				// Another goroutine's Append is still in flight - retry
				// rather than treat the refusal as failure.
			}
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
	ctx := context.Background()
	lease, err := leases.Open(ctx, "repo-zeta")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	ranFn := false
	err = lease.Append(ctx, func(journal.Seq) ([]byte, error) {
		ranFn = true
		return putBody, nil
	})
	if err == nil {
		t.Fatalf("expected Append to refuse once the stream is at the maximum sequence")
	}
	if ranFn {
		t.Errorf("fn ran on an exhausted stream")
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
	want := "refusal: push failed: stream repo-zeta has exhausted its 64-bit sequence space"
	if err.Error() != want {
		t.Errorf("Append() error = %q, want %q", err.Error(), want)
	}
}

// The same exhaustion guard applies when a lease reaches the maximum
// sequence through a landed Append rather than through Open discovering it
// already there - landing seq math.MaxUint64 must not silently wrap next
// to 0, which would collide with that same stream's own already-written
// seq 0. The stream's head is seeded one below the maximum so Append
// legitimately hands out math.MaxUint64 itself.
func TestAppendAtMaxSequenceRefusesInsteadOfWrapping(t *testing.T) {
	c, fake := newLeaseClient(t)
	fake.SetObject(journal.TxKey("repo-eta", journal.Seq(math.MaxUint64-1)), []byte(`{}`))

	leases := journal.NewLeases(c)
	ctx := context.Background()

	lease, err := leases.Open(ctx, "repo-eta")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	var seq journal.Seq
	if err := lease.Append(ctx, func(s journal.Seq) ([]byte, error) {
		seq = s
		return putBody, nil
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if seq != math.MaxUint64 {
		t.Fatalf("Append handed out seq %d, want %d (head MaxUint64-1 + 1)", seq, uint64(math.MaxUint64))
	}

	err = lease.Append(ctx, func(journal.Seq) ([]byte, error) { return putBody, nil })
	if err == nil {
		t.Fatalf("expected Append to refuse after landing seq MaxUint64")
	}
	want := "refusal: push failed: stream repo-eta has exhausted its 64-bit sequence space"
	if err.Error() != want {
		t.Errorf("Append() error = %q, want %q", err.Error(), want)
	}
}

// Regression test for round 1 review findings 1-2 and round 3's major
// finding: a second Append while one is already running on the same Lease
// must refuse in one line, promptly, rather than block or wedge - and,
// unlike the deleted checkout protocol this replaces, there is no separate
// "abandoned" case to time out, because Append itself always resolves the
// checkout before returning (including via panic - see the tests below).
// This drives prepare with a channel so the assertion does not depend on
// scheduling luck: the second Append is only issued once the first is
// certainly still running inside prepare.
func TestAppendRefusesRatherThanBlocksWhileAnotherIsInFlight(t *testing.T) {
	c, _ := newLeaseClient(t)
	leases := journal.NewLeases(c)
	ctx := context.Background()

	lease, err := leases.Open(ctx, "repo-theta")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	started := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- lease.Append(ctx, func(journal.Seq) ([]byte, error) {
			close(started)
			<-release
			return putBody, nil
		})
	}()

	<-started

	secondRan := false
	secondErr := lease.Append(ctx, func(journal.Seq) ([]byte, error) {
		secondRan = true
		return putBody, nil
	})
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Append: %v", err)
	}

	if secondRan {
		t.Fatalf("fn ran for a second Append issued while the first was still in flight")
	}
	if secondErr == nil {
		t.Fatalf("expected the second Append to refuse while the first was in flight, got nil")
	}
	if strings.ContainsAny(secondErr.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", secondErr.Error())
	}
	if errors.Is(secondErr, journal.ErrFenced) {
		t.Errorf("ordinary contention between two Appends must not fence the stream, got %v", secondErr)
	}

	// The lease is healthy afterward: a third Append succeeds and advances
	// past the seq the first Append landed.
	if err := lease.Append(ctx, func(journal.Seq) ([]byte, error) { return putBody, nil }); err != nil {
		t.Fatalf("Append after contention cleared: %v", err)
	}
}

// Regression test for round 3's major finding and the deleted grace
// period, updated for WALD-118: prepare panicking before Append has ever
// issued its PUT proves nothing was attempted, so Append re-panics without
// fencing - a crash with a stack trace on a caller's own bug, not a
// healthy stream permanently fenced on healthy data. This is also
// literally WALD-118's own "how to know it worked" case: "prepare panics,
// Append re-panics, and after recovering it the stream is not fenced and
// the next Append is handed the same sequence."
func TestAppendPanicBeforePUTDoesNotFenceStreamAndRepanics(t *testing.T) {
	c, _ := newLeaseClient(t)
	leases := journal.NewLeases(c)
	ctx := context.Background()

	lease, err := leases.Open(ctx, "repo-panic")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	var (
		recovered any
		gotSeq    journal.Seq
	)
	func() {
		defer func() { recovered = recover() }()
		_ = lease.Append(ctx, func(seq journal.Seq) ([]byte, error) {
			gotSeq = seq
			panic("simulated panic in prepare, before any PUT")
		})
	}()

	if recovered == nil {
		t.Fatalf("expected the panic to propagate out of Append, got no panic")
	}
	if recovered != "simulated panic in prepare, before any PUT" {
		t.Errorf("recovered panic = %v, want the original panic value", recovered)
	}
	if lease.Fencer().IsFenced("repo-panic") {
		t.Fatalf("expected the stream to remain unfenced: prepare panicked before Append ever issued its PUT, so nothing was attempted")
	}

	// The lease is healthy afterward: the next Append is offered the same
	// seq the panicking one was, and succeeds.
	var seq2 journal.Seq
	if err := lease.Append(ctx, func(s journal.Seq) ([]byte, error) {
		seq2 = s
		return putBody, nil
	}); err != nil {
		t.Fatalf("Append after a pre-PUT panic: %v", err)
	}
	if seq2 != gotSeq {
		t.Errorf("Append after a pre-PUT panic offered seq %d, want the same seq %d the panicking Append was given", seq2, gotSeq)
	}
}

// Regression guard for WALD-118's hard constraint: a panic that happens at
// or after Append's own PUT must still fence the stream exactly as it did
// before this ticket (spec/journal/v1 section 11.4 item 6) - narrowing
// fencing to writes Append itself issued must not weaken it for a genuine
// mid-write panic. panicOnPUTStore (above) panics from PutIfAbsent itself,
// so the panic happens strictly after Append has set its internal "issued"
// flag and strictly during the write.
func TestAppendPanicAtPUTStillFencesStream(t *testing.T) {
	c, _ := newLeaseClient(t)
	leases := journal.NewLeases(panicOnPUTStore{c})
	ctx := context.Background()

	lease, err := leases.Open(ctx, "repo-put-panic")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	var (
		recovered any
		gotSeq    journal.Seq
	)
	func() {
		defer func() { recovered = recover() }()
		_ = lease.Append(ctx, func(seq journal.Seq) ([]byte, error) {
			gotSeq = seq
			return putBody, nil
		})
	}()

	if recovered == nil {
		t.Fatalf("expected the panic to propagate out of Append, got no panic")
	}
	if !lease.Fencer().IsFenced("repo-put-panic") {
		t.Fatalf("expected the stream to be fenced: the panic happened at Append's own PUT, after it had already been issued")
	}
	fencedSeq, ok := lease.Fencer().FencedSeq("repo-put-panic")
	if !ok || fencedSeq != gotSeq {
		t.Errorf("fenced seq = %d (ok=%v), want the seq the panicking Append was given, %d", fencedSeq, ok, gotSeq)
	}

	wantPerm := "refusal: push failed: stream repo-put-panic is permanently fenced on this instance (restart walden process to re-materialize from journal)"
	if err := lease.Append(ctx, func(journal.Seq) ([]byte, error) { return putBody, nil }); err == nil || err.Error() != wantPerm {
		t.Errorf("Append() after a PUT-panic-fenced stream = %v, want %q", err, wantPerm)
	}
}

// Regression test for round 4's medium finding, updated for WALD-118:
// prepare calling runtime.Goexit (what t.Fatal/FailNow do) before Append
// has ever issued its PUT unwinds past any straight-line resolution
// without returning or panicking, so a resolution that only ran in the
// normal-return path used to never run at all - busy stayed true forever
// and every later Append refused "already has an append in progress" with
// no way for the retry to ever succeed. Now that issued gates the
// deferred resolution, a pre-PUT Goexit clears busy without fencing:
// nothing was attempted, so there is nothing unprovable about it.
// runtime.Goexit terminates the calling goroutine, so prepare is run in
// its own goroutine here and the test synchronizes on that goroutine's
// completion (via a deferred close, which - like everything else deferred
// on that goroutine's stack, including Append's own resolution - still
// runs during the Goexit unwind) rather than on Append's return, since
// Append never returns in this path.
func TestAppendGoexitBeforePUTDoesNotFenceStreamAndClearsBusy(t *testing.T) {
	c, _ := newLeaseClient(t)
	leases := journal.NewLeases(c)
	ctx := context.Background()

	lease, err := leases.Open(ctx, "repo-goexit")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	var gotSeq journal.Seq
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = lease.Append(ctx, func(seq journal.Seq) ([]byte, error) {
			gotSeq = seq
			runtime.Goexit()
			return nil, nil // unreachable
		})
	}()
	<-done

	if lease.Fencer().IsFenced("repo-goexit") {
		t.Fatalf("expected the stream to remain unfenced: prepare Goexited before Append ever issued its PUT, so nothing was attempted")
	}

	// The regression this guards against: without the fix, busy stays true
	// forever and this Append refuses "already has an append in progress"
	// rather than succeeding at the same seq the Goexit-ed Append was
	// given.
	var seq2 journal.Seq
	if err := lease.Append(ctx, func(s journal.Seq) ([]byte, error) {
		seq2 = s
		return putBody, nil
	}); err != nil {
		t.Errorf("Append after a pre-PUT Goexit: %v", err)
	}
	if seq2 != gotSeq {
		t.Errorf("Append after a pre-PUT Goexit offered seq %d, want the same seq %d the Goexit-ed Append was given", seq2, gotSeq)
	}
}

// Regression test for round 2 review finding 1 and round 3's major finding,
// ported to the scoped Append API: a concurrent Append must never be able
// to run its prepare - and so never be handed an overlapping or duplicate
// sequence - while another Append's prepare is still executing on the same
// Lease. Round 2 reproduced the pre-fix code losing this race 730/3000
// times; here the two Appends are synchronized with channels rather than
// left to scheduling luck, so the assertion holds by construction rather
// than by getting lucky enough times in a row, and the loop repeats across
// fresh streams to also exercise it under -race across many goroutine
// interleavings. The first Append's prepare returns journal.ErrOutcomeUnknown
// directly (no payload, no PUT) purely to give it a fenced outcome without
// depending on the fake at all - Lease.Append's own classification of a
// prepare-returned error is unchanged by WALD-118 (lease.go's own doc
// comment), so this still fences exactly as it always has.
func TestConcurrentAppendNeverOverlapsWhileFirstInFlight(t *testing.T) {
	c, _ := newLeaseClient(t)
	leases := journal.NewLeases(c)
	ctx := context.Background()

	const iterations = 500
	for i := 0; i < iterations; i++ {
		stream := journal.StreamID(fmt.Sprintf("repo-race1-%d", i))
		lease, err := leases.Open(ctx, stream)
		if err != nil {
			t.Fatalf("iteration %d: Open: %v", i, err)
		}

		started := make(chan struct{})
		release := make(chan struct{})
		firstDone := make(chan error, 1)
		go func() {
			firstDone <- lease.Append(ctx, func(journal.Seq) ([]byte, error) {
				close(started)
				<-release
				return nil, journal.ErrOutcomeUnknown
			})
		}()

		<-started

		racerRan := false
		raceErr := lease.Append(ctx, func(journal.Seq) ([]byte, error) {
			racerRan = true
			return putBody, nil
		})
		close(release)
		<-firstDone

		if racerRan {
			t.Fatalf("iteration %d: concurrent Append's prepare ran while the first Append was still in flight", i)
		}
		if raceErr == nil {
			t.Fatalf("iteration %d: concurrent Append unexpectedly succeeded while the first Append was still in flight", i)
		}
		if errors.Is(raceErr, journal.ErrFenced) {
			t.Fatalf("iteration %d: ordinary contention with an in-flight Append must not itself read as fenced: %v", i, raceErr)
		}
	}
}

// Regression test for round 2 review finding 4: Open must validate every
// key a LIST yields, not only the last (highest) one. A malformed key that
// sorts below the real head - a stray ".bak" copy, a leftover artifact -
// must refuse Open exactly as a malformed head does, per this file's own
// doc comment ("a one-line refusal, not a skipped key"), rather than be
// silently skipped because a later, well-formed key overwrote it as the
// tracked candidate.
func TestOpenRefusesMalformedKeyThatSortsBelowHead(t *testing.T) {
	c, fake := newLeaseClient(t)

	// "...0003.json.bak" sorts lexicographically before "...0004.json" (the
	// real head) at the same prefix, so a naive "keep only the last key"
	// scan never looks at it.
	fake.SetObject(journal.TxKey("repo-nu", 3)+".bak", []byte(`{}`))
	fake.SetObject(journal.TxKey("repo-nu", 4), []byte(`{}`))

	leases := journal.NewLeases(c)
	_, err := leases.Open(context.Background(), "repo-nu")
	if err == nil {
		t.Fatalf("expected Open to refuse on a malformed key under tx/, got nil")
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
	if !strings.HasPrefix(err.Error(), "refusal: push failed") {
		t.Errorf("refusal does not announce itself as a refusal: %q", err.Error())
	}
	if !strings.Contains(err.Error(), ".bak") {
		t.Errorf("refusal does not name the offending key: %q", err.Error())
	}
}

// WALD-118: Append refuses a nil ctx in one line, before busy is ever set
// and with zero network calls - ctx is handed to l.store.PutIfAbsent once
// prepare has returned a payload, and store.(*Client).do's first statement
// calls ctx.Err(), which would otherwise panic on a nil interface value.
func TestAppendRefusesNilContext(t *testing.T) {
	c, fake := newLeaseClient(t)
	leases := journal.NewLeases(c)

	lease, err := leases.Open(context.Background(), "repo-nilctx")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	callsBefore := len(fake.Calls())

	ranPrepare := false
	err = lease.Append(nil, func(journal.Seq) ([]byte, error) {
		ranPrepare = true
		return putBody, nil
	})
	if err == nil {
		t.Fatalf("expected Append(nil, ...) to refuse, got nil")
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
	if !strings.HasPrefix(err.Error(), "refusal: push failed") {
		t.Errorf("refusal does not announce itself as a refusal: %q", err.Error())
	}
	if ranPrepare {
		t.Errorf("prepare ran despite a nil ctx")
	}
	if errors.Is(err, journal.ErrFenced) {
		t.Errorf("a nil ctx must refuse, not fence: %v", err)
	}
	if lease.Fencer().IsFenced("repo-nilctx") {
		t.Errorf("expected repo-nilctx to remain unfenced")
	}
	if got := len(fake.Calls()); got != callsBefore {
		t.Errorf("fake saw %d further requests, want 0", got-callsBefore)
	}

	// The lease is healthy afterward: a real Append still succeeds at seq 0.
	var seq journal.Seq
	if err := lease.Append(context.Background(), func(s journal.Seq) ([]byte, error) {
		seq = s
		return putBody, nil
	}); err != nil {
		t.Fatalf("Append after a nil-ctx refusal: %v", err)
	}
	if seq != 0 {
		t.Errorf("Append after a nil-ctx refusal got seq %d, want 0", seq)
	}
}
