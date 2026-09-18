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
	var seq journal.Seq
	if err := lease.Append(func(s journal.Seq) error {
		seq = s
		return nil
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
	lease, err := leases.Open(context.Background(), "repo-alpha")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	var seq journal.Seq
	if err := lease.Append(func(s journal.Seq) error {
		seq = s
		return nil
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
	lease, err := leases.Open(context.Background(), "repo-alpha")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	var seq journal.Seq
	if err := lease.Append(func(s journal.Seq) error {
		seq = s
		return nil
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if seq != 5 {
		t.Errorf("Append handed out seq %d, want 5 (head 4 + 1, discovered across %d-key pages)", seq, fake.PageSize)
	}
}

// 3. A 412 from PutIfAbsent on the leased key, reported by fn's return
// value, fences the stream: the error is exactly section 11.5 item 1's
// string, errors.Is(err, journal.ErrFenced) holds, and the next Append and
// Open refuse with section 11.5 item 2's string having made zero further
// requests - asserted against Fake.Calls().
func TestAppendPreconditionFencesStream(t *testing.T) {
	c, fake := newLeaseClient(t)
	leases := journal.NewLeases(c)
	ctx := context.Background()

	lease, err := leases.Open(ctx, "repo-alpha")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	var gotSeq journal.Seq
	appendErr := lease.Append(func(seq journal.Seq) error {
		gotSeq = seq
		key := journal.TxKey("repo-alpha", seq)
		// A rival writer's record already sits at the key this Append
		// promised, so the conditional PUT below fails with a real,
		// storage-proven 412 - never a status this test fabricates without
		// the fake actually enforcing the condition.
		fake.SetObject(key, []byte(`{}`))
		return putIfAbsentAt(ctx, c, key)
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
	if err := lease.Append(func(journal.Seq) error {
		ranAfterFenced = true
		return nil
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
// ErrOutcomeUnknown path) fences the same stream the same way, with
// section 11.5 item 7's string.
func TestAppendOutcomeUnknownFencesStream(t *testing.T) {
	c, fake := newLeaseClient(t)
	leases := journal.NewLeases(c)
	ctx := context.Background()

	lease, err := leases.Open(ctx, "repo-beta")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	var gotSeq journal.Seq
	appendErr := lease.Append(func(seq journal.Seq) error {
		gotSeq = seq
		key := journal.TxKey("repo-beta", seq)
		// Land:true means the fake actually stores the write - it applied
		// - before Drop severs the connection with no response, the exact
		// ambiguity store.ErrOutcomeUnknown exists for.
		fake.Inject(storetest.Rule{
			Op:    storetest.OpPutIfAbsent,
			Key:   key,
			Call:  1,
			Fault: storetest.Fault{Drop: true, Land: true},
		})
		return putIfAbsentAt(ctx, c, key)
	})

	want := fmt.Sprintf("refusal: push failed: stream repo-beta append at seq %d has unknown outcome (instance is fenced for this stream; restart walden process to re-materialize from journal)", gotSeq)
	if appendErr == nil || appendErr.Error() != want {
		t.Fatalf("Append error:\ngot:  %v\nwant: %q", appendErr, want)
	}
	if !errors.Is(appendErr, journal.ErrFenced) {
		t.Errorf("expected Append's error to match journal.ErrFenced")
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
	appendErr := alpha.Append(func(seq journal.Seq) error {
		key := journal.TxKey("repo-alpha", seq)
		fake.SetObject(key, []byte(`{}`))
		return putIfAbsentAt(ctx, c, key)
	})
	if !errors.Is(appendErr, journal.ErrFenced) {
		t.Fatalf("alpha.Append: expected ErrFenced, got %v", appendErr)
	}

	// repo-beta keeps writing and counting on its own, unaffected.
	var seqB journal.Seq
	if err := beta.Append(func(seq journal.Seq) error {
		seqB = seq
		return putIfAbsentAt(ctx, c, journal.TxKey("repo-beta", seq))
	}); err != nil {
		t.Fatalf("beta.Append: %v", err)
	}
	if seqB != 0 {
		t.Errorf("beta's first Append got seq %d, want 0", seqB)
	}
	var seqB2 journal.Seq
	if err := beta.Append(func(seq journal.Seq) error {
		seqB2 = seq
		return nil
	}); err != nil {
		t.Fatalf("beta.Append (second): %v", err)
	}
	if seqB2 != 1 {
		t.Errorf("beta's second Append got seq %d, want 1", seqB2)
	}

	// _meta keeps writing and counting on its own too.
	var seqM journal.Seq
	if err := meta.Append(func(seq journal.Seq) error {
		seqM = seq
		return putIfAbsentAt(ctx, c, journal.TxKey(journal.MetaStreamID, seq))
	}); err != nil {
		t.Fatalf("meta.Append: %v", err)
	}
	if seqM != 0 {
		t.Errorf("meta's Append got seq %d, want 0", seqM)
	}

	// alpha stays fenced throughout.
	if err := alpha.Append(func(journal.Seq) error { return nil }); !errors.Is(err, journal.ErrFenced) {
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
// exercises the repo-stream wording - through a genuine 412 reported from
// fn.
func TestMetaStreamConflictRefusalWording(t *testing.T) {
	c, fake := newLeaseClient(t)
	leases := journal.NewLeases(c)
	ctx := context.Background()

	meta, err := leases.Open(ctx, journal.MetaStreamID)
	if err != nil {
		t.Fatalf("Open(_meta): %v", err)
	}

	var gotSeq journal.Seq
	appendErr := meta.Append(func(seq journal.Seq) error {
		gotSeq = seq
		key := journal.TxKey(journal.MetaStreamID, seq)
		fake.SetObject(key, []byte(`{}`))
		return putIfAbsentAt(ctx, c, key)
	})
	want := fmt.Sprintf("refusal: meta operation failed: stream _meta fenced by concurrent writer at seq %d (instance is fenced for this stream; restart or check active writer)", gotSeq)
	if appendErr == nil || appendErr.Error() != want {
		t.Fatalf("Append error:\ngot:  %v\nwant: %q", appendErr, want)
	}

	wantPerm := "refusal: meta operation failed: stream _meta is permanently fenced on this instance (restart walden process to re-materialize from journal)"
	if err := meta.Append(func(journal.Seq) error { return nil }); err == nil || err.Error() != wantPerm {
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
	appendErr := meta.Append(func(seq journal.Seq) error {
		gotSeq = seq
		key := journal.TxKey(journal.MetaStreamID, seq)
		fake.Inject(storetest.Rule{
			Op:    storetest.OpPutIfAbsent,
			Key:   key,
			Call:  1,
			Fault: storetest.Fault{Drop: true, Land: true},
		})
		return putIfAbsentAt(ctx, c, key)
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
	appendErr := lease.Append(func(s journal.Seq) error {
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
		return putIfAbsentAt(ctx, c, key)
	})
	if !errors.Is(appendErr, store.ErrStorageUnavailable) {
		t.Fatalf("Append: errors.Is(_, ErrStorageUnavailable) = false, err = %v", appendErr)
	}
	if lease.Fencer().IsFenced("repo-gamma") {
		t.Errorf("expected repo-gamma to remain unfenced after a retryable failure")
	}

	var seq2 journal.Seq
	if err := lease.Append(func(s journal.Seq) error {
		seq2 = s
		return nil
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
// goroutine here retries Append until it wins the turn, and its fn performs
// the real conditional PUT and reports the outcome, so this exercises the
// whole path end to end, not just sequence bookkeeping.
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
				appendErr := lease.Append(func(seq journal.Seq) error {
					mu.Lock()
					dup := seen[seq]
					seen[seq] = true
					mu.Unlock()
					if dup {
						errCh <- fmt.Errorf("sequence %d issued twice", seq)
					}
					return putIfAbsentAt(ctx, c, journal.TxKey("repo-epsilon", seq))
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
	lease, err := leases.Open(context.Background(), "repo-zeta")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	ranFn := false
	err = lease.Append(func(journal.Seq) error {
		ranFn = true
		return nil
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
	if err := lease.Append(func(s journal.Seq) error {
		seq = s
		return nil
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if seq != math.MaxUint64 {
		t.Fatalf("Append handed out seq %d, want %d (head MaxUint64-1 + 1)", seq, uint64(math.MaxUint64))
	}

	err = lease.Append(func(journal.Seq) error { return nil })
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
// checkout before returning (including via panic - see the test below).
// This drives fn with a channel so the assertion does not depend on
// scheduling luck: the second Append is only issued once the first is
// certainly still running inside fn.
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
		firstDone <- lease.Append(func(journal.Seq) error {
			close(started)
			<-release
			return nil
		})
	}()

	<-started

	secondRan := false
	secondErr := lease.Append(func(journal.Seq) error {
		secondRan = true
		return nil
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
	if err := lease.Append(func(journal.Seq) error { return nil }); err != nil {
		t.Fatalf("Append after contention cleared: %v", err)
	}
}

// Regression test for round 3's major finding and the deleted grace
// period: a panic inside fn leaves the process genuinely unable to prove
// whether the write it was making landed, so Append fences the stream
// through the same unknown-outcome path a proven ambiguous failure uses,
// and then re-panics so the panic still reaches fn's own caller instead of
// being swallowed. Unlike the deleted abandoned-checkout timer, this
// requires no clock and no guess: the panic itself is the evidence.
func TestAppendPanicFencesStreamAndRepanics(t *testing.T) {
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
		_ = lease.Append(func(seq journal.Seq) error {
			gotSeq = seq
			panic("simulated panic mid-append")
		})
	}()

	if recovered == nil {
		t.Fatalf("expected the panic to propagate out of Append, got no panic")
	}
	if recovered != "simulated panic mid-append" {
		t.Errorf("recovered panic = %v, want the original panic value", recovered)
	}
	if !lease.Fencer().IsFenced("repo-panic") {
		t.Fatalf("expected the stream to be fenced after a panic mid-append")
	}
	fencedSeq, ok := lease.Fencer().FencedSeq("repo-panic")
	if !ok || fencedSeq != gotSeq {
		t.Errorf("fenced seq = %d (ok=%v), want the seq the panicking Append was given, %d", fencedSeq, ok, gotSeq)
	}

	wantPerm := "refusal: push failed: stream repo-panic is permanently fenced on this instance (restart walden process to re-materialize from journal)"
	if err := lease.Append(func(journal.Seq) error { return nil }); err == nil || err.Error() != wantPerm {
		t.Errorf("Append() after a panic-fenced stream = %v, want %q", err, wantPerm)
	}
}

// Regression test for round 2 review finding 1 and round 3's major finding,
// ported to the scoped Append API: a concurrent Append must never be able
// to run its fn - and so never be handed an overlapping or duplicate
// sequence - while another Append's fn is still executing on the same
// Lease. Round 2 reproduced the pre-fix code losing this race 730/3000
// times; here the two Appends are synchronized with channels rather than
// left to scheduling luck, so the assertion holds by construction rather
// than by getting lucky enough times in a row, and the loop repeats across
// fresh streams to also exercise it under -race across many goroutine
// interleavings.
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
			firstDone <- lease.Append(func(journal.Seq) error {
				close(started)
				<-release
				return journal.ErrOutcomeUnknown
			})
		}()

		<-started

		racerRan := false
		raceErr := lease.Append(func(journal.Seq) error {
			racerRan = true
			return nil
		})
		close(release)
		<-firstDone

		if racerRan {
			t.Fatalf("iteration %d: concurrent Append's fn ran while the first Append was still in flight", i)
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
