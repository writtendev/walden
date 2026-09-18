// This file is the correctness spine PHILOSOPHY.md and ARCHITECTURE.md both
// point at: the per-stream sequence lease that makes single-writer safety
// (spec/journal/v1 section 11.4) an invariant of the type rather than a
// discipline callers have to remember. Opening a stream discovers its head
// sequence exactly once, by one paginated LIST of tx/; nothing else in this
// package ever reads storage to find a head, so there is no code path left
// that could re-read and retry after a conflict - the forbidden half of
// section 11.4 item 4 is unrepresentable, not merely undocumented.
package journal

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"

	"github.com/writtendev/walden/internal/refusal"
)

// TxLister is the whole storage surface a Lease needs to discover a
// stream's head sequence: one paginated listing under a prefix, exactly the
// shape store.(*Client).List already has. It is declared here, not in
// terms of *store.Client, because this package must not import store
// (store imports journal, and config aside, no package imports another in
// a cycle) - *store.Client satisfies this interface structurally, with no
// import needed on either side.
type TxLister interface {
	List(ctx context.Context, prefix, startAfter string, fn func(key string) error) error
}

// Leases is the per-instance registry of per-stream sequence leases: one
// shared Fencer, and at most one *Lease per stream for the life of the
// process. Two leases for one stream inside one process would be
// split-brain within a single instance - the exact failure this file
// exists to prevent - so Open hands out the same *Lease to every caller
// that asks for a given stream, ever.
type Leases struct {
	lister TxLister
	fencer *Fencer

	// mu guards leases and serializes Open end to end, including the LIST
	// call: a single mutex, not one per stream, matching this package's
	// preference for the boring option over finer-grained locking. Open
	// runs at most once per stream over the life of the process, so
	// blocking a concurrent Open of a different stream for the duration of
	// one LIST is not a throughput problem worth a more complex design.
	mu     sync.Mutex
	leases map[StreamID]*Lease
}

// NewLeases builds an empty registry backed by lister. It owns its own
// Fencer: fencing state is per-registry (in practice, per walden process),
// never shared across instances.
func NewLeases(lister TxLister) *Leases {
	return &Leases{
		lister: lister,
		fencer: NewFencer(),
		leases: make(map[StreamID]*Lease),
	}
}

// Open returns the lease for stream, discovering its head sequence on the
// first call and memoizing it for every call after. A stream already
// fenced is refused with RefusePermanentlyFenced having made zero network
// calls (spec/journal/v1 section 11.4 item 3) - Open never lists a stream
// only to find out it is not allowed to write to it.
//
// Head discovery lists TxPrefix(stream) once, keeping only the last key
// seen: section 10 guarantees ascending lexicographic order over tx/ is
// sequence order, and store.(*Client).List already refuses a provider that
// breaks that, so the last key List calls fn with is the head and no
// sorting belongs here. A key under tx/ that does not parse as
// "<20 digits>.json" is a one-line refusal, not a skipped key - a
// malformed key means the journal itself is suspect, and guessing which
// keys to trust is exactly the guessing this file exists to rule out.
//
// The risk worth watching, named here because a compaction change is the
// one thing that can silently break this: a head derived from LIST alone
// is correct only while every transaction at or below the compacted marker
// sequence is retained. The day compaction deletes below marker.sequence, a
// LIST-derived head is too low and the first append after boot takes a 412
// that fences an otherwise healthy writer. WALD-65, blocked by this file,
// owns that.
func (l *Leases) Open(ctx context.Context, stream StreamID) (*Lease, error) {
	if err := ValidateStreamID(stream); err != nil {
		return nil, err
	}
	if l.fencer.IsFenced(stream) {
		return nil, RefusePermanentlyFenced(stream)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Re-check now that mu is held: a concurrent Open of a different
	// stream cannot have fenced this one, but a concurrent Append on an
	// already-open lease for this exact stream could have, between the
	// unlocked check above and this one.
	if l.fencer.IsFenced(stream) {
		return nil, RefusePermanentlyFenced(stream)
	}
	if existing, ok := l.leases[stream]; ok {
		return existing, nil
	}

	prefix := TxPrefix(stream)
	var (
		head  Seq
		found bool
	)
	// Every key List yields is parsed here, not just the last one: section
	// 10's ascending-order guarantee makes the last key the head once every
	// key has been validated, but skips nothing along the way. A malformed
	// key that happens to sort below the head (a stray ".bak" copy, a
	// placeholder object) is exactly as suspect as one that sorts above it
	// - the doc comment above promises a one-line refusal, not a skipped
	// key, and that promise held only for the head before this fix.
	if err := l.lister.List(ctx, prefix, "", func(key string) error {
		seq, err := parseTxSeq(prefix, key)
		if err != nil {
			// A stray object under tx/ - a console-created placeholder, a
			// leftover copy artifact, anything a migration tool left
			// behind - is reachable without any walden bug, and from this
			// point on every push to this stream fails here. what and fix
			// match every other refusal in this package (fencing.go,
			// refuseSeqExhausted below) rather than standing out as the
			// one refusal that neither announces itself as a refusal nor
			// tells the operator what to do about it.
			what := "refusal: push failed"
			if stream == MetaStreamID {
				what = "refusal: meta operation failed"
			}
			return refusal.RefuseWithCause(
				what,
				fmt.Sprintf("transaction key %q under tx/ does not parse: %s", key, err.Error()),
				fmt.Sprintf("remove the malformed object at key %q from the bucket", key),
				err,
			)
		}
		head, found = seq, true
		return nil
	}); err != nil {
		return nil, err
	}

	var (
		next      Seq
		exhausted bool
	)
	if found {
		// head+1 is the next sequence to hand out, unless head is already
		// the maximum representable sequence, in which case head+1 would
		// silently wrap to 0 - already the head's own key - rather than
		// signal that the stream has no room left. See the same guard in
		// Lease.Append.
		if head == math.MaxUint64 {
			exhausted = true
		} else {
			next = head + 1
		}
	}

	lease := &Lease{stream: stream, fencer: l.fencer, next: next, exhausted: exhausted}
	l.leases[stream] = lease
	return lease, nil
}

// parseTxSeq parses the sequence out of a tx/ listing key, given the
// prefix it was listed under. It refuses anything that is not exactly
// "<prefix><20 digits>.json" - no nested path, no different extension, no
// short or long sequence - rather than accept a near miss.
func parseTxSeq(prefix, key string) (Seq, error) {
	base, ok := strings.CutPrefix(key, prefix)
	if !ok {
		return 0, fmt.Errorf("%w: key %q does not start with %q", ErrInvalidSeq, key, prefix)
	}
	base, ok = strings.CutSuffix(base, ".json")
	if !ok || strings.Contains(base, "/") {
		return 0, fmt.Errorf("%w: key %q is not a direct .json entry under %q", ErrInvalidSeq, key, prefix)
	}
	return ParseSeq(base)
}

// Lease is one stream's sequence lease: this process's memoized view of
// the stream's head, discovered once by (*Leases).Open and advanced only
// by a successful Append. The only way to consume a sequence is Append,
// which owns the entire checkout from start to finish inside one call - it
// acquires the sequence, invokes the caller's function with it, and
// resolves the checkout itself in a defer before returning. There is no
// step where a sequence is handed to a caller and the caller is trusted to
// report back later: nothing outside this file can hold a checkout open,
// so there is no such thing as a caller that forgets to release one.
// Abandonment - the failure mode three earlier rounds of review kept
// finding new symptoms of (a wedged process, a fatal double-unlock, a
// stream refused forever with no remedy, a healthy stream fenced on a
// wall-clock guess) - is not detected, tolerated, or timed out here; it is
// unrepresentable, the same standard this file already holds itself to for
// section 11.4 item 4.
//
// At most one Append is ever in flight on a Lease at a time. A second
// Append while one is running does not wait for it - Go already has a
// mechanism (the running call's own eventual return) that will resolve the
// first one without a clock, so there is nothing to time out - it refuses
// in one line, immediately, and the caller retries once the in-flight
// Append has returned. That in-flight window is bounded by how long the
// caller's own fn takes, never by this package.
type Lease struct {
	stream StreamID
	fencer *Fencer

	// mu guards next, exhausted, and busy. It is held only for the two short
	// windows inside Append that read or write this state - acquiring the
	// seq to hand fn and releasing it again once fn has returned - never
	// while fn itself is running, so a slow fn blocks nothing but a second
	// concurrent Append on the same Lease.
	mu        sync.Mutex
	next      Seq
	exhausted bool
	busy      bool // true only while an Append's fn is running on this Lease
}

// Stream returns the stream this lease was opened for.
func (l *Lease) Stream() StreamID { return l.stream }

// Fencer returns the Fencer this lease reports conflicts and unknown
// outcomes through - the same one shared by every other lease this
// stream's Leases registry has ever opened.
func (l *Lease) Fencer() *Fencer { return l.fencer }

// Append acquires the next sequence for this stream, calls fn with it, and
// resolves the checkout before returning - the only way a sequence ever
// leaves this type. It refuses with RefusePermanentlyFenced, making zero
// network calls, if the stream is already fenced (checked both before and
// after acquiring mu, since a concurrent Append can fence the stream in the
// instant between the two). It refuses in one line, rather than wait, if
// another Append is already running on this Lease. It refuses in one line,
// rather than silently wrap onto sequence 0 - already written - once the
// stream has exhausted the full 64-bit sequence space.
//
// fn's outcome is classified exactly as an earlier version of this file's
// Failed method classified it:
//
//   - fn returns nil: the append landed. The lease advances to seq+1 (or,
//     at the maximum 64-bit sequence, marks itself exhausted instead of
//     wrapping to 0).
//   - fn returns an error matching ErrPreconditionFailed: a proven 412.
//     The stream fences permanently through Fencer.HandleConflict (spec
//     section 11.4 items 2-3), and that refusal is returned.
//   - fn returns an error matching ErrOutcomeUnknown: the append's outcome
//     could not be proven either way. The stream fences permanently
//     through Fencer.HandleOutcomeUnknown (spec section 11.4 item 6), and
//     that refusal is returned.
//   - fn returns any other error: returned unchanged. The stream stays
//     unfenced and the sequence is not consumed, so the next Append offers
//     the same seq again. Conflating this retryable case with fencing is
//     the split-brain bug WALD-22 typed ErrPrecondition and
//     ErrOutcomeUnknown to prevent.
//   - fn panics: the process cannot prove whether the write it was in the
//     middle of landed - exactly the epistemic position ErrOutcomeUnknown
//     exists for - so Append recovers the panic, fences the stream through
//     Fencer.HandleOutcomeUnknown, and re-panics so the panic still
//     propagates to fn's own caller rather than being swallowed here.
//   - fn calls runtime.Goexit, terminating its goroutine without returning
//     and without panicking: the same epistemic position as a panic, so
//     the deferred resolution fences through Fencer.HandleOutcomeUnknown
//     rather than leave busy set for the life of the process. There is no
//     value to return to - the goroutine is gone - but the stream is left
//     fenced rather than wedged, so a later Append from a healthy
//     goroutine gets a real refusal instead of "in progress" forever.
//
// mu is not held while fn runs: Append takes it only to read the seq to
// hand fn and mark this Lease busy, releases it, calls fn unlocked, then
// reacquires it to finalize the outcome. A slow fn therefore blocks no
// other stream and no other operation on this process - only a second,
// concurrent Append on this same Lease, which refuses rather than waits.
func (l *Lease) Append(fn func(seq Seq) error) (err error) {
	if l.fencer.IsFenced(l.stream) {
		return RefusePermanentlyFenced(l.stream)
	}

	l.mu.Lock()
	if l.fencer.IsFenced(l.stream) {
		l.mu.Unlock()
		return RefusePermanentlyFenced(l.stream)
	}
	if l.busy {
		l.mu.Unlock()
		return refuseSeqBusy(l.stream)
	}
	if l.exhausted {
		l.mu.Unlock()
		return refuseSeqExhausted(l.stream)
	}
	seq := l.next
	l.busy = true
	l.mu.Unlock()

	var (
		callErr   error
		panicked  any
		completed bool
	)
	// The resolution below runs in a defer, not straight-line code after
	// the call to fn, because a panic is not the only way fn can fail to
	// return: fn calling runtime.Goexit (in practice, t.Fatal/FailNow
	// inside fn, in this package's own tests) also unwinds past any
	// straight-line resolution, and a defer is the only thing a Goexit
	// unwind still runs. completed is set as the last statement of the
	// normal path, once fn has returned and callErr holds its result; the
	// deferred resolution checks it before trusting callErr, so a Goexit
	// unwind - which leaves panicked nil, the same as a normal return -
	// cannot fall through and advance the sequence as though the append
	// had landed. Not completed and not panicking is its own outcome: the
	// process cannot prove whether fn's write landed, the same epistemic
	// position a panic leaves it in, so it is routed through
	// Fencer.HandleOutcomeUnknown exactly as the panic case below is,
	// rather than left to leave busy set for the life of the process.
	defer func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.busy = false

		if panicked != nil {
			l.fencer.HandleOutcomeUnknown(l.stream, seq)
			panic(panicked)
		}

		if !completed {
			err = l.fencer.HandleOutcomeUnknown(l.stream, seq)
			return
		}

		switch {
		case callErr == nil:
			if seq == math.MaxUint64 {
				l.exhausted = true
			} else {
				l.next = seq + 1
			}
		case errors.Is(callErr, ErrPreconditionFailed):
			err = l.fencer.HandleConflict(l.stream, seq)
		case errors.Is(callErr, ErrOutcomeUnknown):
			err = l.fencer.HandleOutcomeUnknown(l.stream, seq)
		default:
			err = callErr
		}
	}()

	func() {
		defer func() { panicked = recover() }()
		callErr = fn(seq)
		completed = true
	}()

	return nil
}

// refuseSeqExhausted is Append's one-line refusal for a stream that has
// written every sequence from 0 through the maximum 64-bit value: there is
// no next sequence left to lease, and the alternative - wrapping to 0 -
// would collide with that sequence's own, already-written record.
func refuseSeqExhausted(stream StreamID) error {
	what := "refusal: push failed"
	if stream == MetaStreamID {
		what = "refusal: meta operation failed"
	}
	return refusal.Refuse(
		what,
		fmt.Sprintf("stream %s has exhausted its 64-bit sequence space", stream),
		"",
	)
}

// refuseSeqBusy is Append's one-line refusal when another Append is
// already running on this Lease. It names no internal method and promises
// no event to wait for: the in-flight Append is guaranteed, by its own
// structure, to finish and release the checkout on its own - there is no
// abandoned or unbounded case to describe here, only ordinary contention,
// so the fix is simply to retry.
func refuseSeqBusy(stream StreamID) error {
	what := "refusal: push failed"
	fix := "retry the push"
	if stream == MetaStreamID {
		what = "refusal: meta operation failed"
		fix = "retry the meta operation"
	}
	return refusal.Refuse(
		what,
		fmt.Sprintf("stream %s already has an append in progress", stream),
		fix,
	)
}
