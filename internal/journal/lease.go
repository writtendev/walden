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
	// stream cannot have fenced this one, but a concurrent Failed on an
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
		headKey string
		found   bool
	)
	if err := l.lister.List(ctx, prefix, "", func(key string) error {
		headKey, found = key, true
		return nil
	}); err != nil {
		return nil, err
	}

	var (
		next      Seq
		exhausted bool
	)
	if found {
		head, err := parseTxSeq(prefix, headKey)
		if err != nil {
			return nil, refusal.RefuseWithCause(
				fmt.Sprintf("open stream %s", stream),
				fmt.Sprintf("transaction key %q under tx/ does not parse: %s", headKey, err.Error()),
				"",
				err,
			)
		}
		// head+1 is the next sequence to hand out, unless head is already
		// the maximum representable sequence, in which case head+1 would
		// silently wrap to 0 - already the head's own key - rather than
		// signal that the stream has no room left. See the same guard in
		// Lease.Next.
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
// by Landed. Next, Landed, and Failed enforce that at most one sequence is
// ever outstanding for this stream at a time - Next blocks until the
// matching Landed or Failed for the previous call has returned - so two
// goroutines in this same process racing an append to the same stream are
// serialized here rather than left to race a real conditional PUT against
// each other. That race matters: a second goroutine's genuine 412 in that
// scenario is indistinguishable from a stale external writer's, and
// section 11.4 item 4 forbids telling them apart by re-reading, so an
// unserialized Lease would fence a perfectly healthy stream over its own
// concurrency.
type Lease struct {
	stream StreamID
	fencer *Fencer

	// checkout is locked by a successful Next and unlocked by the matching
	// Landed or Failed. It is not a "this goroutine's own lock" in the
	// usual sense - the goroutine that calls Landed or Failed is expected
	// to be the same one that called Next, but Go's sync.Mutex has no
	// owner, so nothing enforces that beyond the calling convention every
	// caller in this codebase follows. next and exhausted are read and
	// written only while checkout is held, so no separate mutex protects
	// them.
	checkout  sync.Mutex
	next      Seq
	exhausted bool
}

// Stream returns the stream this lease was opened for.
func (l *Lease) Stream() StreamID { return l.stream }

// Fencer returns the Fencer this lease reports conflicts and unknown
// outcomes through - the same one shared by every other lease this
// stream's Leases registry has ever opened.
func (l *Lease) Fencer() *Fencer { return l.fencer }

// Next returns the sequence to write next, checking out this lease until
// the matching Landed or Failed call. It refuses with RefusePermanentlyFenced,
// making zero network calls, once the stream is fenced - before and after
// checkout, since a concurrent Failed on the previously checked-out
// sequence can fence the stream while this call was waiting to check out.
// It refuses in one line, rather than silently wrapping onto sequence 0 -
// already written - once the stream has exhausted the full 64-bit sequence
// space.
func (l *Lease) Next() (Seq, error) {
	if l.fencer.IsFenced(l.stream) {
		return 0, RefusePermanentlyFenced(l.stream)
	}

	l.checkout.Lock() // released by the matching Landed or Failed

	if l.fencer.IsFenced(l.stream) {
		l.checkout.Unlock()
		return 0, RefusePermanentlyFenced(l.stream)
	}
	if l.exhausted {
		l.checkout.Unlock()
		return 0, refuseSeqExhausted(l.stream)
	}
	return l.next, nil
}

// Landed records that storage acknowledged the append at seq, advancing
// the lease to seq+1 and releasing the checkout Next took. seq at the
// maximum 64-bit value has no successor, so the lease is marked exhausted
// instead of wrapping to 0.
func (l *Lease) Landed(seq Seq) {
	defer l.checkout.Unlock()
	if seq == math.MaxUint64 {
		l.exhausted = true
		return
	}
	l.next = seq + 1
}

// Failed classifies a conditional append's failure at seq and releases the
// checkout Next took. A proven precondition failure or an outcome that
// could not be proven either way both permanently fence the stream
// (spec/journal/v1 section 11.4 items 2-3 and item 6) through Fencer -
// HandleConflict and HandleOutcomeUnknown respectively - and Failed
// returns the resulting one-line refusal. Any other cause (store.
// ErrStorageUnavailable, a refused request, a cancelled context) is
// returned unchanged: the stream stays unfenced and next stays where it
// was, so the same seq is offered again by the next Next call. Conflating
// that retryable case with fencing is the split-brain bug WALD-22 typed
// ErrPrecondition and ErrOutcomeUnknown to prevent.
func (l *Lease) Failed(seq Seq, err error) error {
	defer l.checkout.Unlock()
	switch {
	case errors.Is(err, ErrPreconditionFailed):
		return l.fencer.HandleConflict(l.stream, seq)
	case errors.Is(err, ErrOutcomeUnknown):
		return l.fencer.HandleOutcomeUnknown(l.stream, seq)
	default:
		return err
	}
}

// refuseSeqExhausted is Next's one-line refusal for a stream that has
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
