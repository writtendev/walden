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
	"time"

	"github.com/writtendev/walden/internal/refusal"
)

// abandonedCheckoutGrace bounds how long Next tolerates an outstanding
// checkout with no matching Landed or Failed before concluding it was
// abandoned rather than merely slow, and fencing rather than continuing to
// refuse with refuseSeqOutstanding forever (see the Lease doc comment).
// ARCHITECTURE.md documents the ordinary cost of one ref-transaction
// append as a "~50-150 ms" round trip; by the time Next hands out a seq,
// the slow, unbounded part of a push (receiving the client's packfile) is
// already behind it, so what remains is a small, bounded conditional PUT.
// This grace period is set with wide headroom above that ordinary cost so
// a merely-slow, still-legitimate append - one more attempt in store's
// own bounded retry loop, a bad network minute - is never mistaken for an
// abandoned one; only a caller that truly never reports back ever reaches
// it. It is a var, not a const, only so SetAbandonedCheckoutGraceForTest
// can shrink it for a test; production code never changes it, and this is
// not a sixth knob - there is no flag or env var that reaches it.
var abandonedCheckoutGrace = 5 * time.Minute

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
// ever outstanding for this stream at a time, but - unlike an earlier
// version of this file - no lock is ever held across the boundary between
// them. Next takes mu only for the instant it needs to check the current
// state and, if nothing is outstanding, record the seq it is about to
// hand out; it releases mu before returning either way. A second Next
// while one is already outstanding does not wait for it: it refuses in
// one line, immediately, rather than block - a caller waiting on the old
// held lock would eventually have been served, with a sequence of its
// own; this design trades that away for the guarantee that forgetting to
// release a checkout can never wedge a process (see refuseSeqOutstanding
// for why that trade was made).
//
// A caller who takes a seq from Next and, for any reason (a marshal or
// signing error, a validation refusal, a cancelled context, a panic
// recovered upstream), never calls Landed or Failed has abandoned that
// checkout - and this process now has no way to learn whether the append
// it never made a call about was ever attempted. That is not a distinct
// problem from an outcome storage itself cannot prove either way (spec
// section 11.4 item 6): it is the same problem, so it gets the same
// answer. Next tolerates an outstanding checkout, refusing in one line
// without touching it, for up to abandonedCheckoutGrace - long enough that
// no merely-slow, still-legitimate append is ever caught by it (see that
// var's doc comment) - and only past that grace period does the next Next
// call conclude the checkout was abandoned, clear it, and fence the stream
// through Fencer.HandleOutcomeUnknown exactly as Failed does for a proven
// unknown outcome. From there the stream is a stream like any other this
// package fences: RefusePermanentlyFenced, zero network calls, restart to
// recover - a real, always-available remedy, not the unresolvable "wait
// for a Landed or Failed that will never arrive" a soft, non-fenced
// "refused forever" state would leave behind. Every caller on the write
// path must still call exactly one of Landed or Failed for every seq Next
// hands it - that discipline has not gone away - but failing to hold up
// that discipline now costs, at worst, a one-line refusal to concurrent
// callers until the grace period passes and the stream fences itself,
// never an unrecoverable process and never a stream stuck with no way out.
//
// Landed and Failed verify seq against the outstanding one before doing
// anything else: a mismatched seq - stale, off-by-one, or a second release
// for a checkout that already cleared (including one this file itself
// cleared by fencing it as abandoned) - refuses instead of silently
// advancing next past an unwritten sequence (a permanent gap forbidden by
// section 1 and section 12) or unlocking a state nothing holds.
//
// Within the grace period, this still closes the race the held lock
// closed: two goroutines in this process racing an append to the same
// stream can never be handed the same sequence, because only one seq is
// ever outstanding at a time and Next hands out the current one exactly
// once. A second goroutine's genuine 412 in that scenario would be
// indistinguishable from a stale external writer's, and section 11.4 item
// 4 forbids telling them apart by re-reading, so letting two goroutines
// collide on one seq would fence a perfectly healthy stream over its own
// concurrency - the same reason the original design serialized here at
// all.
type Lease struct {
	stream StreamID
	fencer *Fencer

	// mu guards next, exhausted, outstanding, outstandingSeq, and
	// outstandingSince. It is held only for the duration of a single Next,
	// Landed, or Failed call - never across the boundary between them - so
	// nothing a caller does between those calls, including never calling
	// one at all, can leave mu held.
	mu               sync.Mutex
	next             Seq
	exhausted        bool
	outstanding      bool      // true from a successful Next until the matching Landed, Failed, or grace-period fencing
	outstandingSeq   Seq       // valid only while outstanding is true
	outstandingSince time.Time // when the outstanding checkout was recorded; valid only while outstanding is true
}

// Stream returns the stream this lease was opened for.
func (l *Lease) Stream() StreamID { return l.stream }

// Fencer returns the Fencer this lease reports conflicts and unknown
// outcomes through - the same one shared by every other lease this
// stream's Leases registry has ever opened.
func (l *Lease) Fencer() *Fencer { return l.fencer }

// Next returns the sequence to write next. It refuses with
// RefusePermanentlyFenced, making zero network calls, once the stream is
// fenced - checked both before and after acquiring mu, since a concurrent
// Failed (or this same method, on a previous call) can fence the stream in
// the instant between the two. It refuses in one line, rather than block,
// if a previously returned seq has not yet reached a matching Landed or
// Failed and the grace period for that checkout has not yet passed - see
// the Lease doc comment for why that is a refusal and not a wait. Once the
// grace period has passed with no release, Next concludes the checkout was
// abandoned and fences the stream through the same unknown-outcome path
// Failed uses, atomically with clearing it - see the Lease doc comment.
// It refuses in one line, rather than silently wrapping onto sequence 0 -
// already written - once the stream has exhausted the full 64-bit
// sequence space.
func (l *Lease) Next() (Seq, error) {
	if l.fencer.IsFenced(l.stream) {
		return 0, RefusePermanentlyFenced(l.stream)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.fencer.IsFenced(l.stream) {
		return 0, RefusePermanentlyFenced(l.stream)
	}
	if l.outstanding {
		if time.Since(l.outstandingSince) < abandonedCheckoutGrace {
			return 0, refuseSeqOutstanding(l.stream, l.outstandingSeq)
		}
		// The checkout has outlived any legitimate append by a wide
		// margin (see abandonedCheckoutGrace) with no Landed or Failed
		// ever arriving for it. Clear it and fence in the same
		// acquisition of mu that discovered the abandonment - the mirror
		// of the fix in Failed below - so no concurrent Next can ever
		// observe outstanding cleared while the stream is not yet fenced.
		abandonedSeq := l.outstandingSeq
		l.outstanding = false
		return 0, l.fencer.HandleOutcomeUnknown(l.stream, abandonedSeq)
	}
	if l.exhausted {
		return 0, refuseSeqExhausted(l.stream)
	}

	l.outstanding = true
	l.outstandingSeq = l.next
	l.outstandingSince = time.Now()
	return l.next, nil
}

// Landed records that storage acknowledged the append at seq, advancing
// the lease to seq+1 and clearing the outstanding checkout Next recorded.
// seq must be the one outstanding seq Next most recently returned; any
// other value - stale, off-by-one, or a checkout that already cleared -
// is refused rather than accepted, so a caller-side bookkeeping mistake
// can never open a permanent gap in tx/ by advancing next past a
// sequence nothing wrote. seq at the maximum 64-bit value has no
// successor, so the lease is marked exhausted instead of wrapping to 0.
func (l *Lease) Landed(seq Seq) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.outstanding || seq != l.outstandingSeq {
		return refuseSeqMismatch(l.stream, "Landed", seq, l.outstanding, l.outstandingSeq)
	}
	l.outstanding = false

	if seq == math.MaxUint64 {
		l.exhausted = true
		return nil
	}
	l.next = seq + 1
	return nil
}

// Failed classifies a conditional append's failure at seq and clears the
// outstanding checkout Next recorded. seq must be the one outstanding seq
// Next most recently returned; any other value is refused before it is
// classified at all, so a stale or mismatched seq can never be
// interpolated into the operator-facing section 11.5 fencing refusal in
// place of the sequence the append was actually attempted at. Once
// matched, a proven precondition failure or an outcome that could not be
// proven either way both permanently fence the stream (spec/journal/v1
// section 11.4 items 2-3 and item 6) through Fencer - HandleConflict and
// HandleOutcomeUnknown respectively - and Failed returns the resulting
// one-line refusal. Any other cause (store.ErrStorageUnavailable, a
// refused request, a cancelled context) is returned unchanged: the stream
// stays unfenced and next stays where it was, so the same seq is offered
// again by the next Next call. Conflating that retryable case with
// fencing is the split-brain bug WALD-22 typed ErrPrecondition and
// ErrOutcomeUnknown to prevent.
//
// mu is held across the whole call, including the Fencer call in the
// fencing branches, not just across the seq check: clearing outstanding
// and fencing the stream must be indivisible with respect to a concurrent
// Next, or a Next between the two could see outstanding already clear but
// the stream not yet fenced, and be handed the very seq Failed is in the
// middle of retiring. Next takes the same mu before it checks fenced-ness
// or records a new outstanding seq (see Next), so holding mu here for the
// duration closes that window rather than relocating it.
func (l *Lease) Failed(seq Seq, err error) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.outstanding || seq != l.outstandingSeq {
		return refuseSeqMismatch(l.stream, "Failed", seq, l.outstanding, l.outstandingSeq)
	}

	switch {
	case errors.Is(err, ErrPreconditionFailed):
		l.outstanding = false
		return l.fencer.HandleConflict(l.stream, seq)
	case errors.Is(err, ErrOutcomeUnknown):
		l.outstanding = false
		return l.fencer.HandleOutcomeUnknown(l.stream, seq)
	default:
		l.outstanding = false
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

// refuseSeqOutstanding is Next's one-line refusal when a previously
// returned seq has not yet reached a matching Landed or Failed and is
// still within abandonedCheckoutGrace: rather than block waiting for it,
// which is what wedged a stream for the life of the process whenever a
// caller's own error path skipped the release (round 1 review, findings
// 1-2), Next refuses immediately and leaves it to the caller to retry
// once the in-flight append resolves. This refusal, and only this one, is
// unchanged by the grace period: two goroutines racing a legitimate
// append to the same stream still see exactly this wording, not fencing
// (round 2 review, finding 3) - it is refuseSeqOutstanding's caller, Next,
// that stops returning it and fences instead once the checkout has been
// outstanding long enough that it can no longer plausibly be that race.
func refuseSeqOutstanding(stream StreamID, seq Seq) error {
	what := "refusal: push failed"
	if stream == MetaStreamID {
		what = "refusal: meta operation failed"
	}
	return refusal.Refuse(
		what,
		fmt.Sprintf("stream %s already has seq %d outstanding from a previous Next", stream, seq),
		"wait for the in-flight append to call Landed or Failed, then retry",
	)
}

// refuseSeqMismatch is Landed's and Failed's one-line refusal when seq is
// not the one outstanding seq Next most recently returned - including
// when nothing is outstanding at all. Most triggers are an ordinary
// caller-side mistake rather than a storage condition: a deferred cleanup
// registered before checking Next's own error, a retry loop calling
// Failed twice for one Next, a stale or recomputed seq passed to Landed.
// One trigger is not a mistake: a checkout Next itself already cleared and
// fenced as abandoned (see abandonedCheckoutGrace) reaches here too, if
// its caller does eventually call Landed or Failed - by then the stream
// is already fenced, so RefusePermanentlyFenced governs any further write
// attempt regardless of what this refusal says. None of these triggers
// may silently open a permanent gap in tx/ (Landed) or misattribute a
// fencing sequence to the operator (Failed), and - the failure round 1
// review reproduced as an unrecoverable "fatal error: sync: unlock of
// unlocked mutex" - none of them may crash the process either. Refusing
// here is what makes both impossible.
func refuseSeqMismatch(stream StreamID, op string, seq Seq, outstanding bool, outstandingSeq Seq) error {
	what := "refusal: push failed"
	if stream == MetaStreamID {
		what = "refusal: meta operation failed"
	}
	why := fmt.Sprintf("%s(%d) called for stream %s with no outstanding Next", op, seq, stream)
	if outstanding {
		why = fmt.Sprintf("%s(%d) called for stream %s while seq %d is the outstanding one", op, seq, stream, outstandingSeq)
	}
	return refusal.Refuse(
		what,
		why,
		"call Landed or Failed exactly once, with the seq the matching Next returned",
	)
}
