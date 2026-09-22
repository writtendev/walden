// This file adds walden's write path for ref-transaction records (WALD-27,
// spec/journal/v1 section 5): the one method that builds, signs, and
// marshals a RefTransactionRecord, then hands its bytes to the per-stream
// sequence lease WALD-29's internal/journal/lease.go already owns end to
// end.
//
// AppendRefTx is a caller of that lease, not a second implementation of
// it. As of WALD-118, (*journal.Lease).Append owns the one conditional PUT
// itself: it hands prepare the sequence to write at, takes back the bytes
// prepare built, and issues the write. Nothing here re-implements any part
// of that classification (see lease.go's own doc comment for the full
// contract) — the callback below only builds the record, signs it, and
// marshals it.
//
// The write lives here, in store, rather than in journal, for the same
// reason (*Client).AppendSegment does (segment.go, WALD-26): store already
// imports journal for every format helper this needs, and the reverse
// import would cycle.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
)

// AppendRefTx builds a RefTransactionRecord at the sequence lease hands
// out, signs it with signer (its epoch and private key, WALD-30), marshals
// it, and conditionally writes it to "v1/streams/<stream>/tx/<seq>.json"
// (spec/journal/v1 section 9.2), returning the sequence it landed at.
//
// The stream comes from lease.Stream(), never a separate parameter: a
// stream argument that could disagree with the lease it is appending
// through would be a bug waiting to be written, and taking it from the
// lease makes that disagreement unrepresentable.
//
// segments names pack segments AppendSegment (segment.go) has already
// written and object storage has already acknowledged — spec section 5:
// the ref-transaction record is appended after its segments, not before —
// and AppendRefTx neither writes them nor checks they exist: an existence
// check would be exactly the extra GET/LIST spec section 11.4 rules out
// for a conditional append. Ordering the two calls is the caller's job
// (WALD-46).
//
// now lets a test hold the clock still, the same parameter EnsureGenesis
// (genesis.go) already takes in this package for the same reason: c.now is
// the request-signing clock, and newFakeClient builds a client on real
// time.
//
// Six checks run before lease.Append is ever called, each a one-line
// refusal with zero network calls, in the order a caller's mistake is
// cheapest to catch:
//
//  1. A nil ctx. lease.Append (lease.go, WALD-118) refuses a nil ctx
//     itself, before issuing its PUT, so this check is no longer the only
//     thing standing between a nil ctx and a panic; it stays because it
//     gives this caller's own refusal shape rather than lease.Append's.
//  2. A nil signer. Still load-bearing: signer.SignRefTx is called inside
//     prepare (the closure below), and a method call through a nil
//     *journal.Signer panics there.
//  3. An invalid signer (signer.Valid()). Also load-bearing, and distinct
//     from check 2: journal.NewSigner refuses a wrong-size or mismatched
//     key when a *journal.Signer is built *through* it, but Signer's
//     fields are unexported, not unconstructable — &journal.Signer{} and
//     new(journal.Signer) compile from any package and produce a
//     non-nil *Signer whose zero-value private key is the wrong size for
//     ed25519.Sign, which panics rather than errors on that. This check
//     is what catches a *Signer that did not come from NewSigner; the
//     identical guard also lives inside signer.SignRefTx itself
//     (internal/journal/signer.go) for callers that reach it some other
//     way. It is repeated here only to keep this caller's own
//     zero-network-calls refusal shape, not because the in-method guard
//     alone would be insufficient.
//  4. A nil now. now is never called inside prepare (see below), so this
//     check is not load-bearing against a panic there; it stays because
//     it is one line and turns the common "forgot to pass a clock"
//     mistake into the same one-line refusal every other pre-check
//     gives, rather than a bare panic.
//  5. lease.Stream() naming the meta stream. Ref transactions never go on
//     _meta (spec section 9.1); RefTransactionRecord.Validate would catch
//     it too, but refusing here keeps it out of the append entirely.
//  6. No ref updates at all (spec section 5.1 requires at least one).
//
// now is hoisted above lease.Append rather than called inside prepare:
// nothing about the record's timestamp depends on the sequence
// lease.Append hands out, so now().UTC().Format(time.RFC3339) is computed
// once, below, before lease.Append is ever called. A caller-supplied
// clock that panics when invoked (not nil, just broken) now panics there,
// to this call's own caller, before lease.Append — and therefore its
// panic recovery and fencing (lease.go) — ever runs. That hoist is no
// longer load-bearing against fencing a healthy stream the way checks 2
// and 3 still are, now that lease.Append owns the PUT itself and only
// fences a panic that happens at or after it — but it remains correct,
// and removing it would buy nothing back.
//
// prepare itself is left with exactly what it needs to be: building the
// record (a struct literal), signing it (signer.SignRefTx, given a
// non-nil, valid signer checks 2 and 3 already proved), and marshaling it
// (pure, error-returning). It does not write to storage or call anything
// that does — lease.Append issues the one conditional PUT itself, once
// prepare has returned bytes with no error — so a bug in prepare that
// nonetheless panics now crashes with its own stack trace and leaves the
// stream untouched, per lease.Append's own contract.
//
// Beyond the six checks, AppendRefTx classifies nothing: a Validate, sign,
// or marshal failure inside prepare is passed back to lease.Append
// unchanged. lease.Append is the only place that sorts a proven 412 from
// an unprovable outcome from every other failure (spec section 11.4) —
// this file does not call PutIfAbsent at all, does not GET or LIST
// anything, and does not touch a Fencer.
func (c *Client) AppendRefTx(
	ctx context.Context,
	lease *journal.Lease,
	signer *journal.Signer,
	segments []string,
	updates []journal.RefUpdate,
	now func() time.Time,
) (journal.Seq, error) {
	if ctx == nil {
		return 0, refuseAppendRefTx(lease.Stream(), fmt.Errorf("ctx must not be nil"))
	}
	if signer == nil {
		return 0, refuseAppendRefTx(lease.Stream(), fmt.Errorf("signer must not be nil"))
	}
	if err := signer.Valid(); err != nil {
		return 0, refuseAppendRefTx(lease.Stream(), err)
	}
	if now == nil {
		return 0, refuseAppendRefTx(lease.Stream(), fmt.Errorf("now must not be nil"))
	}
	if lease.Stream() == journal.MetaStreamID {
		return 0, refuseAppendRefTx(lease.Stream(), fmt.Errorf("%w: ref transactions cannot be written to meta stream %q", journal.ErrInvalidRefTx, journal.MetaStreamID))
	}
	if len(updates) == 0 {
		return 0, refuseAppendRefTx(lease.Stream(), fmt.Errorf("%w: updates array must contain at least one ref update", journal.ErrInvalidRefTx))
	}

	// Computed here, once, rather than inside prepare: see the doc comment
	// above. A panic from now surfaces here, to this call's own caller,
	// before lease.Append — and therefore its panic recovery and fencing —
	// ever runs.
	ts := now().UTC().Format(time.RFC3339)

	var seq journal.Seq
	err := lease.Append(ctx, func(s journal.Seq) ([]byte, error) {
		seq = s
		rec := journal.NewRefTransactionRecord(lease.Stream(), s, signer.Epoch(), ts, segments, updates)
		if err := signer.SignRefTx(rec); err != nil {
			return nil, err
		}
		return journal.MarshalRefTx(rec)
	})
	if err != nil {
		return 0, err
	}
	return seq, nil
}

// refuseAppendRefTx wraps cause - an input validation failure caught before
// any network call - in walden's one-line operator-facing refusal shape,
// styled on internal/store/segment.go's refuseAppendSegment for the same
// kind of pre-check. It names the meta operation, not the push, when
// stream is _meta, matching the convention internal/journal/lease.go and
// fencing.go already use for that split.
func refuseAppendRefTx(stream journal.StreamID, cause error) error {
	what := "refusal: push failed"
	if stream == journal.MetaStreamID {
		what = "refusal: meta operation failed"
	}
	return refusal.RefuseWithCause(what, cause.Error(), "", cause)
}
