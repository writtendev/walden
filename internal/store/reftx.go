// This file adds walden's write path for ref-transaction records (WALD-27,
// spec/journal/v1 section 5): the one method that builds, signs, marshals,
// and conditionally writes a RefTransactionRecord through the per-stream
// sequence lease WALD-29's internal/journal/lease.go already owns end to
// end.
//
// AppendRefTx is a caller of that lease, not a second implementation of
// it. (*journal.Lease).Append hands its callback the sequence to write at,
// classifies whatever the callback returns (nil advances the lease;
// journal.ErrPreconditionFailed and journal.ErrOutcomeUnknown fence the
// stream through the shared Fencer; any other error is returned unchanged
// with the sequence left unconsumed; a panic or runtime.Goexit inside the
// callback fences through the unknown-outcome path), and resolves the
// checkout before returning. Nothing here re-implements any part of that:
// the callback below builds the record, signs it, marshals it, and returns
// whatever PutIfAbsent returns, unwrapped.
//
// The write lives here, in store, rather than in journal, for the same
// reason (*Client).AppendSegment does (segment.go, WALD-26): store already
// imports journal for every format helper this needs, and the reverse
// import would cycle.
package store

import (
	"bytes"
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
// Five checks run before lease.Append is ever called, each a one-line
// refusal with zero network calls, in the order a caller's mistake is
// cheapest to catch:
//
//  1. A nil ctx. This is load-bearing, not defensive: ctx is handed to
//     PutIfAbsent inside the callback, and store.(*Client).do's first
//     statement calls ctx.Err() — a method call on a nil interface value
//     panics exactly where the checks below guard against panicking —
//     and unlike the clock (see below), ctx cannot be hoisted out of the
//     callback, because PutIfAbsent needs it at the point of the write.
//  2. A nil signer. Also load-bearing: signer.SignRefTx is called inside
//     the callback, and a method call through a nil *journal.Signer
//     panics exactly where check 1 guards ctx against panicking.
//     (journal.NewSigner already refuses a wrong-size or mismatched key
//     when the signer is built, so that check now lives there instead of
//     here — see WALD-30.)
//  3. A nil now. now is never called inside the callback (see below), so
//     this check is no longer load-bearing against a panic there; it
//     stays because it is one line and turns the common "forgot to pass
//     a clock" mistake into the same one-line refusal every other
//     pre-check gives, rather than a bare panic.
//  4. lease.Stream() naming the meta stream. Ref transactions never go on
//     _meta (spec section 9.1); RefTransactionRecord.Validate would catch
//     it too, but refusing here keeps it out of the append entirely.
//  5. No ref updates at all (spec section 5.1 requires at least one).
//
// Checks 1 and 2 exist because the thing they guard cannot be moved out of
// the callback and still do its job. now is different: nothing about the
// record's timestamp depends on the sequence lease.Append hands out, so
// now().UTC().Format(time.RFC3339) is computed once, below, before
// lease.Append is ever called — not inside its callback. A caller-supplied
// clock that panics when invoked (not nil, just broken) now panics there,
// before any lease interaction: an ordinary crash reaching AppendRefTx's
// caller, not a healthy stream permanently fenced through WALD-29's
// unknown-outcome path. That is the failure mode round 2 of this file's
// review found the nil check alone did not close.
//
// With ctx, signer, and the clock's call site all accounted for above, the
// callback itself is left with: building the record (a struct literal),
// signing it (signer.SignRefTx, given a non-nil signer check 2 already
// proved), marshaling it (pure, error-returning), and one conditional PUT
// (given a ctx check 1 already proved non-nil). Nothing else in it takes
// caller-supplied input that reaches a known panic site. That is narrower
// than "no panic path left" — this comment does not repeat that claim a
// third time — but it is what an audit of this callback's own call chain
// supports today.
//
// Beyond the five checks, AppendRefTx classifies nothing: a Validate, sign,
// or marshal failure inside the callback, and whatever PutIfAbsent itself
// returns, are both passed back to lease.Append unchanged. lease.Append is
// the only place that sorts a proven 412 from an unprovable outcome from
// every other failure (spec section 11.4) — this file does not call
// PutIfAbsent twice, does not GET or LIST anything, and does not touch a
// Fencer.
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
	if now == nil {
		return 0, refuseAppendRefTx(lease.Stream(), fmt.Errorf("now must not be nil"))
	}
	if lease.Stream() == journal.MetaStreamID {
		return 0, refuseAppendRefTx(lease.Stream(), fmt.Errorf("%w: ref transactions cannot be written to meta stream %q", journal.ErrInvalidRefTx, journal.MetaStreamID))
	}
	if len(updates) == 0 {
		return 0, refuseAppendRefTx(lease.Stream(), fmt.Errorf("%w: updates array must contain at least one ref update", journal.ErrInvalidRefTx))
	}

	// Computed here, once, rather than inside lease.Append's callback: see
	// the doc comment above. A panic from now surfaces here, to this
	// call's own caller, before lease.Append — and therefore its panic
	// recovery and fencing — ever runs.
	ts := now().UTC().Format(time.RFC3339)

	var seq journal.Seq
	err := lease.Append(func(s journal.Seq) error {
		seq = s
		rec := journal.NewRefTransactionRecord(lease.Stream(), s, signer.Epoch(), ts, segments, updates)
		if err := signer.SignRefTx(rec); err != nil {
			return err
		}
		data, err := journal.MarshalRefTx(rec)
		if err != nil {
			return err
		}
		return c.PutIfAbsent(ctx, journal.TxKey(lease.Stream(), s), bytes.NewReader(data), int64(len(data)))
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
