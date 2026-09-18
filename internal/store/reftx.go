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
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
)

// AppendRefTx builds a RefTransactionRecord at the sequence lease hands
// out, signs it with priv under keyEpoch, marshals it, and conditionally
// writes it to "v1/streams/<stream>/tx/<seq>.json" (spec/journal/v1
// section 9.2), returning the sequence it landed at.
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
// Four checks run before lease.Append is ever called, each a one-line
// refusal with zero network calls, in the order a caller's mistake is
// cheapest to catch:
//
//  1. A private key of the wrong size. This is load-bearing, not
//     defensive: ed25519.Sign panics on a wrong-size key, and a panic
//     inside lease.Append's callback fences the stream through WALD-29's
//     unknown-outcome path — a malformed key must not take a healthy
//     stream out of service.
//  2. A nil now. This is load-bearing for the identical reason check 1
//     is: now is called inside the callback to stamp the record's
//     timestamp, and calling a nil func value panics exactly where check
//     1's wrong-size key does — a nil clock must not take a healthy
//     stream out of service either. After this check, the callback below
//     has no panic path left.
//  3. lease.Stream() naming the meta stream. Ref transactions never go on
//     _meta (spec section 9.1); RefTransactionRecord.Validate would catch
//     it too, but refusing here keeps it out of the append entirely.
//  4. No ref updates at all (spec section 5.1 requires at least one).
//
// Beyond those four, AppendRefTx classifies nothing: a Validate, sign, or
// marshal failure inside the callback, and whatever PutIfAbsent itself
// returns, are both passed back to lease.Append unchanged. lease.Append is
// the only place that sorts a proven 412 from an unprovable outcome from
// every other failure (spec section 11.4) — this file does not call
// PutIfAbsent twice, does not GET or LIST anything, and does not touch a
// Fencer.
func (c *Client) AppendRefTx(
	ctx context.Context,
	lease *journal.Lease,
	priv ed25519.PrivateKey,
	keyEpoch journal.Epoch,
	segments []string,
	updates []journal.RefUpdate,
	now func() time.Time,
) (journal.Seq, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return 0, refuseAppendRefTx(lease.Stream(), fmt.Errorf("ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv)))
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

	var seq journal.Seq
	err := lease.Append(func(s journal.Seq) error {
		seq = s
		rec := journal.NewRefTransactionRecord(lease.Stream(), s, keyEpoch, now().UTC().Format(time.RFC3339), segments, updates)
		if err := journal.SignRefTx(priv, rec); err != nil {
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
