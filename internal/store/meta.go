// This file implements (*Client).ReplayMeta: spec/journal/v1 section 8's
// replay algorithm, steps 1 and 2, and nothing past them. It answers one
// question — "what is _meta's currently active signing key, epoch, and
// last sequence, right now" — which is exactly what both EnsureGenesis's
// adopt path (genesis.go) and RotateKey (rotation.go) need before either
// can safely touch signing.key or append to _meta. It does not rebuild the
// token table (WALD-33) and does not touch repository streams (WALD-34):
// both replay _meta for a different purpose than this one.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
)

// ReplayMeta reads the genesis record at _meta seq 0, applies it as the
// signing chain's root of trust, then walks seq 1, 2, ... contiguously by
// GET — this is a read/verify path, not an append, so it has no reason to
// reach for (*journal.Leases).Open's per-stream bookkeeping (lease.go,
// WALD-29), which this file does not duplicate — until the first sequence
// whose GET comes back not-found. That alone does not prove the walk has
// reached the chain's current head: a GET-only walk cannot tell "the
// object at this sequence is missing" (a gap) from "the stream ends the
// sequence before" (nothing wrong at all) — both read back as the same
// 404, and treating the first one as the second lets a rotation past a
// gap vanish silently (round 1 medium finding). probeMetaAfterNotFound
// corroborates with one List call before this function trusts a not-found
// as the head — but the corroborating List itself runs after the GET, so
// a legitimate concurrent _meta append can land at exactly seq in the gap
// between the two: the List then sees a key at seq, which is proof the
// stream merely grew during the walk, not proof of a hole (round 2 medium
// finding). Only a key at a sequence strictly greater than seq proves a
// hole; a key equal to seq means the record now exists and the walk
// simply retries the GET at the same seq. Each record between genesis and
// the confirmed head is dispatched by its own "type" field, per spec
// section 8 step 2:
//
//   - "key_rotation": parsed with ParseKeyRotation and applied through
//     (*journal.SigningChain).ApplyRotation, which both advances the chain
//     and folds the sequence forward.
//   - "token_create" / "token_revoke": parsed with the existing
//     ParseTokenCreate/ParseTokenRevoke, verified against the chain's
//     active key through VerifyTokenCreate/VerifyTokenRevoke, then folded
//     into the sequence with AdvanceMetaSeq. The token table itself is not
//     rebuilt (WALD-33 owns that); this only needs the record to have
//     verified before the sequence can be trusted to advance past it.
//   - anything else: AdvanceMetaSeq alone, with no attempt to parse the
//     record's other fields — spec section 5.4's forward-compatibility
//     rule for a meta record type this reader does not recognise.
//
// ReplayMeta returns ErrObjectNotFound, unwrapped, when _meta carries no
// genesis record at all: that is an empty journal, not a corrupt one, and
// EnsureGenesis's mint path is the caller that needs to tell the two
// apart. Every other failure — a corrupt or unchainable record, a network
// failure, a body over maxGenesisBody — comes back as a single-line
// refusal already, so no caller has anything left to wrap.
func (c *Client) ReplayMeta(ctx context.Context) (*journal.SigningChain, error) {
	chain := journal.NewSigningChain()

	genesisBody, err := c.Get(ctx, journal.TxKey(journal.MetaStreamID, 0))
	if err != nil {
		if errors.Is(err, ErrObjectNotFound) {
			return nil, err
		}
		return nil, wrapGenesisFailure(err)
	}
	genesisData, err := io.ReadAll(io.LimitReader(genesisBody, maxGenesisBody+1))
	genesisBody.Close()
	if err != nil {
		return nil, wrapGenesisFailure(err)
	}
	if len(genesisData) > maxGenesisBody {
		return nil, journal.RefuseCorruptGenesis(fmt.Errorf("object exceeds %d bytes, refusing to read further", maxGenesisBody))
	}
	genesisRec, err := journal.ParseGenesis(genesisData)
	if err != nil {
		return nil, journal.RefuseCorruptGenesis(err)
	}
	if err := chain.ApplyGenesis(genesisRec); err != nil {
		return nil, journal.RefuseCorruptGenesis(err)
	}

	for seq := journal.Seq(1); ; {
		body, err := c.Get(ctx, journal.TxKey(journal.MetaStreamID, seq))
		if err != nil {
			if errors.Is(err, ErrObjectNotFound) {
				grew, err := c.probeMetaAfterNotFound(ctx, seq)
				if err != nil {
					return nil, err
				}
				if grew {
					// The corroborating List proved a record now exists at
					// exactly this seq — a concurrent append landed between
					// the GET above and the List, not a hole. Re-read it at
					// the same seq rather than treating the 404 as the
					// stream's head.
					continue
				}
				return chain, nil
			}
			return nil, wrapMetaFailure(seq, err)
		}
		data, err := io.ReadAll(io.LimitReader(body, maxGenesisBody+1))
		body.Close()
		if err != nil {
			return nil, wrapMetaFailure(seq, err)
		}
		if len(data) > maxGenesisBody {
			return nil, refuseOversizedMetaRecord(seq, maxGenesisBody)
		}

		var head struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(data, &head); err != nil {
			return nil, refuseUnreadableMetaRecord(seq, err)
		}

		switch head.Type {
		case journal.RecordTypeKeyRotation:
			rec, err := journal.ParseKeyRotation(data)
			if err != nil {
				return nil, journal.RefuseCorruptRotation(seq, err)
			}
			if err := chain.ApplyRotation(rec); err != nil {
				return nil, refuseMetaVerificationFailed(seq, err)
			}
		case journal.RecordTypeTokenCreate:
			rec, err := journal.ParseTokenCreate(data)
			if err != nil {
				return nil, refuseMetaVerificationFailed(seq, err)
			}
			if err := chain.VerifyTokenCreate(rec); err != nil {
				return nil, refuseMetaVerificationFailed(seq, err)
			}
			if err := chain.AdvanceMetaSeq(seq); err != nil {
				return nil, refuseMetaVerificationFailed(seq, err)
			}
		case journal.RecordTypeTokenRevoke:
			rec, err := journal.ParseTokenRevoke(data)
			if err != nil {
				return nil, refuseMetaVerificationFailed(seq, err)
			}
			if err := chain.VerifyTokenRevoke(rec); err != nil {
				return nil, refuseMetaVerificationFailed(seq, err)
			}
			if err := chain.AdvanceMetaSeq(seq); err != nil {
				return nil, refuseMetaVerificationFailed(seq, err)
			}
		default:
			if err := chain.AdvanceMetaSeq(seq); err != nil {
				return nil, refuseMetaVerificationFailed(seq, err)
			}
		}
		seq++
	}
}

// errMetaContinuesPastGap is probeMetaAfterNotFound's internal signal that
// its corroborating List call found a key at a sequence strictly greater
// than the one whose GET came back not-found: proof the walk stopped at a
// genuine gap, not merely that the stream grew while the walk was running.
// It never escapes this file — List returns a callback's error unchanged
// (list.go's own doc comment), so this reaches probeMetaAfterNotFound
// directly and is turned into refuseMetaSequenceGap there.
var errMetaContinuesPastGap = errors.New("meta stream continues past a missing sequence")

// errMetaGrewDuringWalk is probeMetaAfterNotFound's internal signal that its
// corroborating List call found a key at exactly the sequence whose GET
// came back not-found: a legitimate concurrent _meta append landed in the
// window between that GET and this List, not a hole. It never escapes this
// file, for the same reason errMetaContinuesPastGap does not.
var errMetaGrewDuringWalk = errors.New("meta stream grew past a sequence during replay")

// probeMetaAfterNotFound corroborates a GET 404 at seq — the sequence
// ReplayMeta's contiguous walk just failed to read — against the actual
// listing before trusting it as _meta's head. One List call, starting
// after seq-1's own key (already confirmed present: genesis at seq 0, or a
// record this walk already read and applied), answers the question a
// GET-only walk cannot: List's ascending-order-over-tx/ guarantee (spec
// section 10, list.go's own doc comment) means the first key it yields
// here, if any, names the smallest sequence still to be seen, and that
// sequence can only be seq itself or something greater — nothing between
// seq-1 and seq exists to list.
//
// A first key equal to TxKey(MetaStreamID, seq) is not proof of a hole: it
// proves the record now exists, landed by a writer whose PutIfAbsent won
// between this walk's own GET and this corroborating List (round 2 medium
// finding — the fix this function's earlier version was missing). Only a
// first key at a sequence strictly greater than seq proves the walk
// genuinely skipped seq: nothing List could return names seq, so whatever
// wrote past it did not write at it. grew reports the first case so
// ReplayMeta's caller can retry the GET at the same seq; err carries a
// refusal only for a genuine hole or a List failure. A completely empty
// listing is the ordinary, expected case: the stream ends the sequence
// before, exactly as it did before this fix.
//
// The callback returns as soon as it sees one key — List stops and returns
// that error immediately (list.go) — so this is a one-object probe, not a
// second full listing of _meta.
func (c *Client) probeMetaAfterNotFound(ctx context.Context, seq journal.Seq) (grew bool, err error) {
	startAfter := journal.TxKey(journal.MetaStreamID, seq-1)
	wantKey := journal.TxKey(journal.MetaStreamID, seq)
	listErr := c.List(ctx, journal.TxPrefix(journal.MetaStreamID), startAfter, func(key string) error {
		if key == wantKey {
			return errMetaGrewDuringWalk
		}
		return errMetaContinuesPastGap
	})
	switch {
	case listErr == nil:
		return false, nil
	case errors.Is(listErr, errMetaGrewDuringWalk):
		return true, nil
	case errors.Is(listErr, errMetaContinuesPastGap):
		return false, refuseMetaSequenceGap(seq)
	default:
		return false, wrapMetaFailure(seq, listErr)
	}
}

// refuseMetaSequenceGap returns a one-line refusal when _meta's record at
// seq is missing but the listing proves the stream continues past it: a
// gap, not the stream's genuine end, per spec section 8's contiguous
// replay. Trusting the missing sequence as the head here is exactly what
// let a rotation past the gap adopt a stale active key and epoch (round 1
// medium finding) — this refuses instead, before any of that is chosen.
func refuseMetaSequenceGap(seq journal.Seq) error {
	return refusal.Refuse(
		"invalid journal",
		fmt.Sprintf("_meta seq %d is missing, but later meta records exist", seq),
		"restore the _meta stream from a known-good journal, or point this instance at a fresh journal prefix",
	)
}

// refuseMetaVerificationFailed wraps a _meta record's parse or chain-
// verification failure — ParseTokenCreate/ParseTokenRevoke, ApplyRotation,
// VerifyTokenCreate/VerifyTokenRevoke, AdvanceMetaSeq — as a one-line "invalid
// journal" refusal with a remedy, the same treatment RefuseCorruptRotation
// (journal/rotation.go) already gives a key_rotation record that fails to
// parse. Before this, these five calls returned cause unwrapped: one line,
// since every error journal/identity.go and journal/token.go build already
// is, but with no "invalid journal" prefix and no fix clause on a path an
// operator only ever reaches at boot (round 1 minor finding). cause is kept
// as the wrapped Unwrap() cause, so errors.Is against ErrUnchainableRotation,
// ErrInvalidTokenRecord, and the rest still holds for any caller checking a
// specific reason.
func refuseMetaVerificationFailed(seq journal.Seq, cause error) error {
	return refusal.RefuseWithCause(
		"invalid journal",
		fmt.Sprintf("_meta seq %d: %s", seq, cause.Error()),
		"restore the _meta stream from a known-good journal, or point this instance at a fresh journal prefix",
		cause,
	)
}

// wrapMetaFailure wraps a GET failure encountered while replaying _meta
// past genesis, in the same "invalid journal" shape wrapGenesisFailure
// uses for genesis's own GET (probe.go's probeFailureWhy/probeFailureFix),
// so a 403 or an unreachable endpoint at seq >= 1 does not masquerade as a
// corrupt record either.
func wrapMetaFailure(seq journal.Seq, cause error) error {
	return refusal.RefuseWithCause(
		"invalid journal",
		fmt.Sprintf("_meta seq %d: %s", seq, probeFailureWhy(cause)),
		probeFailureFix(cause),
		cause,
	)
}

// refuseOversizedMetaRecord and refuseUnreadableMetaRecord refuse a _meta
// record ReplayMeta cannot get far enough into to even dispatch on — too
// large to read safely, or not valid JSON at all. Neither can name a
// record type, since the type field is exactly what could not be read;
// both name the object key instead, the way RefuseCorruptGenesis names
// _meta seq 0's.
func refuseOversizedMetaRecord(seq journal.Seq, max int) error {
	return refusal.Refuse(
		"invalid journal",
		fmt.Sprintf("meta record at %s exceeds %d bytes", journal.TxKey(journal.MetaStreamID, seq), max),
		"restore the _meta stream from a known-good journal, or point this instance at a fresh journal prefix",
	)
}

func refuseUnreadableMetaRecord(seq journal.Seq, reason error) error {
	return refusal.RefuseWithCause(
		"invalid journal",
		fmt.Sprintf("meta record at %s is not valid JSON: %v", journal.TxKey(journal.MetaStreamID, seq), reason),
		"restore the _meta stream from a known-good journal, or point this instance at a fresh journal prefix",
		reason,
	)
}
