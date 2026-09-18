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
// signing chain's root of trust, then walks seq 1, 2, ... contiguously —
// by GET, not by LIST: this is a read/verify path, not an append, so it
// has no reason to reach for the head-discovery machinery
// (*journal.Leases).Open owns for the write side (lease.go, WALD-29), and
// doing so here would duplicate exactly the head discovery that file's own
// file comment warns against duplicating — until the first sequence that
// does not exist, which is the chain's current head. Each record in
// between is dispatched by its own "type" field, per spec section 8 step
// 2:
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

	for seq := journal.Seq(1); ; seq++ {
		body, err := c.Get(ctx, journal.TxKey(journal.MetaStreamID, seq))
		if err != nil {
			if errors.Is(err, ErrObjectNotFound) {
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
				return nil, err
			}
		case journal.RecordTypeTokenCreate:
			rec, err := journal.ParseTokenCreate(data)
			if err != nil {
				return nil, err
			}
			if err := chain.VerifyTokenCreate(rec); err != nil {
				return nil, err
			}
			if err := chain.AdvanceMetaSeq(seq); err != nil {
				return nil, err
			}
		case journal.RecordTypeTokenRevoke:
			rec, err := journal.ParseTokenRevoke(data)
			if err != nil {
				return nil, err
			}
			if err := chain.VerifyTokenRevoke(rec); err != nil {
				return nil, err
			}
			if err := chain.AdvanceMetaSeq(seq); err != nil {
				return nil, err
			}
		default:
			if err := chain.AdvanceMetaSeq(seq); err != nil {
				return nil, err
			}
		}
	}
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
