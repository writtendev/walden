// This file implements (*Client).RotateKey: the object-storage
// orchestration for spec/journal/v1 section 4.1's key rotation. It mirrors
// mintGenesis's ordering (genesis.go) deliberately — write the new private
// key to a temp file before its fate is known, append the record, and only
// rename the temp file into place once the append has won — because the
// risk is identical: signing.key must never be replaced ahead of the
// record that makes the new key legitimate. Unlike mintGenesis, the append
// itself goes through (*journal.Lease).Append (lease.go, WALD-29) rather
// than a bare PutIfAbsent: _meta already has a lease-worthy history by the
// time a rotation can happen at all (at minimum, its own genesis record),
// so this file has no head to discover and no fencing to implement — both
// belong to Lease, and duplicating either here is exactly what WALD-29's
// file comment warns against.
package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
)

// RotateKey performs a full key rotation: replay _meta to find the chain's
// currently active key, confirm this instance's local signing.key is that
// key, generate a fresh Ed25519 keypair, and append a key_rotation record
// signed by the outgoing key through leases.Open(ctx,
// journal.MetaStreamID).Append. It returns the retired (outgoing) and
// active (incoming) public keys, formatted, for the caller's own one-line
// report.
//
// Order of operations, mirroring mintGenesis's own doc comment:
//
//  1. ReplayMeta. Its own failures are already single-line refusals except
//     ErrObjectNotFound, which this function turns into a rotation-specific
//     refusal: a journal with no genesis record has no active key to
//     rotate away from.
//  2. LoadSigningKey, and refuse (in the same three-way split
//     EnsureGenesis's adopt path uses: missing, malformed, or unreadable)
//     if this instance holds none.
//  3. Refuse with RefuseNotActiveSigningKey if the local key's public half
//     is not the chain's active key — this instance cannot sign a
//     chainable rotation, so it must not be allowed to try.
//  4. GenerateKeypair, then WriteSigningKeyTemp for the *new* key. Written
//     before the record's fate is known, exactly as mintGenesis writes the
//     genesis key's temp file before its own conditional PUT — signing.key
//     itself is not touched yet.
//  5. leases.Open(ctx, journal.MetaStreamID), then Lease.Append: inside the
//     callback, first confirm the sequence the Lease hands it is the one
//     ReplayMeta's chain (step 1) actually verified up to — seq must equal
//     chain.LastMetaSeq()+1, or refuse (round 1 major finding: a concurrent
//     _meta append between step 1 and this Open, or a pre-existing gap, can
//     otherwise make the Lease offer a sequence past the one old_public_key
//     was verified against, landing a rotation record no replay could ever
//     accept while still committing signing.key to the new key). Only once
//     that holds: build the record at seq, sign it with the *outgoing*
//     private key, marshal it, and PutIfAbsent it.
//  6. On success, CommitSigningKey renames the new key into place — the
//     commit point, matching mintGenesis's own. A failure here refuses
//     with RefuseSigningKeyCommitFailed, naming whichever path (temp or
//     final) actually holds the key, exactly as mintGenesis's does.
//  7. On a proven 412 or a Lease-reported fence, the temp file is removed
//     and the Lease's own refusal (RefuseStreamFenced or
//     RefuseAppendOutcomeUnknown, both from lease.go/fencing.go) is
//     returned unchanged for the proven-412 case. On an *unprovable*
//     outcome the temp file is deliberately kept — it may be the only
//     surviving copy of a now-live key, the same reasoning
//     mintGenesis's own ErrOutcomeUnknown branch gives. Any other error
//     from the callback (a Sign or Marshal failure, or step 5's sequence
//     check failing) leaves _meta unfenced, per Lease.Append's own
//     contract, and the temp file is removed since nothing was ever sent
//     to storage.
func (c *Client) RotateKey(ctx context.Context, dataDir string, leases *journal.Leases, now func() time.Time) (retired, active string, err error) {
	chain, err := c.ReplayMeta(ctx)
	if err != nil {
		if errors.Is(err, ErrObjectNotFound) {
			return "", "", refuseNoGenesisToRotate()
		}
		return "", "", err
	}

	priv, err := journal.LoadSigningKey(dataDir)
	if err != nil {
		switch {
		case os.IsNotExist(err):
			return "", "", journal.RefuseNoSigningKey(dataDir)
		case errors.Is(err, journal.ErrSigningKeyUnavailable):
			return "", "", journal.RefuseInvalidSigningKeyFile(dataDir, err)
		default:
			return "", "", journal.RefuseSigningKeyUnreadable(err)
		}
	}
	localPub := priv.Public().(ed25519.PublicKey)
	localPubFormatted := journal.FormatPublicKey(localPub)
	if localPubFormatted != chain.ActiveKey() {
		return "", "", journal.RefuseNotActiveSigningKey(dataDir, localPubFormatted, chain.ActiveKey())
	}

	newPriv, newPub, err := journal.GenerateKeypair()
	if err != nil {
		return "", "", wrapGenesisKeygenFailure(err)
	}

	// The new private key is written to disk before its fate is known,
	// exactly as mintGenesis writes the genesis key's temp file ahead of
	// its own conditional PUT: signing.key itself is not touched here.
	tmpPath, err := journal.WriteSigningKeyTemp(dataDir, newPriv)
	if err != nil {
		return "", "", wrapGenesisDiskFailure(err)
	}

	lease, err := leases.Open(ctx, journal.MetaStreamID)
	if err != nil {
		// Nothing was ever sent to storage: either the stream was already
		// fenced (zero network calls, per (*journal.Leases).Open's own
		// doc comment) or the head-discovery LIST itself failed. Either
		// way there is no ambiguity about whether this rotation's record
		// landed, so the temp key is litter, not evidence.
		journal.RemoveSigningKeyTemp(tmpPath)
		return "", "", err
	}

	newPubFormatted := journal.FormatPublicKey(newPub)
	var putErr error
	appendErr := lease.Append(func(seq journal.Seq) error {
		// The consistency check the write side never asserted (round 1
		// major finding): old_public_key above was verified against
		// chain as of chain.LastMetaSeq(), but seq comes from the
		// Lease's own LIST-derived head, discovered independently at
		// leases.Open above. A concurrent _meta append landing between
		// ReplayMeta and that Open, or a pre-existing gap, can make the
		// two diverge — the lease then offers a sequence past the one
		// old_public_key was actually chained against, and signing a
		// record there would land one no future replay could ever
		// accept. ApplyRotation already enforces exactly this invariant
		// on the read side (identity.go: "r.Seq != c.lastMetaSeq+1");
		// this is its write-side counterpart, checked here (inside the
		// closure, where seq is finally known) rather than by re-reading
		// the head and retrying, which spec section 11.4 item 4 forbids.
		// A plain error is deliberate, not a fabricated precondition or
		// outcome-unknown: Lease.Append's own contract (lease.go) is
		// that any other error leaves the stream unfenced and the
		// sequence unconsumed, and that is the right outcome here — the
		// lease's cached view is stale, not the stream itself, and a
		// caller that replays _meta again gets a fresh, consistent
		// chain to rotate from.
		if want := chain.LastMetaSeq() + 1; seq != want {
			putErr = refuseMetaSequenceDrift(chain.LastMetaSeq(), seq)
			return putErr
		}
		rec := journal.NewKeyRotationRecord(seq, localPub, newPub, now().UTC().Format(time.RFC3339))
		if err := journal.SignRotation(priv, rec); err != nil {
			putErr = err
			return err
		}
		data, err := journal.MarshalKeyRotation(rec)
		if err != nil {
			putErr = err
			return err
		}
		putErr = c.PutIfAbsent(ctx, journal.TxKey(journal.MetaStreamID, seq), bytes.NewReader(data), int64(len(data)))
		return putErr
	})

	switch {
	case appendErr == nil:
		// The commit point: a crash or failure here leaves a rotation
		// record in the bucket whose new private key never reached disk
		// under its final name. renamed tells RefuseSigningKeyCommitFailed
		// which of CommitSigningKey's two internal steps failed, exactly
		// as it does for mintGenesis's own commit-failure branch.
		if renamed, err := journal.CommitSigningKey(dataDir, tmpPath); err != nil {
			return "", "", journal.RefuseSigningKeyCommitFailed(dataDir, tmpPath, renamed, err)
		}
		return localPubFormatted, newPubFormatted, nil
	case errors.Is(putErr, ErrPrecondition):
		// A proven 412: Lease.Append has already fenced _meta through
		// Fencer.HandleConflict and returned RefuseStreamFenced. This
		// instance lost the race to append the rotation, so the new key
		// never became live; the temp file is litter, exactly as
		// mintGenesis's own ErrPrecondition branch treats it.
		journal.RemoveSigningKeyTemp(tmpPath)
		return "", "", appendErr
	case errors.Is(putErr, ErrOutcomeUnknown):
		// An unprovable outcome: Lease.Append has fenced _meta through
		// Fencer.HandleOutcomeUnknown and returned
		// RefuseAppendOutcomeUnknown. The append may have landed, in
		// which case tmpPath is the only surviving copy of a now-live
		// key — deliberately not removed, mirroring mintGenesis's own
		// ErrOutcomeUnknown branch exactly.
		return "", "", appendErr
	default:
		// Any other error — a Sign or Marshal failure inside the
		// callback — never reached storage at all. Lease.Append leaves
		// _meta unfenced and the sequence unconsumed in this case (its
		// own doc comment), so the temp key is litter, not evidence.
		journal.RemoveSigningKeyTemp(tmpPath)
		return "", "", appendErr
	}
}

// refuseMetaSequenceDrift returns a one-line refusal when the sequence
// (*journal.Lease).Append hands RotateKey's callback does not immediately
// follow the sequence ReplayMeta's chain verified up to: a concurrent
// writer landed a _meta record after this rotation's replay, or the two
// diverge for some other reason (a pre-existing gap ReplayMeta itself did
// not already refuse — see meta.go's contiguity check). Retrying here would
// mean re-reading the head, which spec section 11.4 item 4 forbids; the
// correct recovery is simply running rotate-key again, which replays
// _meta fresh and rotates from whatever is actually current.
func refuseMetaSequenceDrift(chainLastSeq, leaseSeq journal.Seq) error {
	return refusal.Refuse(
		"rotate-key refused",
		fmt.Sprintf("this rotation's replay verified _meta through seq %d, but the append sequence offered is %d", chainLastSeq, leaseSeq),
		"retry rotate-key: _meta changed since this replay, so a fresh run will rotate from the current state",
	)
}

// refuseNoGenesisToRotate returns a one-line refusal when RotateKey finds
// no genesis record at all: there is no active signing key to rotate away
// from, because this journal has never been booted against by anything
// that would have minted or adopted one.
func refuseNoGenesisToRotate() error {
	return refusal.Refuse(
		"rotate-key refused",
		fmt.Sprintf("no genesis record found at %s", journal.TxKey(journal.MetaStreamID, 0)),
		"boot walden against this journal first so a signing identity exists to rotate",
	)
}
