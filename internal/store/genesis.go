// This file implements EnsureGenesis (WALD-28, spec/journal/v1 sections
// 2.1, 3.2): the GET-then-conditional-PUT orchestration that decides
// whether a journal is minted or adopted. internal/journal/genesis.go holds
// the record's decode/encode and the local signing-key file — no I/O
// against object storage — because internal/journal cannot import
// internal/store (that would cycle), and only store can tell a 404 from a
// 403 or an ambiguous write. internal/store/probe.go is this file's
// precedent for that split.
package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"time"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
)

// EnsureGenesis returns the signing identity a boot with a journal
// configured runs on: adopted from an existing genesis record at _meta seq
// 0, or minted fresh when the journal is empty. The bool result reports
// which happened (true for minted), for the boot line
// cmd/walden/main.go prints.
//
// Order of operations is the substance of this function:
//
//  1. Get(TxKey(MetaStreamID, 0)).
//  2. Present -> adopt: ParseGenesis, NewSigningChain().ApplyGenesis, then
//     require a local signing key whose public half matches the record's.
//     Absent or mismatched -> a one-line refusal, because an instance that
//     cannot sign cannot journal, and a push it could not journal must not
//     be acknowledged (spec section 2.2).
//  3. ErrObjectNotFound -> mint: GenerateKeypair, build the record,
//     MarshalGenesis, write the temp key file, PutIfAbsent the record, and
//     only then rename the temp file into place. The rename is the commit
//     point: a crash between a winning PUT and the rename leaves a genesis
//     record in the bucket whose signing key never reached disk. That
//     window is narrowed to one atomic rename, not eliminated — there is no
//     recovery mode here, deliberately.
//  4. ErrPrecondition on that PUT -> the loser of the race. Spec section
//     11.4 items 2-4: a 412 is definitive proof another writer got there
//     first, so this instance does not re-read the head, does not retry,
//     and does not adopt within the same boot. It removes its temp key file
//     and returns journal.RefuseStreamFenced(MetaStreamID, 0), which refuses
//     boot in one line. Restart is the recovery: a restart takes the adopt
//     path at step 2, where it correctly refuses if the operator pointed a
//     second instance at another instance's journal.
//  5. ErrOutcomeUnknown on that PUT -> journal.RefuseAppendOutcomeUnknown
//     (MetaStreamID, 0), no resend and no GET to find out (spec section
//     11.4 item 6). Temp key file removed.
//  6. Any other GET/PUT failure -> wrapped once as a single "invalid
//     journal"-style refusal, the same shape wrapProbeFailure uses in
//     probe.go, so a 403 or an unreachable endpoint does not masquerade as
//     a corrupt journal.
func (c *Client) EnsureGenesis(ctx context.Context, dataDir string, now func() time.Time) (*journal.SigningChain, ed25519.PrivateKey, bool, error) {
	key := journal.TxKey(journal.MetaStreamID, 0)

	body, err := c.Get(ctx, key)
	switch {
	case err == nil:
		return c.adoptGenesis(dataDir, body)
	case errors.Is(err, ErrObjectNotFound):
		return c.mintGenesis(ctx, dataDir, key, now)
	default:
		return nil, nil, false, wrapGenesisFailure(err)
	}
}

// adoptGenesis handles EnsureGenesis's step 2: an existing genesis record
// was found at _meta seq 0.
func (c *Client) adoptGenesis(dataDir string, body io.ReadCloser) (*journal.SigningChain, ed25519.PrivateKey, bool, error) {
	defer body.Close()

	data, err := io.ReadAll(body)
	if err != nil {
		// Already a *refusal.Refusal from getBody.Read (client.go); no
		// second wrap is owed.
		return nil, nil, false, err
	}

	rec, err := journal.ParseGenesis(data)
	if err != nil {
		return nil, nil, false, journal.RefuseCorruptGenesis(err)
	}

	chain := journal.NewSigningChain()
	if err := chain.ApplyGenesis(rec); err != nil {
		return nil, nil, false, journal.RefuseCorruptGenesis(err)
	}

	priv, err := journal.LoadSigningKey(dataDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, false, journal.RefuseNoSigningKey(dataDir)
		}
		return nil, nil, false, journal.RefuseInvalidSigningKeyFile(dataDir, err)
	}
	got := journal.FormatPublicKey(priv.Public().(ed25519.PublicKey))
	if got != rec.PublicKey {
		return nil, nil, false, journal.RefuseSigningKeyMismatch(dataDir, rec.PublicKey, got)
	}

	return chain, priv, false, nil
}

// mintGenesis handles EnsureGenesis's steps 3-6: no genesis record exists
// yet, so this instance attempts to become the one that writes it.
func (c *Client) mintGenesis(ctx context.Context, dataDir, key string, now func() time.Time) (*journal.SigningChain, ed25519.PrivateKey, bool, error) {
	priv, pub, err := journal.GenerateKeypair()
	if err != nil {
		return nil, nil, false, wrapGenesisFailure(err)
	}

	rec := journal.NewGenesisRecord(pub, now().UTC().Format(time.RFC3339))
	data, err := journal.MarshalGenesis(rec)
	if err != nil {
		return nil, nil, false, wrapGenesisFailure(err)
	}

	// The temp key file is written before the record's fate is known: the
	// private key can only be committed to disk once the conditional PUT
	// below has won (EnsureGenesis's doc comment).
	if err := journal.WriteSigningKeyTemp(dataDir, priv); err != nil {
		return nil, nil, false, wrapGenesisFailure(err)
	}

	putErr := c.PutIfAbsent(ctx, key, bytes.NewReader(data), int64(len(data)))
	switch {
	case putErr == nil:
		// The commit point: a crash or failure here leaves a genesis
		// record in the bucket whose signing key never reached disk. The
		// temp file is deliberately not removed if this fails — it may
		// hold the only surviving copy of the private key.
		if err := journal.CommitSigningKey(dataDir); err != nil {
			return nil, nil, false, wrapGenesisFailure(err)
		}
		chain := journal.NewSigningChain()
		if err := chain.ApplyGenesis(rec); err != nil {
			return nil, nil, false, wrapGenesisFailure(err)
		}
		return chain, priv, true, nil
	case errors.Is(putErr, ErrPrecondition):
		journal.RemoveSigningKeyTemp(dataDir)
		return nil, nil, false, journal.RefuseStreamFenced(journal.MetaStreamID, 0)
	case errors.Is(putErr, ErrOutcomeUnknown):
		journal.RemoveSigningKeyTemp(dataDir)
		return nil, nil, false, journal.RefuseAppendOutcomeUnknown(journal.MetaStreamID, 0)
	default:
		journal.RemoveSigningKeyTemp(dataDir)
		return nil, nil, false, wrapGenesisFailure(putErr)
	}
}

// wrapGenesisFailure wraps a GET/PutIfAbsent failure that EnsureGenesis does
// not otherwise classify as a corrupt genesis record, a missing/mismatched
// local key, or fencing, as a single "invalid journal" refusal — the same
// shape wrapProbeFailure (probe.go) uses for the boot-time compare-and-swap
// probe, so a 403 or an unreachable endpoint at genesis time does not
// masquerade as a corrupt journal. It reuses probeFailureWhy/probeFailureFix
// rather than duplicating their cause-to-fix-clause mapping.
func wrapGenesisFailure(cause error) error {
	return refusal.RefuseWithCause("invalid journal", "genesis: "+probeFailureWhy(cause), probeFailureFix(cause), cause)
}
