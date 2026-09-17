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
	"fmt"
	"io"
	"os"
	"time"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
)

// maxGenesisBody bounds how much of the genesis object at _meta seq 0
// walden reads into memory. A genesis record is ~250 bytes by spec section
// 3.1; this GET is the one boot step that reads a third party's bytes
// (spec section 2.2 admits a third party who can write the bucket before
// walden's first boot into the threat model), so it is bounded the way
// every other remote body read in this package already is —
// maxErrorBody in client.go, maxListPageBody in list.go — rather than left
// as the one unbounded io.ReadAll. It is generous headroom over a real
// record and tiny next to a hostile or misconfigured multi-gigabyte one.
const maxGenesisBody = 64 << 10 // 64 KiB

// EnsureGenesis returns the signing identity a boot with a journal
// configured runs on: adopted from an existing genesis record at _meta seq
// 0, or minted fresh when the journal is empty. The bool result reports
// which happened (true for minted), for the boot line
// cmd/walden/main.go prints.
//
// Order of operations is the substance of this function:
//
//  1. Get(TxKey(MetaStreamID, 0)), body bounded by maxGenesisBody.
//  2. Present -> adopt: ParseGenesis, NewSigningChain().ApplyGenesis, then
//     require a local signing key whose public half matches the record's
//     (compared as decoded bytes, not formatted hex, so case differences in
//     a spec-non-conformant but parseable record never look like a
//     mismatch). Absent or mismatched -> a one-line refusal, because an
//     instance that cannot sign cannot journal, and a push it could not
//     journal must not be acknowledged (spec section 2.2).
//  3. ErrObjectNotFound -> mint, refusing first if dataDir already holds a
//     signing.key (round 1 finding 2: that file belongs to some other
//     journal, and minting would rename straight over it). Otherwise:
//     GenerateKeypair, build the record, MarshalGenesis, write the temp key
//     file under a name unique to this call (round 1 finding 1), PutIfAbsent
//     the record, and only then rename the temp file into place. The rename
//     is the commit point: a crash between a winning PUT and the rename
//     leaves a genesis record in the bucket whose signing key never reached
//     disk under its final name — though it is very likely still sitting,
//     fsynced, at its temp name (round 1 finding 3). That window is narrowed
//     to one atomic rename, not eliminated — there is no recovery mode
//     here, deliberately.
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
//     11.4 item 6). Unlike step 4, the temp key file is deliberately kept,
//     not removed (round 1 finding 7): the PUT may have landed, and if it
//     did, the temp file is the only surviving copy of a now-permanent
//     record's private key.
//  6. Any other GET/PUT failure, or a local filesystem failure from steps 2
//     or 3 that never touched storage at all -> wrapped once as a single
//     "invalid journal"-style refusal. Storage failures use the same shape
//     wrapProbeFailure uses in probe.go, so a 403 or an unreachable
//     endpoint does not masquerade as a corrupt journal; local failures use
//     a data-directory-appropriate fix clause instead (round 1 finding 4),
//     so a full disk is never misreported as a bucket-credentials problem.
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

	// Bounded per maxGenesisBody's doc comment: reading declared+1 bytes
	// lets a body exactly at the cap succeed while anything past it is
	// detected without ever holding more than maxGenesisBody+1 bytes.
	data, err := io.ReadAll(io.LimitReader(body, maxGenesisBody+1))
	if err != nil {
		// getBody.Read's own *refusal.Refusal (client.go) carries
		// fixFor(ErrStorageUnavailable) = "pushes succeed when storage
		// returns" — true mid-push, false here: EnsureGenesis runs before
		// net.Listen, so a failure here means walden has exited and bound
		// nothing. Re-wrapping through wrapGenesisFailure swaps in the
		// same boot-appropriate fix clause ProbeCAS uses for the same
		// reason (probe.go's probeUnavailableFix doc comment).
		return nil, nil, false, wrapGenesisFailure(err)
	}
	if len(data) > maxGenesisBody {
		return nil, nil, false, journal.RefuseCorruptGenesis(fmt.Errorf("object exceeds %d bytes, refusing to read further", maxGenesisBody))
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
		switch {
		case os.IsNotExist(err):
			return nil, nil, false, journal.RefuseNoSigningKey(dataDir)
		case errors.Is(err, journal.ErrSigningKeyUnavailable):
			// A parse failure: LoadSigningKey wraps every malformed-content
			// error in ErrSigningKeyUnavailable, and only those.
			return nil, nil, false, journal.RefuseInvalidSigningKeyFile(dataDir, err)
		default:
			// A read failure LoadSigningKey did not wrap at all — its own
			// doc comment says a non-missing, non-parse failure is the raw
			// os.ReadFile error (EACCES, a bad owner, and similar). Telling
			// the operator "malformed" here and pointing at a backup
			// restore, as an earlier version of this file did, misdiagnoses
			// a permissions bug as corrupted content.
			return nil, nil, false, journal.RefuseSigningKeyUnreadable(err)
		}
	}

	// Compared as decoded key bytes, not formatted strings: ParsePublicKey
	// accepts uppercase hex (hex.DecodeString does), so a genesis record
	// carrying non-lowercase-but-parseable hex must not read as a mismatch
	// against a local key that is byte-for-byte correct. rec.PublicKey
	// already passed ParsePublicKey once, in ApplyGenesis above, so the
	// error here is unreachable in practice; RefuseCorruptGenesis is only
	// the defensive fallback.
	wantPub, err := journal.ParsePublicKey(rec.PublicKey)
	if err != nil {
		return nil, nil, false, journal.RefuseCorruptGenesis(err)
	}
	localPub := priv.Public().(ed25519.PublicKey)
	if !localPub.Equal(wantPub) {
		return nil, nil, false, journal.RefuseSigningKeyMismatch(dataDir, rec.PublicKey, journal.FormatPublicKey(localPub))
	}

	return chain, priv, false, nil
}

// mintGenesis handles EnsureGenesis's steps 3-6: no genesis record exists
// yet, so this instance attempts to become the one that writes it.
func (c *Client) mintGenesis(ctx context.Context, dataDir, key string, now func() time.Time) (*journal.SigningChain, ed25519.PrivateKey, bool, error) {
	// A pre-existing signing.key means dataDir already belongs to some
	// journal's identity — CommitSigningKey renames unconditionally, so
	// minting here would destroy that journal's only private key the
	// moment this instance's own conditional PUT won (round 1 finding 2;
	// see RefuseSigningKeyPresentOnMint's doc comment for the operator
	// scenario, typically --data-dir repointed at a new or typo'd journal
	// prefix).
	switch _, err := os.Stat(journal.SigningKeyPath(dataDir)); {
	case err == nil:
		return nil, nil, false, journal.RefuseSigningKeyPresentOnMint(dataDir)
	case !os.IsNotExist(err):
		return nil, nil, false, wrapGenesisDiskFailure(err)
	}

	priv, pub, err := journal.GenerateKeypair()
	if err != nil {
		return nil, nil, false, wrapGenesisKeygenFailure(err)
	}

	rec := journal.NewGenesisRecord(pub, now().UTC().Format(time.RFC3339))
	data, err := journal.MarshalGenesis(rec)
	if err != nil {
		return nil, nil, false, wrapGenesisKeygenFailure(err)
	}

	// The temp key file is written before the record's fate is known: the
	// private key can only be committed to disk once the conditional PUT
	// below has won (EnsureGenesis's doc comment). WriteSigningKeyTemp
	// names its own temp file per call (round 1 finding 1), so tmpPath is
	// this attempt's alone — nothing else writing to dataDir can collide
	// with it or be clobbered by it.
	tmpPath, err := journal.WriteSigningKeyTemp(dataDir, priv)
	if err != nil {
		return nil, nil, false, wrapGenesisDiskFailure(err)
	}

	putErr := c.PutIfAbsent(ctx, key, bytes.NewReader(data), int64(len(data)))
	switch {
	case putErr == nil:
		// The commit point: a crash or failure here leaves a genesis
		// record in the bucket whose signing key never reached disk under
		// its final name. tmpPath is deliberately not removed if this
		// fails — it may hold the only surviving copy of the private key
		// — and the refusal says so and names it, rather than sending the
		// operator to check bucket credentials for a local rename failure.
		if err := journal.CommitSigningKey(dataDir, tmpPath); err != nil {
			return nil, nil, false, journal.RefuseSigningKeyCommitFailed(dataDir, tmpPath, err)
		}
		chain := journal.NewSigningChain()
		if err := chain.ApplyGenesis(rec); err != nil {
			// Unreachable in practice: rec was just built by
			// NewGenesisRecord and MarshalGenesis's round trip is exact.
			// journal.RefuseCorruptGenesis is the defensive fallback.
			return nil, nil, false, journal.RefuseCorruptGenesis(err)
		}
		return chain, priv, true, nil
	case errors.Is(putErr, ErrPrecondition):
		journal.RemoveSigningKeyTemp(tmpPath)
		return nil, nil, false, journal.RefuseStreamFenced(journal.MetaStreamID, 0)
	case errors.Is(putErr, ErrOutcomeUnknown):
		// tmpPath is deliberately retained rather than removed here, same
		// reasoning as the commit-failure branch above: an outcome-unknown
		// PUT may have landed, in which case this instance's temp file is
		// the only surviving copy of the now-permanent record's private
		// key, and CommitSigningKey's own reasoning for keeping a temp
		// file it cannot prove is orphaned applies exactly as much to a
		// write whose outcome is merely unproven as to one that visibly
		// succeeded. journal.RefuseAppendOutcomeUnknown's text is fixed
		// (spec section 11.5 item 8, owned by fencing.go) and does not
		// name tmpPath; an operator who reaches this refusal and later
		// confirms the write landed can still recover the key by hand from
		// dataDir's signing.key.tmp.* file.
		return nil, nil, false, journal.RefuseAppendOutcomeUnknown(journal.MetaStreamID, 0)
	default:
		journal.RemoveSigningKeyTemp(tmpPath)
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
//
// It is only for failures that actually touched object storage (the
// initial Get, a mid-stream read of its body, or PutIfAbsent's non-fencing
// failures): probeFailureFix's default lands on "check bucket, region and
// credentials", which is right for those and wrong for anything local.
// wrapGenesisDiskFailure and wrapGenesisKeygenFailure are the local-failure
// equivalents, kept separate so a full disk or an unwritable data directory
// is never misreported as a storage-credentials problem.
func wrapGenesisFailure(cause error) error {
	return refusal.RefuseWithCause("invalid journal", "genesis: "+probeFailureWhy(cause), probeFailureFix(cause), cause)
}

// wrapGenesisDiskFailure wraps a local filesystem failure — the pre-mint
// signing.key stat, or WriteSigningKeyTemp — as a single "invalid journal"
// refusal whose fix clause talks about the data directory, not the bucket.
// Neither of these touches object storage, so wrapGenesisFailure's
// bucket/region/credentials clause would send the operator to check their
// S3 credentials for a full disk or an unwritable data directory. Mirrors
// internal/auth/filestore.go's clauses for the same class of failure
// ("verify the data directory is writable").
func wrapGenesisDiskFailure(cause error) error {
	return refusal.RefuseWithCause("invalid journal", "genesis: "+cause.Error(), "verify the data directory is writable and its filesystem is healthy", cause)
}

// wrapGenesisKeygenFailure wraps a GenerateKeypair or MarshalGenesis
// failure — both operate on nothing but this process's own memory and
// crypto/rand, so a failure here is not a data-directory problem
// (wrapGenesisDiskFailure) or a storage problem (wrapGenesisFailure), and
// "check bucket, region and credentials" fits neither. Mirrors
// internal/auth/filestore.go's clause for its own encode-failure case
// ("this indicates an internal bug; please report it").
func wrapGenesisKeygenFailure(cause error) error {
	return refusal.RefuseWithCause("invalid journal", "genesis: "+cause.Error(), "this indicates an internal bug; please report it", cause)
}
