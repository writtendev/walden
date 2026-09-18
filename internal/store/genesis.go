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
// 0 (replayed all the way to whatever key is currently active, rotations
// included), or minted fresh when the journal is empty. The bool result
// reports which happened (true for minted), for the boot line
// cmd/walden/main.go prints.
//
// Order of operations is the substance of this function:
//
//  1. Stat dataDir's signing.key, before ReplayMeta rather than after it.
//     This used to run inside the mint path, reached only once the genesis
//     Get had already returned not-found — which left a window, in the
//     shared-data-directory race two instances can run by sharing one
//     --data-dir, where a sibling's winning PutIfAbsent and rename could
//     land in between this instance's Get and its (later) stat: the stat
//     would then find the sibling's signing.key and refuse
//     RefuseSigningKeyPresentOnMint with "no genesis record found" even
//     though the sibling's record was by then committed (round 2 finding,
//     internal/store/genesis.go line 183). Stat-ing first closes that
//     window rather than merely narrowing it: a signing.key can only be on
//     disk once some PutIfAbsent has already won, and storage's read-after-
//     write consistency means the ReplayMeta immediately below is
//     guaranteed to see that same write, so "key present" and "record
//     absent" can no longer both be true here — a late-arriving sibling now
//     always reads as a found record (step 2, adopt) rather than this stale
//     refusal.
//  2. ReplayMeta: GET _meta seq 0 and every record past it, contiguously,
//     folding rotations and token mutations into a signing chain whose
//     ActiveKey() is the key actually in force right now — not merely the
//     genesis record's own public_key. This is what makes adoptGenesis's
//     comparison below correct across a rotation boundary (the load-bearing
//     defect this function used to carry: comparing against the genesis
//     record alone made every boot after a rotation refuse with a spurious
//     signing-key mismatch).
//  3. ReplayMeta succeeds -> adopt: require a local signing key whose
//     public half matches the chain's ActiveKey() (compared as decoded
//     bytes, not formatted hex, so case differences in a
//     spec-non-conformant but parseable record never look like a
//     mismatch). Absent or mismatched -> a one-line refusal, because an
//     instance that cannot sign cannot journal, and a push it could not
//     journal must not be acknowledged (spec section 2.2).
//  4. ReplayMeta's ErrObjectNotFound -> mint, refusing first if step 1
//     found dataDir already holding a signing.key (round 1 finding 2: that
//     file belongs to some other journal, and minting would rename
//     straight over it). Otherwise: GenerateKeypair, build the record,
//     MarshalGenesis, write the temp key file under a name unique to this
//     call (round 1 finding 1), PutIfAbsent the record, and only then
//     rename the temp file into place. The rename is the commit point: a
//     crash between a winning PUT and the rename leaves a genesis record in
//     the bucket whose signing key never reached disk under its final name
//     — though it is very likely still sitting, fsynced, at its temp name
//     (round 1 finding 3). That window is narrowed to one atomic rename,
//     not eliminated — there is no recovery mode here, deliberately.
//  5. ErrPrecondition on that PUT -> the loser of the race. Spec section
//     11.4 items 2-4: a 412 is definitive proof another writer got there
//     first, so this instance does not re-read the head, does not retry,
//     and does not adopt within the same boot. It removes its temp key file
//     and returns journal.RefuseStreamFenced(MetaStreamID, 0), which refuses
//     boot in one line. Restart is the recovery: a restart takes the adopt
//     path at step 3, where it correctly refuses if the operator pointed a
//     second instance at another instance's journal.
//  6. ErrOutcomeUnknown on that PUT -> journal.RefuseAppendOutcomeUnknown
//     (MetaStreamID, 0), no resend and no GET to find out (spec section
//     11.4 item 6). Unlike step 5, the temp key file is deliberately kept,
//     not removed (round 1 finding 7): the PUT may have landed, and if it
//     did, the temp file is the only surviving copy of a now-permanent
//     record's private key.
//  7. Any other ReplayMeta/PUT failure, or a local filesystem failure from
//     steps 1 or 4 that never touched storage at all -> ReplayMeta and
//     wrapGenesisDiskFailure/wrapGenesisKeygenFailure already return these
//     as single "invalid journal"-style refusals (ReplayMeta's own doc
//     comment), so this function has nothing left to wrap.
func (c *Client) EnsureGenesis(ctx context.Context, dataDir string, now func() time.Time) (*journal.SigningChain, ed25519.PrivateKey, bool, error) {
	key := journal.TxKey(journal.MetaStreamID, 0)

	// Step 1: see this function's doc comment for why this runs before
	// ReplayMeta rather than inside the mint path. statErr is only acted on
	// below, in the mint branch — the adopt branch (ReplayMeta succeeds)
	// never needed this stat and must not fail boot over it; LoadSigningKey
	// will surface the same filesystem problem there through its own
	// refusal if it matters.
	_, statErr := os.Stat(journal.SigningKeyPath(dataDir))
	keyPresent := statErr == nil

	chain, err := c.ReplayMeta(ctx)
	switch {
	case err == nil:
		return c.adoptGenesis(dataDir, chain)
	case errors.Is(err, ErrObjectNotFound):
		if keyPresent {
			return nil, nil, false, journal.RefuseSigningKeyPresentOnMint(dataDir)
		}
		if statErr != nil && !os.IsNotExist(statErr) {
			return nil, nil, false, wrapGenesisDiskFailure(statErr)
		}
		return c.mintGenesis(ctx, dataDir, key, now)
	default:
		// ReplayMeta's own doc comment: every failure past
		// ErrObjectNotFound is already a single-line refusal, so there is
		// nothing left here to wrap.
		return nil, nil, false, err
	}
}

// adoptGenesis handles EnsureGenesis's step 3: ReplayMeta has already
// walked _meta from genesis to its current head, so chain.ActiveKey() is
// the key actually in force right now, rotations included. The actual
// load-then-compare work is loadSigningKeyFor (signer.go), shared with
// (*Client).LoadSigner so the boot path and the append path cannot drift
// on what "the identity from the genesis record" means.
func (c *Client) adoptGenesis(dataDir string, chain *journal.SigningChain) (*journal.SigningChain, ed25519.PrivateKey, bool, error) {
	priv, err := loadSigningKeyFor(dataDir, chain)
	if err != nil {
		return nil, nil, false, err
	}
	return chain, priv, false, nil
}

// mintGenesis handles EnsureGenesis's steps 4-7: no genesis record exists
// yet, so this instance attempts to become the one that writes it. The
// pre-existing-signing.key guard (round 1 finding 2) is EnsureGenesis's
// step 1, ahead of the Get that routes here, not this function's own —
// see EnsureGenesis's doc comment for why that stat had to move.
func (c *Client) mintGenesis(ctx context.Context, dataDir, key string, now func() time.Time) (*journal.SigningChain, ed25519.PrivateKey, bool, error) {
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
		// CommitSigningKey's renamed result tells RefuseSigningKeyCommitFailed
		// which of its two internal steps failed (round 2 finding,
		// internal/journal/genesis.go line 452): the rename itself, which
		// leaves the key at tmpPath, or the directory fsync that follows a
		// successful rename, which leaves the key already at its final
		// path — a refusal that named tmpPath regardless would send the
		// operator to a file that no longer exists in the second case.
		if renamed, err := journal.CommitSigningKey(dataDir, tmpPath); err != nil {
			return nil, nil, false, journal.RefuseSigningKeyCommitFailed(dataDir, tmpPath, renamed, err)
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
