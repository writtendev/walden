// This file implements (*Client).LoadSigner (WALD-30): deriving a
// journal.Signer from the journal itself, read-only. It also holds
// loadSigningKeyFor, the load-the-key-then-compare-against-the-chain's-
// active-key block (*Client).adoptGenesis (genesis.go) used to carry
// inline before this ticket — lifted out here so the boot path
// (EnsureGenesis) and the append path (LoadSigner) share one
// implementation of what "the identity from the genesis record" means,
// rather than two that could drift.
package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
)

// LoadSigner derives the signing identity the calling process uses for
// this invocation only: ReplayMeta(ctx) to learn the journal's currently
// active key and epoch (genesis alone always reads as epoch 0, which is
// wrong after any rotation), loadSigningKeyFor to load dataDir's local
// signing key and confirm it is that active key, then journal.NewSigner
// to bundle the two into an immutable Signer.
//
// LoadSigner is read-only: it never mints a genesis record and never
// writes anything, to storage or to dataDir. A pre-receive hook — the
// process this exists for — is not allowed to create a signing identity;
// if the journal carries no genesis record yet, it refuses one line
// rather than minting one on its own authority.
//
// The Signer LoadSigner returns must not outlive the process invocation
// that requested it: see Signer's own doc comment for why a Signer cached
// across a key rotation would keep stamping a retired epoch.
func (c *Client) LoadSigner(ctx context.Context, dataDir string) (*journal.Signer, error) {
	chain, err := c.ReplayMeta(ctx)
	if err != nil {
		if errors.Is(err, ErrObjectNotFound) {
			return nil, refuseNoJournalToSignAgainst()
		}
		return nil, err
	}

	priv, err := loadSigningKeyFor(dataDir, chain)
	if err != nil {
		return nil, err
	}

	return journal.NewSigner(chain, priv)
}

// loadSigningKeyFor loads dataDir's local signing key and confirms it is
// chain's currently active key. This is the block (*Client).adoptGenesis
// used to hold inline before WALD-30 lifted it out here: chain has
// already been replayed by the caller (EnsureGenesis or LoadSigner), so
// this only loads the local half and compares.
//
// Compared as decoded key bytes, not formatted strings: ParsePublicKey
// accepts uppercase hex (hex.DecodeString does), so a chain carrying
// non-lowercase-but-parseable hex must not read as a mismatch against a
// local key that is byte-for-byte correct. chain.ActiveKey() already
// passed ParsePublicKey once, inside ApplyGenesis/ApplyRotation during
// ReplayMeta, so the parse error here is unreachable in practice;
// RefuseCorruptGenesis is only the defensive fallback.
func loadSigningKeyFor(dataDir string, chain *journal.SigningChain) (ed25519.PrivateKey, error) {
	priv, err := journal.LoadSigningKey(dataDir)
	if err != nil {
		switch {
		case os.IsNotExist(err):
			return nil, journal.RefuseNoSigningKey(dataDir)
		case errors.Is(err, journal.ErrSigningKeyUnavailable):
			// A parse failure: LoadSigningKey wraps every malformed-content
			// error in ErrSigningKeyUnavailable, and only those.
			return nil, journal.RefuseInvalidSigningKeyFile(dataDir, err)
		default:
			// A read failure LoadSigningKey did not wrap at all — its own
			// doc comment says a non-missing, non-parse failure is the raw
			// os.ReadFile error (EACCES, a bad owner, and similar). Telling
			// the operator "malformed" here and pointing at a backup
			// restore misdiagnoses a permissions bug as corrupted content.
			return nil, journal.RefuseSigningKeyUnreadable(err)
		}
	}

	wantPub, err := journal.ParsePublicKey(chain.ActiveKey())
	if err != nil {
		return nil, journal.RefuseCorruptGenesis(err)
	}
	localPub := priv.Public().(ed25519.PublicKey)
	if !localPub.Equal(wantPub) {
		return nil, journal.RefuseSigningKeyMismatch(dataDir, chain.LastMetaSeq(), chain.CurrentEpoch() != 0, chain.ActiveKey(), journal.FormatPublicKey(localPub))
	}

	return priv, nil
}

// refuseNoJournalToSignAgainst returns a one-line refusal when LoadSigner
// finds no genesis record at all: ReplayMeta's ErrObjectNotFound means an
// empty _meta prefix, not a corrupt one, and there is no signing identity
// yet for this process to adopt. Styled on rotation.go's
// refuseNoGenesisToRotate for the same underlying condition, but not
// prefixed "rotate-key refused" — this is reached from the append path,
// not the rotate-key CLI.
func refuseNoJournalToSignAgainst() error {
	return refusal.Refuse(
		"no signing identity",
		fmt.Sprintf("no genesis record found at %s", journal.TxKey(journal.MetaStreamID, 0)),
		"boot walden against this journal first so a signing identity exists to load",
	)
}
