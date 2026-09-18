// Tests for Signer and NewSigner (WALD-30). deterministicKeypair is
// defined in identity_test.go, same package.
package journal_test

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/journal"
)

// signerFixedNow is the deterministic clock every genesis/rotation record
// built here uses, so nothing depends on wall-clock time.
const signerFixedTimestamp = "2026-09-18T09:00:00Z"

// singleKeyChain builds an initialized, single-key chain (epoch 0) whose
// active key is priv's public half, plus priv itself.
func singleKeyChain(t *testing.T) (*journal.SigningChain, ed25519.PrivateKey) {
	t.Helper()
	priv, pub := deterministicKeypair(0x01)
	rec := journal.NewGenesisRecord(pub, signerFixedTimestamp)
	chain := journal.NewSigningChain()
	if err := chain.ApplyGenesis(rec); err != nil {
		t.Fatalf("ApplyGenesis: %v", err)
	}
	return chain, priv
}

// twoKeyChain builds an initialized, two-key chain: genesis at epoch 0
// (priv0), rotated once to priv1 (epoch 1, the active key). Returns the
// chain and both private keys.
func twoKeyChain(t *testing.T) (chain *journal.SigningChain, priv0, priv1 ed25519.PrivateKey) {
	t.Helper()
	priv0, pub0 := deterministicKeypair(0x01)
	priv1, pub1 := deterministicKeypair(0x02)

	genesis := journal.NewGenesisRecord(pub0, signerFixedTimestamp)
	chain = journal.NewSigningChain()
	if err := chain.ApplyGenesis(genesis); err != nil {
		t.Fatalf("ApplyGenesis: %v", err)
	}

	rot := journal.NewKeyRotationRecord(1, chain.ActiveKey(), pub1, signerFixedTimestamp)
	if err := journal.SignRotation(priv0, rot); err != nil {
		t.Fatalf("SignRotation: %v", err)
	}
	if err := chain.ApplyRotation(rot); err != nil {
		t.Fatalf("ApplyRotation: %v", err)
	}
	return chain, priv0, priv1
}

func assertSignerOneLine(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if strings.Count(err.Error(), "\n") != 0 {
		t.Errorf("refusal is not one line: %q", err.Error())
	}
}

// (1) NewSigner succeeds on a matched chain/key: Epoch() and PublicKey()
// report the chain's own values.
func TestNewSignerSucceedsOnMatchedChainAndKey(t *testing.T) {
	chain, priv := singleKeyChain(t)

	s, err := journal.NewSigner(chain, priv)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if s.Epoch() != chain.CurrentEpoch() {
		t.Errorf("Epoch() = %d, want %d", s.Epoch(), chain.CurrentEpoch())
	}
	if s.Epoch() != 0 {
		t.Errorf("Epoch() = %d, want 0", s.Epoch())
	}
	if s.PublicKey() != chain.ActiveKey() {
		t.Errorf("PublicKey() = %q, want %q", s.PublicKey(), chain.ActiveKey())
	}
}

// (2) A two-key chain (built by applying a rotation) yields epoch 1 for a
// signer built from the new key.
func TestNewSignerAfterRotationYieldsEpochOne(t *testing.T) {
	chain, _, priv1 := twoKeyChain(t)

	s, err := journal.NewSigner(chain, priv1)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if s.Epoch() != 1 {
		t.Errorf("Epoch() = %d, want 1", s.Epoch())
	}
	if s.PublicKey() != chain.ActiveKey() {
		t.Errorf("PublicKey() = %q, want %q", s.PublicKey(), chain.ActiveKey())
	}
}

// (3) Refusals, each asserted single-line and matching the right sentinel.
func TestNewSignerRefusals(t *testing.T) {
	_, priv := singleKeyChain(t)

	t.Run("nil chain", func(t *testing.T) {
		_, err := journal.NewSigner(nil, priv)
		assertSignerOneLine(t, err)
		if !errors.Is(err, journal.ErrGenesisMissing) {
			t.Errorf("errors.Is(_, ErrGenesisMissing) = false, err = %v", err)
		}
	})

	t.Run("uninitialized chain", func(t *testing.T) {
		chain := journal.NewSigningChain()
		_, err := journal.NewSigner(chain, priv)
		assertSignerOneLine(t, err)
		if !errors.Is(err, journal.ErrGenesisMissing) {
			t.Errorf("errors.Is(_, ErrGenesisMissing) = false, err = %v", err)
		}
	})

	t.Run("wrong-size key", func(t *testing.T) {
		chain, _ := singleKeyChain(t)
		badPriv := priv[:len(priv)-1]
		_, err := journal.NewSigner(chain, badPriv)
		assertSignerOneLine(t, err)
		if !errors.Is(err, journal.ErrInvalidKey) {
			t.Errorf("errors.Is(_, ErrInvalidKey) = false, err = %v", err)
		}
	})

	t.Run("key not the active key", func(t *testing.T) {
		chain, _ := singleKeyChain(t)
		otherPriv, _ := deterministicKeypair(0x99)
		_, err := journal.NewSigner(chain, otherPriv)
		assertSignerOneLine(t, err)
		if !errors.Is(err, journal.ErrInvalidKey) {
			t.Errorf("errors.Is(_, ErrInvalidKey) = false, err = %v", err)
		}
	})

	t.Run("retired key after rotation", func(t *testing.T) {
		chain, priv0, _ := twoKeyChain(t)
		_, err := journal.NewSigner(chain, priv0)
		assertSignerOneLine(t, err)
		if !errors.Is(err, journal.ErrInvalidKey) {
			t.Errorf("errors.Is(_, ErrInvalidKey) = false, err = %v", err)
		}
	})
}

// (4) An uppercase-hex active key that is byte-equal to the local key must
// NOT refuse: NewSigner compares decoded key bytes, not formatted strings,
// the same way (*store.Client).adoptGenesis does and for the same reason.
func TestNewSignerAcceptsUppercaseHexActiveKeyThatIsByteEqual(t *testing.T) {
	priv, pub := deterministicKeypair(0x03)
	lower := journal.FormatPublicKey(pub)
	upper := "ed25519:" + strings.ToUpper(strings.TrimPrefix(lower, "ed25519:"))

	rec := &journal.GenesisRecord{
		Version:   journal.VersionPrefix,
		Stream:    journal.MetaStreamID,
		Seq:       0,
		Type:      journal.RecordTypeGenesis,
		PublicKey: upper,
		Timestamp: signerFixedTimestamp,
	}
	chain := journal.NewSigningChain()
	if err := chain.ApplyGenesis(rec); err != nil {
		t.Fatalf("ApplyGenesis: %v", err)
	}
	if chain.ActiveKey() != upper {
		t.Fatalf("chain.ActiveKey() = %q, want %q (uppercase, unmodified)", chain.ActiveKey(), upper)
	}

	s, err := journal.NewSigner(chain, priv)
	if err != nil {
		t.Fatalf("NewSigner refused a byte-equal key over an uppercase-hex active key: %v", err)
	}
	if s.Epoch() != 0 {
		t.Errorf("Epoch() = %d, want 0", s.Epoch())
	}
}

// (5) SignRefTx stamps KeyEpoch from the signer even when the record
// arrived carrying a different one, and the result verifies against the
// chain it was built from.
func TestSignerSignRefTxStampsItsOwnEpoch(t *testing.T) {
	chain, _, priv1 := twoKeyChain(t)
	s, err := journal.NewSigner(chain, priv1)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	rec := journal.NewRefTransactionRecord("repo-alpha", 0, 99, signerFixedTimestamp, nil, []journal.RefUpdate{
		{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: strings.Repeat("a", 40)},
	})
	if rec.KeyEpoch != 99 {
		t.Fatalf("test setup: rec.KeyEpoch = %d, want 99 before signing", rec.KeyEpoch)
	}

	if err := s.SignRefTx(rec); err != nil {
		t.Fatalf("SignRefTx: %v", err)
	}
	if rec.KeyEpoch != s.Epoch() {
		t.Errorf("rec.KeyEpoch = %d, want signer's own epoch %d", rec.KeyEpoch, s.Epoch())
	}
	if rec.KeyEpoch != 1 {
		t.Errorf("rec.KeyEpoch = %d, want 1", rec.KeyEpoch)
	}

	if err := chain.VerifyRefTx(rec); err != nil {
		t.Errorf("VerifyRefTx on a record signed by the signer: %v", err)
	}
}

// (6) SignRefTx on a nil record refuses (does not panic) with
// ErrInvalidRefTx.
func TestSignerSignRefTxNilRecord(t *testing.T) {
	chain, priv := singleKeyChain(t)
	s, err := journal.NewSigner(chain, priv)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	err = s.SignRefTx(nil)
	assertSignerOneLine(t, err)
	if !errors.Is(err, journal.ErrInvalidRefTx) {
		t.Errorf("errors.Is(_, ErrInvalidRefTx) = false, err = %v", err)
	}
}
