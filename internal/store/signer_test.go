// Tests for (*Client).LoadSigner (WALD-30), driven against
// storetest.Fake the same way genesis_test.go and rotation_test.go are.
// TestLoadSignerAppendVerifiesFromFreshGenesisReplay and its rotation
// follow-on are this ticket's actual "done when": a record a Signer this
// package derived signs is one a from-genesis replay verifies, and a
// single flipped signature byte makes that verification fail loudly
// rather than being skipped.
package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/store"
	"github.com/writtendev/walden/internal/store/storetest"
)

func assertSignerTestOneLine(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if strings.Count(err.Error(), "\n") != 0 {
		t.Errorf("refusal is not one line: %q", err.Error())
	}
}

// (1) After EnsureGenesis mints, LoadSigner returns epoch 0 with the
// public key the genesis record names.
func TestLoadSignerAfterMintReportsGenesisEpochAndKey(t *testing.T) {
	c, _ := newFakeClient(t)
	dataDir := t.TempDir()

	chain, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
	if err != nil {
		t.Fatalf("EnsureGenesis failed: %v", err)
	}

	signer, err := c.LoadSigner(context.Background(), dataDir)
	if err != nil {
		t.Fatalf("LoadSigner failed: %v", err)
	}
	if signer.Epoch() != 0 {
		t.Errorf("Epoch() = %d, want 0", signer.Epoch())
	}
	if signer.PublicKey() != chain.ActiveKey() {
		t.Errorf("PublicKey() = %q, want %q", signer.PublicKey(), chain.ActiveKey())
	}
}

// (2) After RotateKey, LoadSigner returns epoch 1 and the new key.
func TestLoadSignerAfterRotationReportsNewEpochAndKey(t *testing.T) {
	c, _ := newFakeClient(t)
	dataDir := t.TempDir()

	if _, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow); err != nil {
		t.Fatalf("EnsureGenesis failed: %v", err)
	}

	leases := journal.NewLeases(c)
	_, active, err := c.RotateKey(context.Background(), dataDir, leases, fixedRotateNow)
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	signer, err := c.LoadSigner(context.Background(), dataDir)
	if err != nil {
		t.Fatalf("LoadSigner failed: %v", err)
	}
	if signer.Epoch() != 1 {
		t.Errorf("Epoch() = %d, want 1", signer.Epoch())
	}
	if signer.PublicKey() != active {
		t.Errorf("PublicKey() = %q, want %q", signer.PublicKey(), active)
	}
}

// (3) Refusals: an empty journal prefix, a missing signing.key, a
// malformed one, and a stale one (a key from a discarded keypair) each
// refuse in one line, naming the constructors genesis.go's refusals
// already publish (or, for the empty-prefix case, this file's own).
func TestLoadSignerRefusals(t *testing.T) {
	t.Run("empty journal prefix", func(t *testing.T) {
		c, _ := newFakeClient(t)
		dataDir := t.TempDir()

		_, err := c.LoadSigner(context.Background(), dataDir)
		assertSignerTestOneLine(t, err)
		if errors.Is(err, store.ErrObjectNotFound) {
			t.Errorf("LoadSigner must not leak the raw ErrObjectNotFound to its caller: %v", err)
		}
		if !strings.Contains(err.Error(), journal.TxKey(journal.MetaStreamID, 0)) {
			t.Errorf("refusal does not name the missing genesis key: %q", err.Error())
		}
	})

	t.Run("missing signing.key", func(t *testing.T) {
		c, _ := newFakeClient(t)
		dataDir := t.TempDir()
		if _, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow); err != nil {
			t.Fatalf("EnsureGenesis failed: %v", err)
		}
		if err := os.Remove(journal.SigningKeyPath(dataDir)); err != nil {
			t.Fatalf("failed to remove signing key: %v", err)
		}

		_, err := c.LoadSigner(context.Background(), dataDir)
		assertSignerTestOneLine(t, err)
		if !errors.Is(err, journal.ErrSigningKeyUnavailable) {
			t.Errorf("errors.Is(_, ErrSigningKeyUnavailable) = false, err = %v", err)
		}
	})

	t.Run("malformed signing.key", func(t *testing.T) {
		c, _ := newFakeClient(t)
		dataDir := t.TempDir()
		if _, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow); err != nil {
			t.Fatalf("EnsureGenesis failed: %v", err)
		}
		if err := os.WriteFile(journal.SigningKeyPath(dataDir), []byte("not a key\n"), 0600); err != nil {
			t.Fatalf("failed to corrupt signing key: %v", err)
		}

		_, err := c.LoadSigner(context.Background(), dataDir)
		assertSignerTestOneLine(t, err)
		if !errors.Is(err, journal.ErrSigningKeyUnavailable) {
			t.Errorf("errors.Is(_, ErrSigningKeyUnavailable) = false, err = %v", err)
		}
	})

	t.Run("stale key from a discarded keypair", func(t *testing.T) {
		c, _ := newFakeClient(t)
		dataDir := t.TempDir()
		if _, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow); err != nil {
			t.Fatalf("EnsureGenesis failed: %v", err)
		}
		other, _, err := journal.GenerateKeypair()
		if err != nil {
			t.Fatalf("GenerateKeypair failed: %v", err)
		}
		if err := journal.SaveSigningKey(dataDir, other); err != nil {
			t.Fatalf("SaveSigningKey failed: %v", err)
		}

		_, err = c.LoadSigner(context.Background(), dataDir)
		assertSignerTestOneLine(t, err)
		if !errors.Is(err, journal.ErrSigningKeyUnavailable) {
			t.Errorf("errors.Is(_, ErrSigningKeyUnavailable) = false, err = %v", err)
		}
	})
}

// (4) LoadSigner writes nothing, at any point along a mint-then-rotate
// history: no OpPut or OpPutIfAbsent call appears in fake.Calls() from
// LoadSigner's own calls (isolated by comparing the call count before and
// after, since EnsureGenesis/RotateKey themselves legitimately write).
func TestLoadSignerWritesNothing(t *testing.T) {
	c, fake := newFakeClient(t)
	dataDir := t.TempDir()

	if _, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow); err != nil {
		t.Fatalf("EnsureGenesis failed: %v", err)
	}
	leases := journal.NewLeases(c)
	if _, _, err := c.RotateKey(context.Background(), dataDir, leases, fixedRotateNow); err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	before := len(fake.Calls())
	if _, err := c.LoadSigner(context.Background(), dataDir); err != nil {
		t.Fatalf("LoadSigner failed: %v", err)
	}
	for _, call := range fake.Calls()[before:] {
		if call.Op == storetest.OpPut || call.Op == storetest.OpPutIfAbsent {
			t.Errorf("LoadSigner issued a write: %+v", call)
		}
	}
}

// decodeRefTxRecord decodes a stored ref-transaction record with
// encoding/json rather than journal.ParseRefTx: WALD-34 (which owns
// ParseRefTx) has not landed in this worktree, and the plan for this
// ticket says explicitly not to wait on it.
func decodeRefTxRecord(t *testing.T, data []byte) *journal.RefTransactionRecord {
	t.Helper()
	var rec journal.RefTransactionRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	return &rec
}

// (5) The ticket's actual end-to-end proof: mint a journal, LoadSigner,
// AppendRefTx through a lease, Get the written object, decode it, then
// ReplayMeta a fresh chain and VerifyRefTx the record — it verifies, at
// the epoch the chain reports. Flipping one byte of the stored signature
// then makes verification fail with ErrSignatureMismatch in one line,
// which is what the caller gets — not a record silently skipped.
func TestLoadSignerAppendVerifiesFromFreshGenesisReplay(t *testing.T) {
	c, fake := newFakeClient(t)
	dataDir := t.TempDir()

	if _, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow); err != nil {
		t.Fatalf("EnsureGenesis failed: %v", err)
	}

	signer, err := c.LoadSigner(context.Background(), dataDir)
	if err != nil {
		t.Fatalf("LoadSigner failed: %v", err)
	}

	leases := journal.NewLeases(c)
	lease, err := leases.Open(context.Background(), "repo-alpha")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	seq, err := c.AppendRefTx(context.Background(), lease, signer, nil, reftxUpdates(), fixedReftxNow)
	if err != nil {
		t.Fatalf("AppendRefTx failed: %v", err)
	}

	key := fullKey(journal.TxKey("repo-alpha", seq))
	data, ok := fake.Object(key)
	if !ok {
		t.Fatalf("Object(%q) not found", key)
	}
	rec := decodeRefTxRecord(t, data)

	freshChain, err := c.ReplayMeta(context.Background())
	if err != nil {
		t.Fatalf("ReplayMeta failed: %v", err)
	}
	if err := freshChain.VerifyRefTx(rec); err != nil {
		t.Fatalf("VerifyRefTx on a record signed via LoadSigner+AppendRefTx: %v", err)
	}
	if rec.KeyEpoch != 0 {
		t.Errorf("rec.KeyEpoch = %d, want 0 (genesis epoch, no rotation yet)", rec.KeyEpoch)
	}

	// Flip one byte of the stored record's signature: verification must
	// fail loudly, not be silently skipped.
	tamperedSig := []rune(rec.Signature)
	flipHexDigit(t, tamperedSig)
	tampered := *rec
	tampered.Signature = string(tamperedSig)

	tamperedChain, err := c.ReplayMeta(context.Background())
	if err != nil {
		t.Fatalf("ReplayMeta (for the tampered check) failed: %v", err)
	}
	err = tamperedChain.VerifyRefTx(&tampered)
	if err == nil {
		t.Fatal("expected VerifyRefTx to fail on a tampered signature")
	}
	assertSignerTestOneLine(t, err)
	if !errors.Is(err, journal.ErrSignatureMismatch) {
		t.Errorf("errors.Is(_, ErrSignatureMismatch) = false, err = %v", err)
	}
}

// flipHexDigit mutates the last hex digit of sig in place to a different
// hex digit, so the caller ends up with a signature string that decodes
// to a different byte value at that position rather than an invalid one
// (which would fail at ParseSignature instead of at the cryptographic
// check this test means to exercise).
func flipHexDigit(t *testing.T, sig []rune) {
	t.Helper()
	if len(sig) == 0 {
		t.Fatal("signature is empty")
	}
	last := sig[len(sig)-1]
	replacement := byte('0')
	if last == '0' {
		replacement = '1'
	}
	sig[len(sig)-1] = rune(replacement)
}

// (6) Repeated across a rotation: rotate, load a fresh signer, append,
// and verify the new record at epoch 1 on a chain replayed from genesis.
func TestLoadSignerAppendAfterRotationVerifiesAtNewEpoch(t *testing.T) {
	c, fake := newFakeClient(t)
	dataDir := t.TempDir()

	if _, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow); err != nil {
		t.Fatalf("EnsureGenesis failed: %v", err)
	}
	leases := journal.NewLeases(c)
	if _, _, err := c.RotateKey(context.Background(), dataDir, leases, fixedRotateNow); err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	signer, err := c.LoadSigner(context.Background(), dataDir)
	if err != nil {
		t.Fatalf("LoadSigner failed: %v", err)
	}
	if signer.Epoch() != 1 {
		t.Fatalf("signer.Epoch() = %d, want 1", signer.Epoch())
	}

	lease, err := leases.Open(context.Background(), "repo-beta")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	seq, err := c.AppendRefTx(context.Background(), lease, signer, nil, reftxUpdates(), fixedReftxNow)
	if err != nil {
		t.Fatalf("AppendRefTx failed: %v", err)
	}

	key := fullKey(journal.TxKey("repo-beta", seq))
	data, ok := fake.Object(key)
	if !ok {
		t.Fatalf("Object(%q) not found", key)
	}
	rec := decodeRefTxRecord(t, data)
	if rec.KeyEpoch != 1 {
		t.Errorf("rec.KeyEpoch = %d, want 1", rec.KeyEpoch)
	}

	freshChain, err := c.ReplayMeta(context.Background())
	if err != nil {
		t.Fatalf("ReplayMeta failed: %v", err)
	}
	if err := freshChain.VerifyRefTx(rec); err != nil {
		t.Fatalf("VerifyRefTx on a record signed at the post-rotation epoch: %v", err)
	}
}
