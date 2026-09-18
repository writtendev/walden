// Tests for (*Client).ReplayMeta (WALD-31, spec/journal/v1 section 8 steps
// 1-2), driven against storetest.Fake the same way genesis_test.go and
// storetest_client_test.go are: a pass here means the replay walks
// genesis, rotations, and token mutations correctly against something that
// actually enforces spec/journal/v1's compare-and-swap contract, not a
// mock that only knows what a test author remembered to assert.
package store_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/store"
)

// (a) An empty journal: ReplayMeta returns ErrObjectNotFound, unwrapped, so
// EnsureGenesis's mint path can tell an empty journal from a corrupt one.
func TestReplayMetaEmptyJournalReturnsObjectNotFound(t *testing.T) {
	c, _ := newFakeClient(t)

	_, err := c.ReplayMeta(context.Background())
	if !errors.Is(err, store.ErrObjectNotFound) {
		t.Fatalf("errors.Is(_, ErrObjectNotFound) = false, err = %v", err)
	}
}

// (b) Genesis alone: the chain holds exactly the genesis key, at epoch 0,
// with LastMetaSeq 0.
func TestReplayMetaGenesisOnly(t *testing.T) {
	c, _ := newFakeClient(t)
	dataDir := t.TempDir()

	seedChain, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
	if err != nil {
		t.Fatalf("EnsureGenesis failed: %v", err)
	}

	chain, err := c.ReplayMeta(context.Background())
	if err != nil {
		t.Fatalf("ReplayMeta failed: %v", err)
	}
	if chain.ActiveKey() != seedChain.ActiveKey() {
		t.Errorf("ActiveKey() = %q, want %q", chain.ActiveKey(), seedChain.ActiveKey())
	}
	if chain.CurrentEpoch() != 0 {
		t.Errorf("CurrentEpoch() = %d, want 0", chain.CurrentEpoch())
	}
	if chain.LastMetaSeq() != 0 {
		t.Errorf("LastMetaSeq() = %d, want 0", chain.LastMetaSeq())
	}
}

// putRotation signs and writes a key_rotation record directly at _meta seq,
// bypassing RotateKey — meta_test.go exercises ReplayMeta in isolation, so
// rotation_test.go and store/rotation_test.go are the ones that exercise
// RotateKey itself.
func putRotation(t *testing.T, c *store.Client, seq journal.Seq, oldPriv ed25519.PrivateKey, newPub ed25519.PublicKey, timestamp string) {
	t.Helper()
	rec := journal.NewKeyRotationRecord(seq, oldPriv.Public().(ed25519.PublicKey), newPub, timestamp)
	if err := journal.SignRotation(oldPriv, rec); err != nil {
		t.Fatalf("SignRotation failed: %v", err)
	}
	data, err := journal.MarshalKeyRotation(rec)
	if err != nil {
		t.Fatalf("MarshalKeyRotation failed: %v", err)
	}
	if err := c.PutIfAbsent(context.Background(), journal.TxKey(journal.MetaStreamID, seq), bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("PutIfAbsent rotation at seq %d failed: %v", seq, err)
	}
}

// (c) Genesis plus one rotation: the chain's active key is the rotated key,
// epoch 1, LastMetaSeq 1.
func TestReplayMetaWalksRotation(t *testing.T) {
	c, _ := newFakeClient(t)
	dataDir := t.TempDir()

	_, genesisPriv, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
	if err != nil {
		t.Fatalf("EnsureGenesis failed: %v", err)
	}
	_, newPub, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	putRotation(t, c, 1, genesisPriv, newPub, "2026-09-17T12:00:00Z")

	chain, err := c.ReplayMeta(context.Background())
	if err != nil {
		t.Fatalf("ReplayMeta failed: %v", err)
	}
	wantActive := journal.FormatPublicKey(newPub)
	if chain.ActiveKey() != wantActive {
		t.Errorf("ActiveKey() = %q, want %q", chain.ActiveKey(), wantActive)
	}
	if chain.CurrentEpoch() != 1 {
		t.Errorf("CurrentEpoch() = %d, want 1", chain.CurrentEpoch())
	}
	if chain.LastMetaSeq() != 1 {
		t.Errorf("LastMetaSeq() = %d, want 1", chain.LastMetaSeq())
	}
}

// (d) Two rotations in a row: the chain ends up three keys deep, active key
// is the second rotation's new key, epoch 2.
func TestReplayMetaWalksTwoRotations(t *testing.T) {
	c, _ := newFakeClient(t)
	dataDir := t.TempDir()

	_, genesisPriv, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
	if err != nil {
		t.Fatalf("EnsureGenesis failed: %v", err)
	}
	priv2, pub2, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	putRotation(t, c, 1, genesisPriv, pub2, "2026-09-17T12:00:00Z")

	_, pub3, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	putRotation(t, c, 2, priv2, pub3, "2026-09-17T13:00:00Z")

	chain, err := c.ReplayMeta(context.Background())
	if err != nil {
		t.Fatalf("ReplayMeta failed: %v", err)
	}
	wantActive := journal.FormatPublicKey(pub3)
	if chain.ActiveKey() != wantActive {
		t.Errorf("ActiveKey() = %q, want %q", chain.ActiveKey(), wantActive)
	}
	if chain.CurrentEpoch() != 2 {
		t.Errorf("CurrentEpoch() = %d, want 2", chain.CurrentEpoch())
	}
	if chain.LastMetaSeq() != 2 {
		t.Errorf("LastMetaSeq() = %d, want 2", chain.LastMetaSeq())
	}
}

// (e) An unrecognized meta record type at seq 1 is tolerated: spec section
// 5.4's forward-compatibility rule. ReplayMeta advances past it without
// trying to interpret its fields, and a genuine rotation at seq 2 still
// verifies against the unchanged genesis key.
func TestReplayMetaToleratesUnknownRecordType(t *testing.T) {
	c, fake := newFakeClient(t)
	dataDir := t.TempDir()

	_, genesisPriv, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
	if err != nil {
		t.Fatalf("EnsureGenesis failed: %v", err)
	}

	unknown := []byte(`{"version":"v1","stream":"_meta","seq":"1","type":"future_record_type","anything":"goes"}`)
	fake.SetObject(fullKey(journal.TxKey(journal.MetaStreamID, 1)), unknown)

	_, pub2, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	putRotation(t, c, 2, genesisPriv, pub2, "2026-09-17T13:00:00Z")

	chain, err := c.ReplayMeta(context.Background())
	if err != nil {
		t.Fatalf("ReplayMeta failed on an unknown meta record type: %v", err)
	}
	if chain.LastMetaSeq() != 2 {
		t.Errorf("LastMetaSeq() = %d, want 2", chain.LastMetaSeq())
	}
	wantActive := journal.FormatPublicKey(pub2)
	if chain.ActiveKey() != wantActive {
		t.Errorf("ActiveKey() = %q, want %q", chain.ActiveKey(), wantActive)
	}
}

// (f) A corrupt genesis record refuses through RefuseCorruptGenesis, the
// same refusal EnsureGenesis's own adopt path already used before this
// ticket moved genesis parsing into ReplayMeta.
func TestReplayMetaCorruptGenesisRefuses(t *testing.T) {
	c, fake := newFakeClient(t)
	fake.SetObject(fullKey(journal.TxKey(journal.MetaStreamID, 0)), []byte("not json"))

	_, err := c.ReplayMeta(context.Background())
	if !errors.Is(err, journal.ErrInvalidGenesis) {
		t.Fatalf("errors.Is(_, ErrInvalidGenesis) = false, err = %v", err)
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
}

// (g) A key_rotation record that fails to parse (missing signature)
// refuses through RefuseCorruptRotation, naming the object key.
func TestReplayMetaCorruptRotationRefuses(t *testing.T) {
	c, fake := newFakeClient(t)
	dataDir := t.TempDir()
	if _, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow); err != nil {
		t.Fatalf("EnsureGenesis failed: %v", err)
	}

	malformed := []byte(`{"version":"v1","stream":"_meta","seq":"1","type":"key_rotation","old_public_key":"ed25519:00"}`)
	fake.SetObject(fullKey(journal.TxKey(journal.MetaStreamID, 1)), malformed)

	_, err := c.ReplayMeta(context.Background())
	if !errors.Is(err, journal.ErrInvalidRotation) {
		t.Fatalf("errors.Is(_, ErrInvalidRotation) = false, err = %v", err)
	}
	if !strings.Contains(err.Error(), journal.TxKey(journal.MetaStreamID, 1)) {
		t.Errorf("refusal does not name the object key: %q", err.Error())
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
}

// (h) A rotation whose old_public_key does not match the chain's active
// key does not chain to genesis: ApplyRotation's own ErrUnchainableRotation
// surfaces unchanged.
func TestReplayMetaUnchainableRotationRefuses(t *testing.T) {
	c, _ := newFakeClient(t)
	dataDir := t.TempDir()
	if _, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow); err != nil {
		t.Fatalf("EnsureGenesis failed: %v", err)
	}

	wrongPriv, _, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	_, newPub, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	// Signed by a key that never chained to genesis at all.
	putRotation(t, c, 1, wrongPriv, newPub, "2026-09-17T12:00:00Z")

	_, err = c.ReplayMeta(context.Background())
	if !errors.Is(err, journal.ErrUnchainableRotation) {
		t.Fatalf("errors.Is(_, ErrUnchainableRotation) = false, err = %v", err)
	}
}

// (i) A meta record over maxGenesisBody at seq 1 refuses in one line,
// mirroring TestEnsureGenesisOversizedBodyRefused for genesis itself.
func TestReplayMetaOversizedRecordRefused(t *testing.T) {
	c, fake := newFakeClient(t)
	dataDir := t.TempDir()
	if _, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow); err != nil {
		t.Fatalf("EnsureGenesis failed: %v", err)
	}

	oversized := bytes.Repeat([]byte("x"), 64<<10+1)
	fake.SetObject(fullKey(journal.TxKey(journal.MetaStreamID, 1)), oversized)

	_, err := c.ReplayMeta(context.Background())
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
}
