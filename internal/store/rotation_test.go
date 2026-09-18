// Tests for (*Client).RotateKey (WALD-31), driven against storetest.Fake
// the same way genesis_test.go's EnsureGenesis tests are: a pass here means
// the rotate orchestration is right against something that actually
// enforces spec/journal/v1's compare-and-swap contract, not a mock that
// only knows what a test author remembered to assert.
package store_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/store/storetest"
)

// fixedRotateNow is the deterministic clock every RotateKey test uses, so a
// minted rotation record's timestamp never depends on wall-clock time.
func fixedRotateNow() time.Time {
	return time.Date(2026, 9, 18, 9, 0, 0, 0, time.UTC)
}

// (a) mint, RotateKey twice, then a fresh ReplayMeta shows three keys and
// the second rotation's key active — "how to know it worked" item 2.
func TestRotateKeyTwiceThenReplay(t *testing.T) {
	c, _ := newFakeClient(t)
	dataDir := t.TempDir()

	seedChain, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
	if err != nil {
		t.Fatalf("EnsureGenesis failed: %v", err)
	}
	genesisKey := seedChain.ActiveKey()

	leases := journal.NewLeases(c)

	retired1, active1, err := c.RotateKey(context.Background(), dataDir, leases, fixedRotateNow)
	if err != nil {
		t.Fatalf("first RotateKey failed: %v", err)
	}
	if retired1 != genesisKey {
		t.Errorf("first rotation retired = %q, want genesis key %q", retired1, genesisKey)
	}
	if active1 == genesisKey {
		t.Errorf("first rotation active key unchanged from genesis key %q", genesisKey)
	}

	retired2, active2, err := c.RotateKey(context.Background(), dataDir, leases, fixedRotateNow)
	if err != nil {
		t.Fatalf("second RotateKey failed: %v", err)
	}
	if retired2 != active1 {
		t.Errorf("second rotation retired = %q, want first rotation's active key %q", retired2, active1)
	}

	chain, err := c.ReplayMeta(context.Background())
	if err != nil {
		t.Fatalf("ReplayMeta failed: %v", err)
	}
	if chain.CurrentEpoch() != 2 {
		t.Errorf("CurrentEpoch() = %d, want 2", chain.CurrentEpoch())
	}
	if chain.ActiveKey() != active2 {
		t.Errorf("ActiveKey() = %q, want %q", chain.ActiveKey(), active2)
	}
	if key, err := chain.KeyAtEpoch(0); err != nil || key != genesisKey {
		t.Errorf("KeyAtEpoch(0) = %q, %v, want %q, nil", key, err, genesisKey)
	}
	if key, err := chain.KeyAtEpoch(1); err != nil || key != active1 {
		t.Errorf("KeyAtEpoch(1) = %q, %v, want %q, nil", key, err, active1)
	}

	loaded, err := journal.LoadSigningKey(dataDir)
	if err != nil {
		t.Fatalf("LoadSigningKey failed: %v", err)
	}
	if journal.FormatPublicKey(loaded.Public().(ed25519.PublicKey)) != active2 {
		t.Errorf("signing.key on disk does not match the second rotation's active key")
	}
	if matches := signingKeyTempFiles(t, dataDir); len(matches) != 0 {
		t.Errorf("temp key file(s) left behind after two successful rotations: %v", matches)
	}
}

// (b) Regression for the WALD-31 defect: mint, rotate, then EnsureGenesis
// again adopts a two-key chain instead of refusing with a signing-key
// mismatch. Run against the pre-fix comparison (genesis record's
// public_key alone), this test fails — which is the point ("how to know it
// worked" item 3).
func TestEnsureGenesisAfterRotationAdopts(t *testing.T) {
	c, _ := newFakeClient(t)
	dataDir := t.TempDir()

	if _, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow); err != nil {
		t.Fatalf("first EnsureGenesis (mint) failed: %v", err)
	}

	leases := journal.NewLeases(c)
	_, active, err := c.RotateKey(context.Background(), dataDir, leases, fixedRotateNow)
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	chain, priv, minted, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
	if err != nil {
		t.Fatalf("EnsureGenesis after a rotation refused (the WALD-31 defect): %v", err)
	}
	if minted {
		t.Error("EnsureGenesis after a rotation minted, want adopt")
	}
	if chain.CurrentEpoch() != 1 {
		t.Errorf("CurrentEpoch() = %d, want 1", chain.CurrentEpoch())
	}
	if chain.ActiveKey() != active {
		t.Errorf("ActiveKey() = %q, want %q", chain.ActiveKey(), active)
	}
	if journal.FormatPublicKey(priv.Public().(ed25519.PublicKey)) != active {
		t.Error("EnsureGenesis returned a private key that does not match the active key")
	}
}

// (c) A local signing.key that is not the chain's active key refuses in one
// line and touches no storage state.
func TestRotateKeyRefusesWhenLocalKeyNotActive(t *testing.T) {
	c, fake := newFakeClient(t)
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
	callsBefore := len(fake.Calls())
	leases := journal.NewLeases(c)
	_, _, err = c.RotateKey(context.Background(), dataDir, leases, fixedRotateNow)
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	if !errors.Is(err, journal.ErrSigningKeyUnavailable) {
		t.Errorf("expected errors.Is(_, ErrSigningKeyUnavailable), got %v", err)
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
	// RotateKey's specified order (ReplayMeta, then LoadSigningKey, then
	// this check) means ReplayMeta's own reads always happen first, but a
	// local key that is not the active key must never reach a write: no
	// PutIfAbsent (the rotation append) and no temp key file.
	for _, call := range fake.Calls()[callsBefore:] {
		if call.Op == storetest.OpPutIfAbsent || call.Op == storetest.OpPut {
			t.Errorf("RotateKey issued a write before confirming the local key is active: %+v", call)
		}
	}
	if matches := signingKeyTempFiles(t, dataDir); len(matches) != 0 {
		t.Errorf("temp key file(s) left behind: %v", matches)
	}
}

// (d) No genesis record at all: RotateKey refuses in one line rather than
// trying to mint one itself.
func TestRotateKeyRefusesWithNoGenesis(t *testing.T) {
	c, _ := newFakeClient(t)
	dataDir := t.TempDir()
	leases := journal.NewLeases(c)

	_, _, err := c.RotateKey(context.Background(), dataDir, leases, fixedRotateNow)
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
}

// (e) A missing local signing.key file refuses through RefuseNoSigningKey.
func TestRotateKeyRefusesWithNoLocalKey(t *testing.T) {
	c, _ := newFakeClient(t)
	dataDir := t.TempDir()
	if _, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow); err != nil {
		t.Fatalf("EnsureGenesis failed: %v", err)
	}
	if err := os.Remove(journal.SigningKeyPath(dataDir)); err != nil {
		t.Fatalf("failed to remove signing key: %v", err)
	}

	leases := journal.NewLeases(c)
	_, _, err := c.RotateKey(context.Background(), dataDir, leases, fixedRotateNow)
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	if !errors.Is(err, journal.ErrSigningKeyUnavailable) {
		t.Errorf("expected errors.Is(_, ErrSigningKeyUnavailable), got %v", err)
	}
}

// (f) A proven 412 on the rotation PUT fences _meta, refuses in one line,
// leaves signing.key holding the old key, and removes the temp file —
// "how to know it worked" item 5's first half.
func TestRotateKeyPreconditionFencesAndKeepsOldKey(t *testing.T) {
	c, fake := newFakeClient(t)
	dataDir := t.TempDir()
	seedChain, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
	if err != nil {
		t.Fatalf("EnsureGenesis failed: %v", err)
	}
	genesisKey := seedChain.ActiveKey()

	fake.Inject(storetest.Rule{
		Op: storetest.OpPutIfAbsent, Key: fullKey(journal.TxKey(journal.MetaStreamID, 1)), Call: 1,
		Fault: storetest.Fault{Status: http.StatusPreconditionFailed, Code: "PreconditionFailed"},
	})

	leases := journal.NewLeases(c)
	_, _, err = c.RotateKey(context.Background(), dataDir, leases, fixedRotateNow)
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	if !errors.Is(err, journal.ErrFenced) {
		t.Errorf("expected errors.Is(_, journal.ErrFenced), got %v", err)
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}

	loaded, err := journal.LoadSigningKey(dataDir)
	if err != nil {
		t.Fatalf("LoadSigningKey failed: %v", err)
	}
	if journal.FormatPublicKey(loaded.Public().(ed25519.PublicKey)) != genesisKey {
		t.Error("signing.key changed after a fenced rotation attempt")
	}
	if matches := signingKeyTempFiles(t, dataDir); len(matches) != 0 {
		t.Errorf("temp key file(s) left behind after a fenced rotation: %v", matches)
	}

	// The stream is now permanently fenced on this Leases/Fencer.
	// RotateKey's specified order runs ReplayMeta (read-only) ahead of
	// leases.Open, so a second attempt still issues those reads, but it
	// must never re-attempt the append itself: no further PutIfAbsent, and
	// (*journal.Leases).Open's own "zero network calls once fenced"
	// contract (lease.go) still holds for the Lease/Open call that follows
	// ReplayMeta.
	putCallsBefore := 0
	for _, call := range fake.Calls() {
		if call.Op == storetest.OpPutIfAbsent {
			putCallsBefore++
		}
	}
	if _, _, err := c.RotateKey(context.Background(), dataDir, leases, fixedRotateNow); err == nil {
		t.Fatal("expected the second attempt on a fenced lease to refuse, got nil")
	}
	putCallsAfter := 0
	for _, call := range fake.Calls() {
		if call.Op == storetest.OpPutIfAbsent {
			putCallsAfter++
		}
	}
	if putCallsAfter != putCallsBefore {
		t.Errorf("a rotation attempt on an already-fenced stream issued %d more PutIfAbsent call(s), want 0", putCallsAfter-putCallsBefore)
	}
}

// (g) An unprovable outcome on the rotation PUT fences _meta, refuses in
// one line, and deliberately keeps the temp key file — it may be the only
// surviving copy of a now-live key — "how to know it worked" item 5's
// second half.
func TestRotateKeyOutcomeUnknownKeepsTempFile(t *testing.T) {
	c, fake := newFakeClient(t)
	dataDir := t.TempDir()
	if _, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow); err != nil {
		t.Fatalf("EnsureGenesis failed: %v", err)
	}

	fake.Inject(storetest.Rule{
		Op: storetest.OpPutIfAbsent, Key: fullKey(journal.TxKey(journal.MetaStreamID, 1)), Call: 1,
		Fault: storetest.Fault{Land: true, Drop: true},
	})

	leases := journal.NewLeases(c)
	_, _, err := c.RotateKey(context.Background(), dataDir, leases, fixedRotateNow)
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	if !errors.Is(err, journal.ErrFenced) {
		t.Errorf("expected errors.Is(_, journal.ErrFenced), got %v", err)
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}

	matches := signingKeyTempFiles(t, dataDir)
	if len(matches) != 1 {
		t.Fatalf("expected exactly one leftover temp key file, got %v", matches)
	}
}
