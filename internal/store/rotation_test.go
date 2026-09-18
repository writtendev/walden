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

// buildRefTxRecord builds a minimal, valid RefTransactionRecord for
// TestRotateKeyProducedChainVerifiesRefTx: one ref update on a repository
// stream (never _meta — Validate refuses that), unsigned. The caller signs
// it with journal.SignRefTx before handing it to (*journal.SigningChain).VerifyRefTx.
func buildRefTxRecord(stream journal.StreamID, seq journal.Seq, epoch journal.Epoch) *journal.RefTransactionRecord {
	return &journal.RefTransactionRecord{
		Version:  journal.VersionPrefix,
		Stream:   stream,
		Seq:      seq,
		Type:     journal.RecordTypeRefUpdate,
		KeyEpoch: epoch,
		Segments: []string{},
		Updates: []journal.RefUpdate{{
			Ref:    "refs/heads/main",
			OldOID: journal.ZeroOID40,
			NewOID: strings.Repeat("a", 40),
		}},
		Timestamp: "2026-09-18T09:00:00Z",
	}
}

// TestRotateKeyProducedChainVerifiesRefTx covers the plan's "how to know it
// worked" item 4, which round 1 found untested: nothing in this package
// called (*journal.SigningChain).VerifyRefTx at all, so no record was ever
// signed against the chain and epoch RotateKey itself produces — every
// existing VerifyRefTx test (internal/journal/reftx_test.go, marker_test.go,
// fixtures_test.go) drives the chain from a struct literal or a fixture
// instead. This exercises the same rule against a rotation this code
// actually performed: a ref transaction signed with the new key and
// stamped at the new epoch verifies; one signed by the retired key but
// still claiming the new epoch fails (the epoch names a key it did not
// sign with); and one stamped at the retired epoch, on a stream the chain
// has already verified at the new epoch, fails with ErrKeyEpochRegression
// rather than letting a retired key go on validating records inserted
// after a newer one.
//
// This uses journal.SignRefTx, journal.RefTransactionRecord, and
// (*journal.SigningChain).VerifyRefTx exactly as they exist today —
// internal/journal/reftx.go belongs to WALD-27 (PR #60, in review
// concurrently) and is not touched here, and this does not call
// journal.AppendRefTx (also WALD-27's) at all: the record is built and
// signed directly against RotateKey's own chain and dataDir signing key.
func TestRotateKeyProducedChainVerifiesRefTx(t *testing.T) {
	c, _ := newFakeClient(t)
	dataDir := t.TempDir()

	_, genesisPriv, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
	if err != nil {
		t.Fatalf("EnsureGenesis failed: %v", err)
	}

	leases := journal.NewLeases(c)
	if _, _, err := c.RotateKey(context.Background(), dataDir, leases, fixedRotateNow); err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}
	newPriv, err := journal.LoadSigningKey(dataDir)
	if err != nil {
		t.Fatalf("LoadSigningKey failed: %v", err)
	}

	chain, err := c.ReplayMeta(context.Background())
	if err != nil {
		t.Fatalf("ReplayMeta failed: %v", err)
	}
	if chain.CurrentEpoch() != 1 {
		t.Fatalf("CurrentEpoch() = %d, want 1 after one rotation", chain.CurrentEpoch())
	}

	stream := journal.StreamID("repo1")

	// (1) Signed by the new key, stamped at the new epoch: verifies.
	newEpochRec := buildRefTxRecord(stream, 0, 1)
	if err := journal.SignRefTx(newPriv, newEpochRec); err != nil {
		t.Fatalf("SignRefTx (new key) failed: %v", err)
	}
	if err := chain.VerifyRefTx(newEpochRec); err != nil {
		t.Errorf("a record signed by the new key at the new epoch should verify, got %v", err)
	}

	// (2) Signed by the retired key but stamped at the new epoch: epoch 1's
	// key is the new key, not the one this record was actually signed
	// with, so verification fails on the signature itself — the floor
	// VerifyRefTx just raised to 1 for this stream does not reject epoch 1
	// outright, so this is a real signature check, not a shortcut on the
	// epoch.
	retiredKeyRec := buildRefTxRecord(stream, 1, 1)
	if err := journal.SignRefTx(genesisPriv, retiredKeyRec); err != nil {
		t.Fatalf("SignRefTx (retired key) failed: %v", err)
	}
	err = chain.VerifyRefTx(retiredKeyRec)
	if err == nil {
		t.Error("a record signed by the retired key at the new epoch should not verify")
	} else if !errors.Is(err, journal.ErrSignatureMismatch) {
		t.Errorf("expected errors.Is(_, ErrSignatureMismatch), got %v", err)
	}

	// (3) Stamped at the retired epoch (0), on a stream already verified at
	// epoch 1 by (1) above: ErrKeyEpochRegression, not a retired key
	// silently validating a record inserted after a newer one.
	regressedRec := buildRefTxRecord(stream, 2, 0)
	if err := journal.SignRefTx(genesisPriv, regressedRec); err != nil {
		t.Fatalf("SignRefTx (retired epoch) failed: %v", err)
	}
	if err := chain.VerifyRefTx(regressedRec); !errors.Is(err, journal.ErrKeyEpochRegression) {
		t.Errorf("expected errors.Is(_, ErrKeyEpochRegression), got %v", err)
	}
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

// (h) Round 1 major finding: RotateKey must refuse, not append, when the
// sequence (*journal.Lease).Append hands its callback does not follow the
// sequence this rotation's own ReplayMeta verified up to. The review's own
// repro races two concurrent rotate-key invocations against a shared
// journal so that one instance's Leases registry memoizes a stale head
// before the other's rotation lands; that exact interleaving is not
// reproducible deterministically through the public API without a hook
// into RotateKey itself (out of this ticket's scope), so this reaches the
// same divergence a different, deterministic way: the Leases registry is
// pre-warmed (memoizing head 0, next seq 1) before a concurrent, non-
// rotation _meta record is landed directly at seq 1 -- an unrecognized
// record type, tolerated by ReplayMeta's own §5.4 forward-compatibility
// case (meta_test.go's TestReplayMetaToleratesUnknownRecordType uses the
// same shape), so it advances chain.LastMetaSeq() to 1 without touching
// the active key. RotateKey's own fresh ReplayMeta call then sees
// LastMetaSeq()=1 while its Leases registry still offers the stale seq 1
// -- the same shape of divergence a race would produce, seq wanting one
// more than the lease is offering -- and must refuse rather than sign and
// land a rotation whose old_public_key no future replay could accept.
func TestRotateKeyRefusesOnStaleLeaseSequence(t *testing.T) {
	c, fake := newFakeClient(t)
	dataDir := t.TempDir()
	seedChain, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
	if err != nil {
		t.Fatalf("EnsureGenesis failed: %v", err)
	}
	genesisKey := seedChain.ActiveKey()

	leases := journal.NewLeases(c)
	// Pre-warm the lease: this memoizes _meta's head as 0 (only genesis
	// exists yet), so the Lease will offer seq 1 on the next Append no
	// matter what lands in the bucket afterward -- (*journal.Leases).Open's
	// own doc comment (lease.go) is explicit that head discovery happens
	// once and is cached for the life of the registry.
	if _, err := leases.Open(context.Background(), journal.MetaStreamID); err != nil {
		t.Fatalf("leases.Open (pre-warm) failed: %v", err)
	}

	// A concurrent writer's _meta record lands at seq 1 after the lease was
	// pre-warmed above -- an unrecognized type, so ReplayMeta advances past
	// it (§5.4) without changing the active key, matching the review's
	// scenario where the divergence is in the sequence, not RotateKey's own
	// step-3 active-key check.
	unknown := []byte(`{"version":"v1","stream":"_meta","seq":"1","type":"concurrent_write","anything":"goes"}`)
	fake.SetObject(fullKey(journal.TxKey(journal.MetaStreamID, 1)), unknown)

	callsBefore := len(fake.Calls())
	_, _, err = c.RotateKey(context.Background(), dataDir, leases, fixedRotateNow)
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
	if errors.Is(err, journal.ErrFenced) {
		t.Error("a stale-lease refusal must not fence the stream: the lease's view is stale, not the stream (Lease.Append's own contract for a plain callback error)")
	}

	// No PutIfAbsent for the rotation record: the check runs before the
	// callback ever reaches storage.
	for _, call := range fake.Calls()[callsBefore:] {
		if call.Op == storetest.OpPutIfAbsent {
			t.Errorf("RotateKey issued a PutIfAbsent despite the stale-sequence check: %+v", call)
		}
	}

	// signing.key is untouched, and the temp file for the key this attempt
	// generated is removed -- nothing was ever sent to storage, so there is
	// no ambiguity about whether it might be live (Lease.Append's own
	// contract for any error besides a proven 412 or an unprovable
	// outcome).
	loaded, err := journal.LoadSigningKey(dataDir)
	if err != nil {
		t.Fatalf("LoadSigningKey failed: %v", err)
	}
	if journal.FormatPublicKey(loaded.Public().(ed25519.PublicKey)) != genesisKey {
		t.Error("signing.key changed after a stale-lease-sequence refusal")
	}
	if matches := signingKeyTempFiles(t, dataDir); len(matches) != 0 {
		t.Errorf("temp key file(s) left behind after a stale-lease-sequence refusal: %v", matches)
	}

	// A fresh RotateKey call against the same (now current) leases registry
	// still refuses: the lease is memoized to seq 1 for the life of this
	// registry (lease.go), so retrying with the same *journal.Leases is not
	// the recovery -- a fresh process (a fresh Leases registry) is, exactly
	// as the refusal's own fix clause says.
	_, _, err = c.RotateKey(context.Background(), dataDir, leases, fixedRotateNow)
	if err == nil {
		t.Fatal("expected the retry against the same stale Leases registry to refuse again, got nil")
	}
}
