// Tests for (*Client).AppendTokenCreate, (*Client).AppendTokenRevoke, and
// (*Client).ReplayMetaTable (WALD-33), driven against storetest.Fake the
// same way reftx_test.go and rotation_test.go are: a pass here means the
// _meta token writer proves spec/journal/v1 section 11's conditional-
// append contract end to end, against something that actually enforces
// compare-and-swap, not a mock that only knows what a test author
// remembered to assert.
package store_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/store/storetest"
)

// fixedTokensNow is the deterministic clock every AppendTokenCreate/
// AppendTokenRevoke test uses, so a written record's timestamp never
// depends on wall-clock time.
func fixedTokensNow() time.Time {
	return time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
}

// assertTokensOneLine fails the test unless err is non-nil and its
// message has no embedded newline, per AGENTS.md's mechanical review rule
// that every operator-facing refusal is one line.
func assertTokensOneLine(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if strings.Count(err.Error(), "\n") != 0 {
		t.Errorf("refusal is not one line: %q", err.Error())
	}
}

// 1. Happy path: AppendTokenCreate writes a token_create record at the
// sequence the meta lease hands out (seq 1, right after genesis's own
// seq 0), the written bytes verify, and ReplayMetaTable rebuilds the
// expected row. The lease then advances: AppendTokenRevoke on the same
// lease writes seq 2 and the row comes back revoked.
func TestAppendTokenCreateThenRevokeRoundTrip(t *testing.T) {
	c, fake := newFakeClient(t)
	ctx := context.Background()
	dataDir := t.TempDir()

	chain, priv, _, err := c.EnsureGenesis(ctx, dataDir, fixedTokensNow)
	if err != nil {
		t.Fatalf("EnsureGenesis: %v", err)
	}

	leases := journal.NewLeases(c)
	lease, err := leases.Open(ctx, journal.MetaStreamID)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	scopes := []string{"rw:blog-*", "r:docs"}
	tokenHash := journal.TokenHashPrefix + strings.Repeat("a", 64)
	seq, err := c.AppendTokenCreate(ctx, lease, priv, chain, "tok_writer_02", tokenHash, scopes, fixedTokensNow)
	if err != nil {
		t.Fatalf("AppendTokenCreate: %v", err)
	}
	if seq != 1 {
		t.Fatalf("seq = %d, want 1", seq)
	}

	key := fullKey(journal.TxKey(journal.MetaStreamID, 1))
	data, ok := fake.Object(key)
	if !ok {
		t.Fatalf("Object(%q) not found", key)
	}
	var rec journal.TokenCreateRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("json.Unmarshal wrote bytes: %v", err)
	}
	if err := journal.VerifyTokenCreate(&rec, chain.ActiveKey()); err != nil {
		t.Fatalf("VerifyTokenCreate on the written record: %v", err)
	}

	replayedChain, table, err := c.ReplayMetaTable(ctx)
	if err != nil {
		t.Fatalf("ReplayMetaTable: %v", err)
	}
	if replayedChain.LastMetaSeq() != 1 {
		t.Errorf("LastMetaSeq() = %d, want 1", replayedChain.LastMetaSeq())
	}
	row, ok := table.Row("tok_writer_02")
	if !ok {
		t.Fatal("rebuilt table lost tok_writer_02")
	}
	if row.TokenHash != tokenHash {
		t.Errorf("TokenHash = %q, want %q", row.TokenHash, tokenHash)
	}
	if row.Revoked {
		t.Error("freshly created row came back revoked")
	}
	if got, want := strings.Join(row.Scopes, ","), strings.Join(scopes, ","); got != want {
		t.Errorf("Scopes = %q, want %q", got, want)
	}

	// chain is this test's own long-lived view of _meta, so it is advanced
	// by hand to match the record just written -- exactly as a caller
	// making two sequential appends on one lease without a full re-replay
	// between them would have to (AppendTokenCreate/AppendTokenRevoke
	// themselves never mutate the *journal.SigningChain a caller passes
	// in; only a fresh ReplayMeta/ReplayMetaTable, or this, keeps it
	// current).
	if err := chain.AdvanceMetaSeq(seq); err != nil {
		t.Fatalf("chain.AdvanceMetaSeq(%d): %v", seq, err)
	}

	// The lease advances: AppendTokenRevoke on the same lease writes seq 2.
	seq2, err := c.AppendTokenRevoke(ctx, lease, priv, chain, "tok_writer_02", tokenHash, fixedTokensNow)
	if err != nil {
		t.Fatalf("AppendTokenRevoke: %v", err)
	}
	if seq2 != 2 {
		t.Fatalf("seq = %d, want 2", seq2)
	}

	_, table2, err := c.ReplayMetaTable(ctx)
	if err != nil {
		t.Fatalf("ReplayMetaTable after revoke: %v", err)
	}
	row2, ok := table2.Row("tok_writer_02")
	if !ok {
		t.Fatal("rebuilt table lost tok_writer_02 after revoke")
	}
	if !row2.Revoked {
		t.Error("row is not revoked after AppendTokenRevoke")
	}
}

// 2. Fixture-independent end-to-end: mint genesis, create a token, rotate
// the signing key, then revoke the token signed by the rotated key --
// spec section 4.3's payload note behaviour (a token record carries no
// key_epoch and is verified against the key active at its own meta
// sequence) that the golden journal also exercises, proven here against
// a fresh journal this test controls end to end.
func TestAppendTokenRevokeAfterKeyRotationVerifiesAgainstRotatedKey(t *testing.T) {
	c, _ := newFakeClient(t)
	ctx := context.Background()
	dataDir := t.TempDir()

	chain, priv, _, err := c.EnsureGenesis(ctx, dataDir, fixedTokensNow)
	if err != nil {
		t.Fatalf("EnsureGenesis: %v", err)
	}
	leases := journal.NewLeases(c)
	lease, err := leases.Open(ctx, journal.MetaStreamID)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	tokenHash := journal.TokenHashPrefix + strings.Repeat("a", 64)
	if _, err := c.AppendTokenCreate(ctx, lease, priv, chain, "tok_admin_01", tokenHash, []string{"rwc:*"}, fixedTokensNow); err != nil {
		t.Fatalf("AppendTokenCreate: %v", err)
	}

	retired, active, err := c.RotateKey(ctx, dataDir, leases, fixedTokensNow)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if retired == active {
		t.Fatal("RotateKey did not change the active key")
	}

	// Re-replay to learn the post-rotation chain, and reload the rotated
	// private key RotateKey committed to disk.
	rotatedChain, _, err := c.ReplayMetaTable(ctx)
	if err != nil {
		t.Fatalf("ReplayMetaTable after rotation: %v", err)
	}
	if rotatedChain.ActiveKey() != active {
		t.Fatalf("ActiveKey() = %q, want %q", rotatedChain.ActiveKey(), active)
	}
	rotatedPriv, err := journal.LoadSigningKey(dataDir)
	if err != nil {
		t.Fatalf("LoadSigningKey after rotation: %v", err)
	}

	if _, err := c.AppendTokenRevoke(ctx, lease, rotatedPriv, rotatedChain, "tok_admin_01", tokenHash, fixedTokensNow); err != nil {
		t.Fatalf("AppendTokenRevoke signed by the rotated key: %v", err)
	}

	finalChain, table, err := c.ReplayMetaTable(ctx)
	if err != nil {
		t.Fatalf("ReplayMetaTable after revoke: %v", err)
	}
	if finalChain.ActiveKey() != active {
		t.Errorf("ActiveKey() after replay = %q, want %q", finalChain.ActiveKey(), active)
	}
	row, ok := table.Row("tok_admin_01")
	if !ok {
		t.Fatal("rebuilt table lost tok_admin_01")
	}
	if !row.Revoked {
		t.Error("tok_admin_01 is not revoked after the round trip")
	}
}

// 3. AppendTokenCreate does not itself check the rebuilt table for a
// reused token id -- that pre-check is the CLI's job
// (cmd/walden/token.go), against the table its own ReplayMetaTable call
// produced. Two AppendTokenCreate calls naming the same token_id both
// land (each is independently valid at the sequence it writes), and it
// is only the next replay that refuses under spec section 8.1 rule 10 --
// proving the layering the plan describes: the writer permits, replay
// refuses.
func TestAppendTokenCreateDoesNotItselfCheckReuse(t *testing.T) {
	c, _ := newFakeClient(t)
	ctx := context.Background()
	dataDir := t.TempDir()

	chain, priv, _, err := c.EnsureGenesis(ctx, dataDir, fixedTokensNow)
	if err != nil {
		t.Fatalf("EnsureGenesis: %v", err)
	}
	leases := journal.NewLeases(c)
	lease, err := leases.Open(ctx, journal.MetaStreamID)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	hash1 := journal.TokenHashPrefix + strings.Repeat("a", 64)
	hash2 := journal.TokenHashPrefix + strings.Repeat("b", 64)
	seq, err := c.AppendTokenCreate(ctx, lease, priv, chain, "tok_dup", hash1, []string{"rwc:*"}, fixedTokensNow)
	if err != nil {
		t.Fatalf("first AppendTokenCreate: %v", err)
	}
	// See TestAppendTokenCreateThenRevokeRoundTrip for why chain is
	// advanced by hand between two sequential appends on one lease.
	if err := chain.AdvanceMetaSeq(seq); err != nil {
		t.Fatalf("chain.AdvanceMetaSeq(%d): %v", seq, err)
	}
	if _, err := c.AppendTokenCreate(ctx, lease, priv, chain, "tok_dup", hash2, []string{"r:docs"}, fixedTokensNow); err != nil {
		t.Fatalf("second AppendTokenCreate (same token_id): %v", err)
	}

	if _, _, err := c.ReplayMetaTable(ctx); err == nil {
		t.Fatal("ReplayMetaTable accepted a journal poisoned with a reused token id")
	}
}

// 4. Every pre-check AppendTokenCreate/AppendTokenRevoke make before ever
// calling lease.Append refuse with zero entries added to fake.Calls()
// beyond whatever Open itself already made, leave the stream unfenced,
// and are exactly one line -- mirroring
// TestAppendRefTxPreChecksRefuseWithZeroNetworkCallsAndNoFencing
// (reftx_test.go).
func TestAppendTokenCreatePreChecksRefuseWithZeroNetworkCallsAndNoFencing(t *testing.T) {
	c, fake := newFakeClient(t)
	ctx := context.Background()
	dataDir := t.TempDir()

	chain, priv, _, err := c.EnsureGenesis(ctx, dataDir, fixedTokensNow)
	if err != nil {
		t.Fatalf("EnsureGenesis: %v", err)
	}
	leases := journal.NewLeases(c)
	metaLease, err := leases.Open(ctx, journal.MetaStreamID)
	if err != nil {
		t.Fatalf("Open(_meta): %v", err)
	}
	repoLease, err := leases.Open(ctx, "repo-alpha")
	if err != nil {
		t.Fatalf("Open(repo-alpha): %v", err)
	}

	uninitialized := journal.NewSigningChain()
	otherPriv, _, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	tests := []struct {
		name   string
		lease  *journal.Lease
		ctx    context.Context
		priv   ed25519.PrivateKey
		chain  *journal.SigningChain
		scopes []string
		now    func() time.Time
	}{
		{"nil lease", nil, ctx, priv, chain, []string{"rwc:*"}, fixedTokensNow},
		{"nil ctx", metaLease, nil, priv, chain, []string{"rwc:*"}, fixedTokensNow},
		{"wrong-size private key", metaLease, ctx, priv[:len(priv)-1], chain, []string{"rwc:*"}, fixedTokensNow},
		{"nil now", metaLease, ctx, priv, chain, []string{"rwc:*"}, nil},
		{"nil chain", metaLease, ctx, priv, nil, []string{"rwc:*"}, fixedTokensNow},
		{"uninitialized chain", metaLease, ctx, priv, uninitialized, []string{"rwc:*"}, fixedTokensNow},
		{"non-meta lease", repoLease, ctx, priv, chain, []string{"rwc:*"}, fixedTokensNow},
		{"empty scopes", metaLease, ctx, priv, chain, []string{}, fixedTokensNow},
		{"empty scope entry", metaLease, ctx, priv, chain, []string{""}, fixedTokensNow},
		{"duplicate scope", metaLease, ctx, priv, chain, []string{"r:docs", "r:docs"}, fixedTokensNow},
		{"control character scope", metaLease, ctx, priv, chain, []string{"r:docs\x00"}, fixedTokensNow},
		{"invalid UTF-8 scope", metaLease, ctx, priv, chain, []string{"r:doc\xffs"}, fixedTokensNow},
		{"signing key not the active key", metaLease, ctx, otherPriv, chain, []string{"rwc:*"}, fixedTokensNow},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			callsBefore := len(fake.Calls())
			_, err := c.AppendTokenCreate(tc.ctx, tc.lease, tc.priv, tc.chain, "tok_precheck", journal.TokenHashPrefix+strings.Repeat("a", 64), tc.scopes, tc.now)
			assertTokensOneLine(t, err)
			if errors.Is(err, journal.ErrFenced) {
				t.Errorf("a pre-check failure must refuse, not fence: %v", err)
			}
			if metaLease.Fencer().IsFenced(journal.MetaStreamID) {
				t.Errorf("expected _meta to remain unfenced")
			}
			if got := len(fake.Calls()); got != callsBefore {
				t.Errorf("fake saw %d further requests, want 0", got-callsBefore)
			}
		})
	}

	// A bad token id and a bad token hash are shared with AppendTokenRevoke
	// too, so they get one pass each here rather than duplicated below.
	t.Run("bad token id", func(t *testing.T) {
		callsBefore := len(fake.Calls())
		_, err := c.AppendTokenCreate(ctx, metaLease, priv, chain, "tok admin 01", journal.TokenHashPrefix+strings.Repeat("a", 64), []string{"rwc:*"}, fixedTokensNow)
		assertTokensOneLine(t, err)
		if got := len(fake.Calls()); got != callsBefore {
			t.Errorf("fake saw %d further requests, want 0", got-callsBefore)
		}
	})
	t.Run("bad token hash", func(t *testing.T) {
		callsBefore := len(fake.Calls())
		_, err := c.AppendTokenCreate(ctx, metaLease, priv, chain, "tok_precheck", "not-a-hash", []string{"rwc:*"}, fixedTokensNow)
		assertTokensOneLine(t, err)
		if got := len(fake.Calls()); got != callsBefore {
			t.Errorf("fake saw %d further requests, want 0", got-callsBefore)
		}
	})
}

// 5. AppendTokenRevoke's own pre-checks, covering the ones it does not
// share with AppendTokenCreate (it has no scopes to check).
func TestAppendTokenRevokePreChecksRefuseWithZeroNetworkCallsAndNoFencing(t *testing.T) {
	c, fake := newFakeClient(t)
	ctx := context.Background()
	dataDir := t.TempDir()

	chain, priv, _, err := c.EnsureGenesis(ctx, dataDir, fixedTokensNow)
	if err != nil {
		t.Fatalf("EnsureGenesis: %v", err)
	}
	leases := journal.NewLeases(c)
	metaLease, err := leases.Open(ctx, journal.MetaStreamID)
	if err != nil {
		t.Fatalf("Open(_meta): %v", err)
	}
	repoLease, err := leases.Open(ctx, "repo-alpha")
	if err != nil {
		t.Fatalf("Open(repo-alpha): %v", err)
	}

	uninitialized := journal.NewSigningChain()
	otherPriv, _, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	hash := journal.TokenHashPrefix + strings.Repeat("a", 64)

	tests := []struct {
		name  string
		lease *journal.Lease
		ctx   context.Context
		priv  ed25519.PrivateKey
		chain *journal.SigningChain
	}{
		{"nil lease", nil, ctx, priv, chain},
		{"nil ctx", metaLease, nil, priv, chain},
		{"wrong-size private key", metaLease, ctx, priv[:len(priv)-1], chain},
		{"nil chain", metaLease, ctx, priv, nil},
		{"uninitialized chain", metaLease, ctx, priv, uninitialized},
		{"non-meta lease", repoLease, ctx, priv, chain},
		{"signing key not the active key", metaLease, ctx, otherPriv, chain},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			callsBefore := len(fake.Calls())
			_, err := c.AppendTokenRevoke(tc.ctx, tc.lease, tc.priv, tc.chain, "tok_precheck", hash, fixedTokensNow)
			assertTokensOneLine(t, err)
			if errors.Is(err, journal.ErrFenced) {
				t.Errorf("a pre-check failure must refuse, not fence: %v", err)
			}
			if metaLease.Fencer().IsFenced(journal.MetaStreamID) {
				t.Errorf("expected _meta to remain unfenced")
			}
			if got := len(fake.Calls()); got != callsBefore {
				t.Errorf("fake saw %d further requests, want 0", got-callsBefore)
			}
		})
	}

	t.Run("nil now", func(t *testing.T) {
		callsBefore := len(fake.Calls())
		_, err := c.AppendTokenRevoke(ctx, metaLease, priv, chain, "tok_precheck", hash, nil)
		assertTokensOneLine(t, err)
		if got := len(fake.Calls()); got != callsBefore {
			t.Errorf("fake saw %d further requests, want 0", got-callsBefore)
		}
	})
}

// 6. A clock that panics when called must not be able to reach
// lease.Append's callback (WALD-27's own finding, applied here): because
// AppendTokenCreate computes now().UTC().Format(time.RFC3339) once,
// before lease.Append is ever called, a panicking now surfaces directly
// to this call's own caller, leaving _meta unfenced -- pinned here by a
// following successful append on the same lease, the property the hoist
// buys.
func TestAppendTokenCreatePanickingNowSurfacesBeforeLeaseInteraction(t *testing.T) {
	c, fake := newFakeClient(t)
	ctx := context.Background()
	dataDir := t.TempDir()

	chain, priv, _, err := c.EnsureGenesis(ctx, dataDir, fixedTokensNow)
	if err != nil {
		t.Fatalf("EnsureGenesis: %v", err)
	}
	leases := journal.NewLeases(c)
	lease, err := leases.Open(ctx, journal.MetaStreamID)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	callsBefore := len(fake.Calls())

	panickingNow := func() time.Time {
		panic("clock unavailable")
	}

	func() {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected AppendTokenCreate to panic when now panics")
			}
			if r != "clock unavailable" {
				t.Errorf("recovered panic = %v, want %q", r, "clock unavailable")
			}
		}()
		_, _ = c.AppendTokenCreate(ctx, lease, priv, chain, "tok_panic", journal.TokenHashPrefix+strings.Repeat("a", 64), []string{"rwc:*"}, panickingNow)
		t.Fatal("AppendTokenCreate returned instead of panicking")
	}()

	if lease.Fencer().IsFenced(journal.MetaStreamID) {
		t.Errorf("a panicking clock must leave _meta unfenced: it must surface before lease.Append ever runs")
	}
	if got := len(fake.Calls()); got != callsBefore {
		t.Errorf("fake saw %d further requests, want 0 (lease.Append must never have run)", got-callsBefore)
	}

	// The property the hoist buys: _meta is still healthy, and a normal
	// append on the same lease still succeeds at the sequence the panicking
	// call never consumed.
	seq, err := c.AppendTokenCreate(ctx, lease, priv, chain, "tok_after_panic", journal.TokenHashPrefix+strings.Repeat("b", 64), []string{"rwc:*"}, fixedTokensNow)
	if err != nil {
		t.Fatalf("AppendTokenCreate after the panic: %v", err)
	}
	if seq != 1 {
		t.Errorf("seq = %d, want 1 (the panicking call must not have consumed a sequence)", seq)
	}
}

// 7. A stale chain -- one replayed before a concurrent writer landed a
// further _meta record -- must not be trusted to sign at the sequence
// the lease independently offers: RotateKey's own refuseMetaSequenceDrift
// reasoning (rotation.go), applied to a token record. The refusal is
// plain, so _meta is left unfenced and the sequence unconsumed, and a
// caller that replays again succeeds.
func TestAppendTokenCreateRefusesOnStaleChainSequence(t *testing.T) {
	c, fake := newFakeClient(t)
	ctx := context.Background()
	dataDir := t.TempDir()

	staleChain, priv, _, err := c.EnsureGenesis(ctx, dataDir, fixedTokensNow)
	if err != nil {
		t.Fatalf("EnsureGenesis: %v", err)
	}

	// A concurrent writer lands a further _meta record (an unrelated
	// token_create) directly, before this test's own lease is even
	// opened -- staleChain (replayed above, LastMetaSeq 0) does not
	// reflect it, but the lease opened below will: (*journal.Leases).Open
	// discovers a stream's head with its own LIST, once, at Open time.
	concurrentRec := journal.NewTokenCreateRecord(1, "tok_concurrent", journal.TokenHashPrefix+strings.Repeat("c", 64), []string{"rwc:*"}, "2026-09-18T00:00:00Z")
	if err := journal.SignTokenCreate(priv, concurrentRec); err != nil {
		t.Fatalf("SignTokenCreate: %v", err)
	}
	data, err := journal.MarshalTokenCreate(concurrentRec)
	if err != nil {
		t.Fatalf("MarshalTokenCreate: %v", err)
	}
	if err := c.PutIfAbsent(ctx, journal.TxKey(journal.MetaStreamID, 1), bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("PutIfAbsent (simulated concurrent writer): %v", err)
	}

	// Opened after the concurrent write: this lease's own head discovery
	// sees it, so it will offer seq 2 next -- one past what staleChain was
	// verified through.
	leases := journal.NewLeases(c)
	lease, err := leases.Open(ctx, journal.MetaStreamID)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	callsBefore := len(fake.Calls())
	_, err = c.AppendTokenCreate(ctx, lease, priv, staleChain, "tok_late", journal.TokenHashPrefix+strings.Repeat("d", 64), []string{"rwc:*"}, fixedTokensNow)
	if err == nil {
		t.Fatal("AppendTokenCreate accepted a stale chain's view of _meta")
	}
	assertTokensOneLine(t, err)
	if errors.Is(err, journal.ErrFenced) {
		t.Errorf("a stale-chain sequence drift must refuse, not fence: %v", err)
	}
	if lease.Fencer().IsFenced(journal.MetaStreamID) {
		t.Errorf("expected _meta to remain unfenced")
	}
	// The sequence check runs first inside the closure, before any
	// PutIfAbsent, so this refusal costs no further request at all.
	if got := len(fake.Calls()); got != callsBefore {
		t.Errorf("fake saw %d further requests, want 0 (the sequence check runs before any PutIfAbsent)", got-callsBefore)
	}

	// A fresh replay produces a chain consistent with the lease's own
	// next sequence, and the retry succeeds.
	freshChain, _, err := c.ReplayMetaTable(ctx)
	if err != nil {
		t.Fatalf("ReplayMetaTable: %v", err)
	}
	seq, err := c.AppendTokenCreate(ctx, lease, priv, freshChain, "tok_late", journal.TokenHashPrefix+strings.Repeat("d", 64), []string{"rwc:*"}, fixedTokensNow)
	if err != nil {
		t.Fatalf("AppendTokenCreate after a fresh replay: %v", err)
	}
	if seq != 2 {
		t.Errorf("seq = %d, want 2", seq)
	}
}

// TestReplayMetaTableAgreesWithFixtureTokenTableReplay loads the golden
// journal's _meta stream into a fake bucket and asserts ReplayMetaTable
// rebuilds the same two-row table
// journal.TestFixtureTokenTableReplay asserts directly against the
// format-side type -- proving the store-side walk and the format-side
// type agree on the same published bytes.
func TestReplayMetaTableAgreesWithFixtureTokenTableReplay(t *testing.T) {
	c, fake := newFakeClient(t)
	loadGoldenMetaFixture(t, fake)

	chain, table, err := c.ReplayMetaTable(context.Background())
	if err != nil {
		t.Fatalf("ReplayMetaTable on the golden journal: %v", err)
	}
	if chain.LastMetaSeq() != 4 {
		t.Errorf("LastMetaSeq() = %d, want 4", chain.LastMetaSeq())
	}
	rows := table.Rows()
	if len(rows) != 2 {
		t.Fatalf("rebuilt table holds %d rows, want 2", len(rows))
	}
	admin, ok := table.Row("tok_admin_01")
	if !ok || !admin.Revoked {
		t.Errorf("tok_admin_01: found=%v revoked=%v, want found and revoked", ok, ok && admin.Revoked)
	}
	writer, ok := table.Row("tok_writer_02")
	if !ok || writer.Revoked {
		t.Errorf("tok_writer_02: found=%v revoked=%v, want found and live", ok, ok && writer.Revoked)
	}
}

// TestReplayMetaTableGoldenJournalFlippedSignatureByteRefuses corrupts one
// byte of the golden journal's tok_writer_02 signature and asserts both
// ReplayMeta and ReplayMetaTable refuse identically under rule 19 -- the
// table being enforced on every walk must not weaken the signature check
// that already existed before WALD-33.
func TestReplayMetaTableGoldenJournalFlippedSignatureByteRefuses(t *testing.T) {
	c, fake := newFakeClient(t)
	loadGoldenMetaFixture(t, fake)

	key := fullKey(journal.TxKey(journal.MetaStreamID, 4))
	data, ok := fake.Object(key)
	if !ok {
		t.Fatalf("Object(%q) not found", key)
	}
	var rec journal.TokenCreateRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	// Flip one hex character of the signature -- still well-formed
	// ("ed25519:<128-hex>"), just wrong.
	flipped := []byte(rec.Signature)
	if flipped[len(flipped)-1] == '0' {
		flipped[len(flipped)-1] = '1'
	} else {
		flipped[len(flipped)-1] = '0'
	}
	rec.Signature = string(flipped)
	tampered, err := json.MarshalIndent(&rec, "", "  ")
	if err != nil {
		t.Fatalf("json.MarshalIndent: %v", err)
	}
	fake.SetObject(key, append(tampered, '\n'))

	if _, err := c.ReplayMeta(context.Background()); !errors.Is(err, journal.ErrSignatureMismatch) {
		t.Errorf("ReplayMeta: errors.Is(_, ErrSignatureMismatch) = false, err = %v", err)
	}
	if _, _, err := c.ReplayMetaTable(context.Background()); !errors.Is(err, journal.ErrSignatureMismatch) {
		t.Errorf("ReplayMetaTable: errors.Is(_, ErrSignatureMismatch) = false, err = %v", err)
	}
}

// loadGoldenMetaFixture reads every object under the published golden
// journal's _meta stream (spec/journal/v1/fixtures/v1/streams/_meta/tx/)
// and seeds fake with it at the same keys AppendTokenCreate/ReplayMeta
// themselves use, so these tests exercise the store-side walk against the
// same bytes internal/journal/fixtures_test.go holds the format-side type
// to.
func loadGoldenMetaFixture(t *testing.T, fake *storetest.Fake) {
	t.Helper()
	dir := filepath.Join("..", "..", "spec", "journal", "v1", "fixtures", "v1", "streams", string(journal.MetaStreamID), "tx")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read golden _meta fixture dir %s: %v", dir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("failed to read %s: %v", entry.Name(), err)
		}
		seq, err := journal.ParseSeq(strings.TrimSuffix(entry.Name(), ".json"))
		if err != nil {
			t.Fatalf("golden fixture file %s does not name a sequence: %v", entry.Name(), err)
		}
		fake.SetObject(fullKey(journal.TxKey(journal.MetaStreamID, seq)), data)
	}
}
