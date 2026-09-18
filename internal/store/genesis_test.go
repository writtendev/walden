// Tests for (*Client).EnsureGenesis (WALD-28), driven against
// storetest.Fake the same way storetest_client_test.go and probe_test.go
// are: a pass here means the mint/adopt/fence orchestration is right
// against something that actually enforces spec/journal/v1's
// compare-and-swap contract, not a mock that only knows what a test author
// remembered to assert.
package store_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/store"
	"github.com/writtendev/walden/internal/store/storetest"
)

// signingKeyTempFiles returns every signing key temp file
// (SigningKeyPath(dataDir)+".tmp.<32-hex>") currently under dataDir. Every
// test that used to check a single fixed "signing.key.tmp" path checks this
// instead, since round 1 finding 1's fix gives each WriteSigningKeyTemp call
// its own randomly suffixed name.
func signingKeyTempFiles(t *testing.T, dataDir string) []string {
	t.Helper()
	matches, err := filepath.Glob(journal.SigningKeyPath(dataDir) + ".tmp.*")
	if err != nil {
		t.Fatalf("Glob failed: %v", err)
	}
	return matches
}

// fixedGenesisNow is the deterministic clock every EnsureGenesis test uses,
// so a minted record's timestamp never depends on wall-clock time.
func fixedGenesisNow() time.Time {
	return time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// metaObjectCount counts the objects fake holds under the _meta stream's
// prefix, journal-relative keys included via fullKey.
func metaObjectCount(fake *storetest.Fake) int {
	prefix := fullKey(journal.StreamPrefix(journal.MetaStreamID))
	n := 0
	for _, k := range fake.Keys() {
		if strings.HasPrefix(k, prefix) {
			n++
		}
	}
	return n
}

// (a) An empty journal mints: exactly one object under _meta, its
// public_key matches the saved key file, and the chain's ActiveKey matches.
func TestEnsureGenesisMintsOnEmptyJournal(t *testing.T) {
	c, fake := newFakeClient(t)
	dataDir := t.TempDir()

	chain, priv, minted, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
	if err != nil {
		t.Fatalf("EnsureGenesis failed: %v", err)
	}
	if !minted {
		t.Error("minted = false, want true")
	}
	if chain == nil || !chain.IsInitialized() {
		t.Fatal("expected an initialized signing chain")
	}

	objKey := fullKey(journal.TxKey(journal.MetaStreamID, 0))
	data, ok := fake.Object(objKey)
	if !ok {
		t.Fatalf("expected an object at %s", objKey)
	}
	rec, err := journal.ParseGenesis(data)
	if err != nil {
		t.Fatalf("ParseGenesis on the minted object failed: %v", err)
	}

	wantPub := journal.FormatPublicKey(priv.Public().(ed25519.PublicKey))
	if rec.PublicKey != wantPub {
		t.Errorf("minted object public_key = %q, want %q", rec.PublicKey, wantPub)
	}
	if chain.ActiveKey() != wantPub {
		t.Errorf("chain.ActiveKey() = %q, want %q", chain.ActiveKey(), wantPub)
	}

	loaded, err := journal.LoadSigningKey(dataDir)
	if err != nil {
		t.Fatalf("LoadSigningKey failed: %v", err)
	}
	if !loaded.Equal(priv) {
		t.Errorf("saved signing key does not match the key EnsureGenesis returned")
	}
	if matches := signingKeyTempFiles(t, dataDir); len(matches) != 0 {
		t.Errorf("temp key file(s) left behind after a successful mint: %v", matches)
	}

	if n := metaObjectCount(fake); n != 1 {
		t.Errorf("expected exactly one object under _meta, got %d", n)
	}
}

// (b) A second call against the same data directory adopts: no PUT is
// issued, and the object's bytes are unchanged.
func TestEnsureGenesisSecondCallAdopts(t *testing.T) {
	c, fake := newFakeClient(t)
	dataDir := t.TempDir()

	chain1, priv1, minted1, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
	if err != nil {
		t.Fatalf("first EnsureGenesis failed: %v", err)
	}
	if !minted1 {
		t.Fatal("first call: minted = false, want true")
	}

	objKey := fullKey(journal.TxKey(journal.MetaStreamID, 0))
	before, _ := fake.Object(objKey)
	callsBefore := len(fake.Calls())

	chain2, priv2, minted2, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
	if err != nil {
		t.Fatalf("second EnsureGenesis failed: %v", err)
	}
	if minted2 {
		t.Error("second call: minted = true, want false (adopt)")
	}

	after, _ := fake.Object(objKey)
	if string(before) != string(after) {
		t.Errorf("object bytes changed between mint and adopt")
	}

	for _, call := range fake.Calls()[callsBefore:] {
		if call.Op == storetest.OpPutIfAbsent || call.Op == storetest.OpPut {
			t.Errorf("adopt issued a write: %+v", call)
		}
	}

	if chain2.ActiveKey() != chain1.ActiveKey() {
		t.Errorf("adopted chain's ActiveKey = %q, want %q", chain2.ActiveKey(), chain1.ActiveKey())
	}
	if !priv2.Equal(priv1) {
		t.Errorf("adopted key does not match the minted key")
	}
}

// (c) Adopting with the local key file deleted, and adopting with a local
// key file holding a different key, each refuse in one line.
func TestEnsureGenesisAdoptRefusesWithoutMatchingKey(t *testing.T) {
	t.Run("missing key file", func(t *testing.T) {
		c, _ := newFakeClient(t)
		dataDir := t.TempDir()
		if _, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow); err != nil {
			t.Fatalf("mint failed: %v", err)
		}
		if err := os.Remove(journal.SigningKeyPath(dataDir)); err != nil {
			t.Fatalf("failed to remove signing key: %v", err)
		}

		_, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
		if err == nil {
			t.Fatal("expected a refusal, got nil")
		}
		if !errors.Is(err, journal.ErrSigningKeyUnavailable) {
			t.Errorf("expected ErrSigningKeyUnavailable, got %v", err)
		}
		if strings.ContainsAny(err.Error(), "\n\r") {
			t.Errorf("refusal is not a single line: %q", err.Error())
		}
	})

	t.Run("mismatched key file", func(t *testing.T) {
		c, _ := newFakeClient(t)
		dataDir := t.TempDir()
		if _, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow); err != nil {
			t.Fatalf("mint failed: %v", err)
		}
		other, _, err := journal.GenerateKeypair()
		if err != nil {
			t.Fatalf("GenerateKeypair failed: %v", err)
		}
		if err := journal.SaveSigningKey(dataDir, other); err != nil {
			t.Fatalf("SaveSigningKey failed: %v", err)
		}

		_, _, _, err = c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
		if err == nil {
			t.Fatal("expected a refusal, got nil")
		}
		if !errors.Is(err, journal.ErrSigningKeyUnavailable) {
			t.Errorf("expected ErrSigningKeyUnavailable, got %v", err)
		}
		if strings.ContainsAny(err.Error(), "\n\r") {
			t.Errorf("refusal is not a single line: %q", err.Error())
		}
	})
}

// (d) A 412 on the genesis PUT fences the loser in one line, and leaves no
// signing key litter behind.
func TestEnsureGenesisPreconditionFencesLoser(t *testing.T) {
	c, fake := newFakeClient(t)
	dataDir := t.TempDir()
	fake.Inject(storetest.Rule{
		Op: storetest.OpPutIfAbsent, Call: 1,
		Fault: storetest.Fault{Status: http.StatusPreconditionFailed, Code: "PreconditionFailed"},
	})

	_, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	want := journal.RefuseStreamFenced(journal.MetaStreamID, 0).Error()
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
	if !errors.Is(err, journal.ErrFenced) {
		t.Errorf("expected errors.Is(err, journal.ErrFenced), got %v", err)
	}
	if fileExists(journal.SigningKeyPath(dataDir)) {
		t.Errorf("signing.key left behind after a fenced mint attempt")
	}
	if matches := signingKeyTempFiles(t, dataDir); len(matches) != 0 {
		t.Errorf("signing key temp file(s) left behind after a fenced mint attempt: %v", matches)
	}
}

// (e) An ambiguous outcome on the genesis PUT fences the instance with the
// section 11.5 item 8 text, and does not touch signing.key itself. Unlike
// the 412 case (d), the temp key file is deliberately retained rather than
// removed (round 1 finding 7): an outcome-unknown PUT may have landed, in
// which case the temp file is the only surviving copy of a now-permanent
// record's private key, so deleting it on a mere maybe would trade a
// recoverable state for an unrecoverable one on no proof of loss.
func TestEnsureGenesisOutcomeUnknownFences(t *testing.T) {
	c, fake := newFakeClient(t)
	dataDir := t.TempDir()
	fake.Inject(storetest.Rule{
		Op: storetest.OpPutIfAbsent, Call: 1,
		Fault: storetest.Fault{Status: http.StatusInternalServerError, Code: "InternalError", Land: true},
	})

	_, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	want := journal.RefuseAppendOutcomeUnknown(journal.MetaStreamID, 0).Error()
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
	if !errors.Is(err, store.ErrOutcomeUnknown) && !errors.Is(err, journal.ErrFenced) {
		t.Errorf("expected the error to trace to ErrOutcomeUnknown/ErrFenced, got %v", err)
	}
	if fileExists(journal.SigningKeyPath(dataDir)) {
		t.Errorf("signing.key left behind after an outcome-unknown mint attempt")
	}
	if matches := signingKeyTempFiles(t, dataDir); len(matches) != 1 {
		t.Errorf("expected exactly one retained signing key temp file after an outcome-unknown mint attempt, got %d: %v", len(matches), matches)
	}
}

// (f) A 403 on the initial GET refuses as a storage failure, not as a
// corrupt journal: it must not trace to journal.ErrInvalidGenesis.
func TestEnsureGenesisGetForbiddenIsStorageFailure(t *testing.T) {
	c, fake := newFakeClient(t)
	dataDir := t.TempDir()
	fake.Inject(storetest.Rule{
		Op: storetest.OpGet, Call: 1,
		Fault: storetest.Fault{Status: http.StatusForbidden, Code: "AccessDenied"},
	})

	_, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	if errors.Is(err, journal.ErrInvalidGenesis) {
		t.Errorf("a GET failure must not masquerade as a corrupt genesis record: %v", err)
	}
	if !errors.Is(err, store.ErrStorageRefused) {
		t.Errorf("expected errors.Is(err, store.ErrStorageRefused), got %v", err)
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
}

// (g) Round 1 finding 2: minting must not silently overwrite a signing.key
// that already exists in dataDir. An operator repointing --data-dir at a
// new or typo'd journal prefix must get a refusal, not a destroyed private
// key and a cheerful "journal identity minted:" line — and mint must
// refuse before it ever calls PutIfAbsent, since generating and PUTting a
// second identity is itself part of the damage.
func TestEnsureGenesisMintRefusesOverExistingSigningKey(t *testing.T) {
	c, fake := newFakeClient(t)
	dataDir := t.TempDir()

	other, _, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	if err := journal.SaveSigningKey(dataDir, other); err != nil {
		t.Fatalf("SaveSigningKey failed: %v", err)
	}
	callsBefore := len(fake.Calls())

	_, _, _, err = c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	if !errors.Is(err, journal.ErrSigningKeyUnavailable) {
		t.Errorf("expected errors.Is(err, journal.ErrSigningKeyUnavailable), got %v", err)
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}

	for _, call := range fake.Calls()[callsBefore:] {
		if call.Op == storetest.OpPutIfAbsent || call.Op == storetest.OpPut {
			t.Errorf("mint issued a write before refusing over an existing signing key: %+v", call)
		}
	}
	if n := metaObjectCount(fake); n != 0 {
		t.Errorf("expected no object under _meta, got %d", n)
	}

	loaded, err := journal.LoadSigningKey(dataDir)
	if err != nil {
		t.Fatalf("LoadSigningKey failed: %v", err)
	}
	if !loaded.Equal(other) {
		t.Error("the pre-existing signing key was overwritten by a refused mint attempt")
	}
}

// (g2) Round 2 finding: a local signing.key must never cause a refusal that
// claims no genesis record exists when one actually does — the exact shape
// of the shared-data-directory race where a sibling's winning PutIfAbsent
// and CommitSigningKey could land between this instance's Get and a later
// stat, leaving RefuseSigningKeyPresentOnMint's "no genesis record found"
// false by the time it printed (internal/store/genesis.go, line 183 in the
// version that finding was filed against). EnsureGenesis now stats the
// local key before the Get rather than after (see EnsureGenesis's doc
// comment), so a genesis record that is actually present always routes to
// adopt regardless of what the earlier stat found; these two cases pin that
// down deterministically, without depending on goroutine timing the way
// TestEnsureGenesisConcurrentRaceSharedDataDir must.
func TestEnsureGenesisPresentSigningKeyNeverBlocksAdopt(t *testing.T) {
	t.Run("matching local key adopts", func(t *testing.T) {
		c, fake := newFakeClient(t)
		dataDir := t.TempDir()

		priv, pub, err := journal.GenerateKeypair()
		if err != nil {
			t.Fatalf("GenerateKeypair failed: %v", err)
		}
		if err := journal.SaveSigningKey(dataDir, priv); err != nil {
			t.Fatalf("SaveSigningKey failed: %v", err)
		}
		rec := journal.NewGenesisRecord(pub, fixedGenesisNow().UTC().Format(time.RFC3339))
		data, err := journal.MarshalGenesis(rec)
		if err != nil {
			t.Fatalf("MarshalGenesis failed: %v", err)
		}
		fake.SetObject(fullKey(journal.TxKey(journal.MetaStreamID, 0)), data)

		_, _, minted, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
		if err != nil {
			t.Fatalf("EnsureGenesis failed: %v", err)
		}
		if minted {
			t.Error("minted = true, want false (adopt)")
		}
	})

	t.Run("mismatched local key names the record, not a missing one", func(t *testing.T) {
		c, fake := newFakeClient(t)
		dataDir := t.TempDir()

		_, pub, err := journal.GenerateKeypair()
		if err != nil {
			t.Fatalf("GenerateKeypair failed: %v", err)
		}
		other, _, err := journal.GenerateKeypair()
		if err != nil {
			t.Fatalf("GenerateKeypair failed: %v", err)
		}
		if err := journal.SaveSigningKey(dataDir, other); err != nil {
			t.Fatalf("SaveSigningKey failed: %v", err)
		}
		rec := journal.NewGenesisRecord(pub, fixedGenesisNow().UTC().Format(time.RFC3339))
		data, err := journal.MarshalGenesis(rec)
		if err != nil {
			t.Fatalf("MarshalGenesis failed: %v", err)
		}
		fake.SetObject(fullKey(journal.TxKey(journal.MetaStreamID, 0)), data)

		_, _, _, err = c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
		if err == nil {
			t.Fatal("expected a refusal, got nil")
		}
		if strings.Contains(err.Error(), "no genesis record found") {
			t.Errorf("refusal claims no genesis record exists, but one does: %q", err.Error())
		}
		want := journal.RefuseSigningKeyMismatch(dataDir, 0, rec.PublicKey, journal.FormatPublicKey(other.Public().(ed25519.PublicKey))).Error()
		if err.Error() != want {
			t.Errorf("got %q, want %q", err.Error(), want)
		}
	})
}

// TestEnsureGenesisMismatchAfterRotationNamesRotationNotGenesis is round 1's
// medium finding on internal/journal/genesis.go: RefuseSigningKeyMismatch
// used to hardcode "genesis at <_meta seq 0> names <want>" even though, after
// a rotation, chain.ActiveKey() (the key EnsureGenesis's adopt path actually
// compares against) is no longer genesis's own public_key. Reproduces the
// exact scenario from the review: mint, rotate once, restore the retired
// (genesis) key to signing.key, and boot — the refusal must not claim
// genesis names the active key, since genesis never named it in the first
// place; it must instead name the seq _meta was replayed through.
func TestEnsureGenesisMismatchAfterRotationNamesRotationNotGenesis(t *testing.T) {
	c, _ := newFakeClient(t)
	dataDir := t.TempDir()

	seedChain, genesisPriv, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
	if err != nil {
		t.Fatalf("EnsureGenesis (mint) failed: %v", err)
	}
	genesisKey := seedChain.ActiveKey()

	leases := journal.NewLeases(c)
	_, activeKey, err := c.RotateKey(context.Background(), dataDir, leases, fixedRotateNow)
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}
	if activeKey == genesisKey {
		t.Fatal("RotateKey did not change the active key")
	}

	// signing.key on disk now holds the post-rotation key; restore the
	// retired genesis key in its place, the way an operator recovering an
	// old backup would.
	if err := journal.SaveSigningKey(dataDir, genesisPriv); err != nil {
		t.Fatalf("SaveSigningKey failed: %v", err)
	}

	_, _, _, err = c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	if strings.Contains(err.Error(), fmt.Sprintf("genesis at %s names", journal.TxKey(journal.MetaStreamID, 0))) {
		t.Errorf("refusal still blames genesis for a key only a rotation named: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "_meta replayed through seq 1") {
		t.Errorf("refusal does not name the sequence _meta was replayed through: %q", err.Error())
	}
	if !strings.Contains(err.Error(), activeKey) {
		t.Errorf("refusal does not name the rotation's active key %q: %q", activeKey, err.Error())
	}
	if !strings.Contains(err.Error(), genesisKey) {
		t.Errorf("refusal does not name the local (genesis) key %q on disk: %q", genesisKey, err.Error())
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
}

// (h) Round 1 finding 4: a local filesystem failure during mint — here,
// WriteSigningKeyTemp failing because dataDir itself does not exist — must
// not be answered with the bucket/region/credentials fix clause
// wrapGenesisFailure uses for genuine storage failures. Nothing in this
// path ever reaches the bucket (no PutIfAbsent call), so a clause about S3
// credentials would send the operator to check the wrong thing entirely.
func TestEnsureGenesisMintLocalDiskFailureGetsDiskFix(t *testing.T) {
	c, fake := newFakeClient(t)
	dataDir := filepath.Join(t.TempDir(), "does-not-exist")

	_, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	if strings.Contains(err.Error(), "bucket") || strings.Contains(err.Error(), "credentials") {
		t.Errorf("a local disk failure must not carry the bucket/credentials fix clause: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "data directory") {
		t.Errorf("expected the refusal to name the data directory: %q", err.Error())
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
	for _, call := range fake.Calls() {
		if call.Op == storetest.OpPutIfAbsent || call.Op == storetest.OpPut {
			t.Errorf("a WriteSigningKeyTemp failure must not still attempt PutIfAbsent: %+v", call)
		}
	}
}

// (i) Round 1 finding 5: an oversized object at _meta seq 0 must be refused
// in one line, not read in full. A genesis record is ~250 bytes by spec
// section 3.1; this seeds an object well past maxGenesisBody and checks
// EnsureGenesis refuses rather than allocating the whole thing.
func TestEnsureGenesisOversizedBodyRefused(t *testing.T) {
	c, fake := newFakeClient(t)
	dataDir := t.TempDir()

	huge := make([]byte, 1<<20) // 1 MiB, far past maxGenesisBody's 64 KiB.
	for i := range huge {
		huge[i] = 'x'
	}
	fake.SetObject(fullKey(journal.TxKey(journal.MetaStreamID, 0)), huge)

	_, _, _, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	if !errors.Is(err, journal.ErrInvalidGenesis) {
		t.Errorf("expected errors.Is(err, journal.ErrInvalidGenesis), got %v", err)
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
}

// (j) Round 1 finding 6: the adopt check must compare decoded key bytes,
// not formatted hex strings, so a genesis record naming the local key's
// public half in non-lowercase (but still parseable) hex adopts instead of
// refusing a mismatch that is really only a case difference.
func TestEnsureGenesisAdoptToleratesUppercaseHexKey(t *testing.T) {
	c, fake := newFakeClient(t)
	dataDir := t.TempDir()

	priv, pub, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	if err := journal.SaveSigningKey(dataDir, priv); err != nil {
		t.Fatalf("SaveSigningKey failed: %v", err)
	}

	lower := journal.FormatPublicKey(pub) // "ed25519:<64-lower-hex>"
	upper := "ed25519:" + strings.ToUpper(strings.TrimPrefix(lower, "ed25519:"))
	rec := map[string]string{
		"version":    "v1",
		"stream":     "_meta",
		"seq":        "0",
		"type":       "genesis",
		"public_key": upper,
		"timestamp":  "2026-09-17T12:00:00Z",
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	fake.SetObject(fullKey(journal.TxKey(journal.MetaStreamID, 0)), data)

	chain, adoptedPriv, minted, err := c.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
	if err != nil {
		t.Fatalf("expected an uppercase-hex public_key to adopt, got refusal: %v", err)
	}
	if minted {
		t.Error("minted = true, want false (adopt)")
	}
	if !adoptedPriv.Equal(priv) {
		t.Error("adopted key does not match the local signing key")
	}
	// ApplyGenesis stores the record's public_key string verbatim
	// (identity.go), so the chain's ActiveKey carries the record's own
	// uppercase spelling — it is the *comparison* against the local key
	// that must be immune to case, not the chain's memory of the record.
	if chain.ActiveKey() != upper {
		t.Errorf("chain.ActiveKey() = %q, want the record's own form %q", chain.ActiveKey(), upper)
	}
}

// The ticket's real acceptance test: two Clients over one Fake, each with
// its own data directory, calling EnsureGenesis concurrently. Exactly one
// object lands under _meta, exactly one caller succeeds (minted), and
// exactly one signing.key exists across the two directories — no temp
// litter on either side. The fake's conditional PUT is check-and-create
// under one mutex (storetest doc comment), so the winner is genuine rather
// than simulated; run under -race.
//
// The loser's refusal is not pinned to RefuseStreamFenced alone. With
// separate data directories, the loser has no local signing key of its own
// to adopt with, so which one-line refusal it produces depends on pure
// goroutine scheduling relative to the winner's conditional PUT:
//   - if the loser's Get lands before the winner's PutIfAbsent is visible,
//     it takes the mint path, loses its own PutIfAbsent, and refuses with
//     RefuseStreamFenced (journal.ErrFenced);
//   - if the loser's Get lands after, it sees the winner's genesis record
//     already present and takes the adopt path — but this data directory
//     has no signing.key of its own, so it refuses with RefuseNoSigningKey
//     (journal.ErrSigningKeyUnavailable) rather than fencing.
//
// A round 3 review reproduced the adopt-path outcome at 8/200, 3/200, and
// 1/20 under GOMAXPROCS=1 (0/200 on an idle machine, which is why an
// assertion pinned to RefuseStreamFenced alone passed in CI and would still
// fail under load). Both outcomes are correct — the sibling
// TestEnsureGenesisConcurrentRaceSharedDataDir already treats "which correct
// refusal fired" as immaterial to a race test's real job, and this test
// follows that shape rather than pinning one interleaving as the only
// correct one.
func TestEnsureGenesisConcurrentRaceSingleWinner(t *testing.T) {
	restore := store.SetBackoffForTest(time.Millisecond, 5*time.Millisecond)
	t.Cleanup(restore)
	fake := storetest.New(t)

	newRacer := func() *store.Client {
		j := &store.Journal{
			Endpoint:    fake.URL(),
			Region:      "us-east-1",
			Bucket:      fake.Bucket(),
			Prefix:      testPrefix,
			PathStyle:   true,
			Credentials: store.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		}
		return store.NewClient(j)
	}
	c1, c2 := newRacer(), newRacer()
	dir1, dir2 := t.TempDir(), t.TempDir()

	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, 2)
	minted := make([]bool, 2)

	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, _, m, err := c1.EnsureGenesis(context.Background(), dir1, fixedGenesisNow)
		minted[0], errs[0] = m, err
	}()
	go func() {
		defer wg.Done()
		<-start
		_, _, m, err := c2.EnsureGenesis(context.Background(), dir2, fixedGenesisNow)
		minted[1], errs[1] = m, err
	}()
	close(start)
	wg.Wait()

	var successes, refused int
	for i, err := range errs {
		if err == nil {
			successes++
			if !minted[i] {
				t.Errorf("winner %d: minted = false, want true", i)
			}
			continue
		}
		refused++
		if !errors.Is(err, journal.ErrFenced) && !errors.Is(err, journal.ErrSigningKeyUnavailable) {
			t.Errorf("loser %d: unexpected refusal, want RefuseStreamFenced or RefuseNoSigningKey: %v", i, err)
		}
		if strings.ContainsAny(err.Error(), "\n\r") {
			t.Errorf("loser %d: refusal is not a single line: %q", i, err.Error())
		}
	}
	if successes != 1 {
		t.Errorf("successes = %d, want 1", successes)
	}
	if refused != 1 {
		t.Errorf("refused = %d, want 1", refused)
	}

	if n := metaObjectCount(fake); n != 1 {
		t.Errorf("expected exactly one object under _meta, got %d", n)
	}

	var keyCount int
	for _, dir := range []string{dir1, dir2} {
		if fileExists(journal.SigningKeyPath(dir)) {
			keyCount++
		}
		if matches := signingKeyTempFiles(t, dir); len(matches) != 0 {
			t.Errorf("temp key file(s) left behind in %s: %v", dir, matches)
		}
	}
	if keyCount != 1 {
		t.Errorf("expected exactly one signing.key across both directories, got %d", keyCount)
	}
}

// The regression test for round 1 finding 1: two Clients over one Fake,
// racing EnsureGenesis against the SAME data directory (the scenario the
// original TestEnsureGenesisConcurrentRaceSingleWinner missed by giving each
// racer its own t.TempDir()). Before the fix, a fixed "signing.key.tmp"
// path opened O_TRUNC with no O_EXCL let the two racers overwrite each
// other's unwritten key before either conditional PUT was decided, so the
// eventual winner's CommitSigningKey could rename the LOSER's bytes into
// place under the WINNER's genesis record — a permanently unsignable
// journal (spec section 2.2) reached with no crash at all. The reviewer's
// reproduction hit this on 56 of 60 iterations against one shared data
// directory; this test runs the same shape repeatedly and asserts, every
// time, that whichever key ends up on disk is the actual winner's key and
// nothing else — a per-call random temp file name plus O_EXCL (see
// WriteSigningKeyTemp's doc comment) makes the clobber structurally
// impossible rather than merely unlikely, so this passes deterministically
// rather than passing most of the time.
func TestEnsureGenesisConcurrentRaceSharedDataDir(t *testing.T) {
	restore := store.SetBackoffForTest(time.Millisecond, 5*time.Millisecond)
	t.Cleanup(restore)

	newRacer := func(fake *storetest.Fake) *store.Client {
		j := &store.Journal{
			Endpoint:    fake.URL(),
			Region:      "us-east-1",
			Bucket:      fake.Bucket(),
			Prefix:      testPrefix,
			PathStyle:   true,
			Credentials: store.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		}
		return store.NewClient(j)
	}

	const iterations = 60
	for i := 0; i < iterations; i++ {
		fake := storetest.New(t)
		c1, c2 := newRacer(fake), newRacer(fake)
		dataDir := t.TempDir() // the whole point: ONE dir for both racers.

		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make([]error, 2)
		minted := make([]bool, 2)
		privs := make([]ed25519.PrivateKey, 2)

		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, priv, m, err := c1.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
			minted[0], errs[0], privs[0] = m, err, priv
		}()
		go func() {
			defer wg.Done()
			<-start
			_, priv, m, err := c2.EnsureGenesis(context.Background(), dataDir, fixedGenesisNow)
			minted[1], errs[1], privs[1] = m, err, priv
		}()
		close(start)
		wg.Wait()

		// A shared data directory admits more legitimate outcomes than two
		// separate directories do: exactly one PutIfAbsent can ever win
		// (storage's conditional-write contract, unaffected by any of
		// this), but the *other* racer can land on either side of that
		// win depending on pure goroutine scheduling — arriving at its own
		// Get() before the winner's PUT lands (and then losing its own
		// PutIfAbsent with RefuseStreamFenced), or arriving after (adopting
		// the winner's already-on-disk identity outright, since the two
		// racers share the very directory that identity was just written
		// to, or refusing honestly via RefuseNoSigningKey/
		// RefuseSigningKeyMismatch if it observes the record before the
		// winner's local rename has caught up). All of these are correct;
		// what must never happen, on any interleaving, is a signing.key
		// that does not match the genesis record — that is the corruption
		// round 1 finding 1 describes.
		//
		// Before a round 2 fix (EnsureGenesis now stats the local signing
		// key before its genesis GET rather than after — see
		// EnsureGenesis's doc comment), a third shape was possible here:
		// this racer's own Get() returning not-found just ahead of the
		// winner's commit, followed by this racer's stat finding the
		// winner's signing.key already on disk, reaching
		// RefuseSigningKeyPresentOnMint's "no genesis record found" claim
		// opposite what the winner had, by then, already proven. Stat-then-
		// Get closes that ordering (see TestEnsureGenesisPresentSigningKeyNeverBlocksAdopt
		// for a deterministic pin of the invariant it relies on), so that
		// refusal should no longer surface from this loop at all; errors.Is
		// against ErrSigningKeyUnavailable is kept broad below rather than
		// narrowed to the two remaining constructors, since this test's own
		// job is the key/record match, not enumerating which refusal fired.
		var successPrivs []ed25519.PrivateKey
		for racer, err := range errs {
			if err == nil {
				successPrivs = append(successPrivs, privs[racer])
				continue
			}
			if !errors.Is(err, journal.ErrFenced) && !errors.Is(err, journal.ErrSigningKeyUnavailable) {
				t.Fatalf("iteration %d: racer %d: unexpected refusal: %v", i, racer, err)
			}
			if strings.ContainsAny(err.Error(), "\n\r") {
				t.Fatalf("iteration %d: racer %d: refusal is not a single line: %q", i, racer, err.Error())
			}
		}
		if len(successPrivs) == 0 {
			t.Fatalf("iteration %d: both racers refused; expected at least one to succeed", i)
		}
		for idx, p := range successPrivs {
			if !p.Equal(successPrivs[0]) {
				t.Fatalf("iteration %d: successful racers returned different private keys (index %d) — this is exactly the corruption round 1 finding 1 describes", i, idx)
			}
		}

		if n := metaObjectCount(fake); n != 1 {
			t.Fatalf("iteration %d: expected exactly one object under _meta, got %d", i, n)
		}

		// The crux of the regression: the key actually on disk must be the
		// one true winner's key, never a loser's bytes renamed into place
		// under the winner's genesis record.
		onDisk, err := journal.LoadSigningKey(dataDir)
		if err != nil {
			t.Fatalf("iteration %d: LoadSigningKey failed: %v", i, err)
		}
		if !onDisk.Equal(successPrivs[0]) {
			t.Fatalf("iteration %d: signing.key does not hold the winner's private key — this is the corruption round 1 finding 1 describes", i)
		}

		objKey := fullKey(journal.TxKey(journal.MetaStreamID, 0))
		data, ok := fake.Object(objKey)
		if !ok {
			t.Fatalf("iteration %d: expected a genesis object", i)
		}
		rec, err := journal.ParseGenesis(data)
		if err != nil {
			t.Fatalf("iteration %d: ParseGenesis failed: %v", i, err)
		}
		wantPub := journal.FormatPublicKey(onDisk.Public().(ed25519.PublicKey))
		if rec.PublicKey != wantPub {
			t.Fatalf("iteration %d: genesis record's public_key does not match the key on disk — signing.key cannot sign for this journal", i)
		}

		if matches := signingKeyTempFiles(t, dataDir); len(matches) != 0 {
			t.Fatalf("iteration %d: temp key file(s) left behind: %v", i, matches)
		}
	}
}
