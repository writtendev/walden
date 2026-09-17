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
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/store"
	"github.com/writtendev/walden/internal/store/storetest"
)

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
	if fileExists(journal.SigningKeyPath(dataDir) + ".tmp") {
		t.Errorf("temp key file left behind after a successful mint")
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
	if fileExists(journal.SigningKeyPath(dataDir) + ".tmp") {
		t.Errorf("signing.key.tmp left behind after a fenced mint attempt")
	}
}

// (e) An ambiguous outcome on the genesis PUT fences the instance with the
// section 11.5 item 8 text, and leaves no signing key litter behind.
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
	if fileExists(journal.SigningKeyPath(dataDir) + ".tmp") {
		t.Errorf("signing.key.tmp left behind after an outcome-unknown mint attempt")
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

// The ticket's real acceptance test: two Clients over one Fake, each with
// its own data directory, calling EnsureGenesis concurrently. Exactly one
// object lands under _meta, exactly one caller succeeds (minted), the other
// is fenced with RefuseStreamFenced's exact text, and exactly one
// signing.key exists across the two directories — no temp litter on
// either side. The fake's conditional PUT is check-and-create under one
// mutex (storetest doc comment), so the winner is genuine rather than
// simulated; run under -race.
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

	var successes, fenced int
	wantFenced := journal.RefuseStreamFenced(journal.MetaStreamID, 0).Error()
	for i, err := range errs {
		if err == nil {
			successes++
			if !minted[i] {
				t.Errorf("winner %d: minted = false, want true", i)
			}
			continue
		}
		fenced++
		if err.Error() != wantFenced {
			t.Errorf("loser %d error = %q, want %q", i, err.Error(), wantFenced)
		}
	}
	if successes != 1 {
		t.Errorf("successes = %d, want 1", successes)
	}
	if fenced != 1 {
		t.Errorf("fenced = %d, want 1", fenced)
	}

	if n := metaObjectCount(fake); n != 1 {
		t.Errorf("expected exactly one object under _meta, got %d", n)
	}

	var keyCount int
	for _, dir := range []string{dir1, dir2} {
		if fileExists(journal.SigningKeyPath(dir)) {
			keyCount++
		}
		if fileExists(journal.SigningKeyPath(dir) + ".tmp") {
			t.Errorf("temp key file left behind in %s", dir)
		}
	}
	if keyCount != 1 {
		t.Errorf("expected exactly one signing.key across both directories, got %d", keyCount)
	}
}
