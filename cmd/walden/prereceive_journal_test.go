// Tests for the pre-receive hook's journal appends (WALD-44), driven
// through runPreReceive itself against a fake object storage endpoint:
// what lands in the bucket for a push that carries new objects, for the
// two shapes of push that carry none, and for journal-less mode, which
// must still touch nothing at all.
//
// Deliberately not here: fault injection over storetest rules, or any
// assertion that the exit code is a durability guarantee. That is WALD-46.
package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/store/storetest"
)

// hookJournalFixture is the state one hook-level journal test needs: a
// fake bucket already carrying a genesis record, a data directory holding
// the matching signing key, and a bare repository for the hook to resolve.
type hookJournalFixture struct {
	fake     *storetest.Fake
	dataDir  string
	repo     string
	repoPath string
}

// newHookJournalFixture boots runServe once against a fresh fake so the
// journal has a genesis record and dataDir has the signing key
// (*store.Client).LoadSigner will look for -- the same seeding
// rotate_test.go and token_test.go do -- then creates the bare repository
// and sets the three WALDEN_* variables
// internal/githttp/receivepack.go would have set for the hook.
func newHookJournalFixture(t *testing.T, repo string) *hookJournalFixture {
	t.Helper()

	dataDir := t.TempDir()
	setJournalCreds(t)
	fake := storetest.New(t)
	journalURL := journalTestJournalURL(fake)

	var bootStdout, bootStderr bytes.Buffer
	if err := runServe(cancelledContext(), []string{
		"--data-dir", dataDir,
		"--listen", "127.0.0.1:0",
		"--journal", journalURL,
	}, &bootStdout, &bootStderr); err != nil {
		t.Fatalf("runServe (mint genesis): %v\n%s", err, bootStderr.String())
	}

	repoPath := initBareRepo(t, dataDir, repo)

	t.Setenv("WALDEN_REPO", repo)
	t.Setenv("WALDEN_DATA_DIR", dataDir)
	t.Setenv("WALDEN_JOURNAL", journalURL)

	return &hookJournalFixture{fake: fake, dataDir: dataDir, repo: repo, repoPath: repoPath}
}

// quarantine writes pack into a quarantine directory shaped the way git
// makes one, inside the repository, and points GIT_QUARANTINE_PATH and
// GIT_OBJECT_DIRECTORY at it. A nil pack leaves the pack directory empty.
func (f *hookJournalFixture) quarantine(t *testing.T, name string, pack []byte) {
	t.Helper()
	dir := filepath.Join(f.repoPath, "objects", "tmp_objdir-incoming-"+name)
	mkdirAll(t, filepath.Join(dir, "pack"))
	if pack != nil {
		writeFile(t, filepath.Join(dir, "pack", "pack-"+name+".pack"), pack)
	}
	t.Setenv("GIT_QUARANTINE_PATH", dir)
	t.Setenv("GIT_OBJECT_DIRECTORY", dir)
}

// noQuarantine clears both variables, which is what a delete-only push
// looks like: git creates no quarantine directory when no objects arrive.
func (f *hookJournalFixture) noQuarantine(t *testing.T) {
	t.Helper()
	t.Setenv("GIT_QUARANTINE_PATH", "")
	t.Setenv("GIT_OBJECT_DIRECTORY", "")
}

// object returns the fake's bytes for a journal key, under the same
// "prefix" journalTestJournalURL puts in the URL.
func (f *hookJournalFixture) object(key string) ([]byte, bool) {
	return f.fake.Object("prefix/" + key)
}

// refTx reads and parses the ref transaction at seq on this fixture's
// repository stream.
func (f *hookJournalFixture) refTx(t *testing.T, seq journal.Seq) *journal.RefTransactionRecord {
	t.Helper()
	return journalRefTx(t, f.fake, journal.StreamID(f.repo), seq)
}

// journalRefTx reads and parses the ref transaction at seq on stream,
// under the "prefix" journalTestJournalURL puts in the journal URL. It is
// shared with the end-to-end test in serve_unix_test.go, which reaches the
// same fake through a real `walden serve` subprocess.
func journalRefTx(t *testing.T, fake *storetest.Fake, stream journal.StreamID, seq journal.Seq) *journal.RefTransactionRecord {
	t.Helper()
	key := journal.TxKey(stream, seq)
	data, ok := fake.Object("prefix/" + key)
	if !ok {
		t.Fatalf("no ref transaction at %s; keys: %v", key, fake.Keys())
	}
	rec, err := journal.ParseRefTx(data)
	if err != nil {
		t.Fatalf("ParseRefTx(%s): %v", key, err)
	}
	return rec
}

// segmentKeys returns every key the fake holds under this fixture's
// repository stream's segments/ prefix.
func (f *hookJournalFixture) segmentKeys() []string {
	prefix := "prefix/" + journal.SegmentPrefix(journal.StreamID(f.repo))
	var keys []string
	for _, k := range f.fake.Keys() {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys
}

// runHook invokes runPreReceive with stdin built from updates, exactly as
// git's pre-receive protocol spells them.
func runHook(t *testing.T, updates []journal.RefUpdate) error {
	t.Helper()
	var stdin strings.Builder
	for _, u := range updates {
		stdin.WriteString(u.OldOID + " " + u.NewOID + " " + u.Ref + "\n")
	}
	return runPreReceive(context.Background(), nil, strings.NewReader(stdin.String()), io.Discard, io.Discard)
}

func assertUpdates(t *testing.T, got, want []journal.RefUpdate) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("updates = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("update[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestRunPreReceiveJournalsAPackAndItsRefTransaction is the headline case:
// a push carrying new objects PUTs the quarantined packfile verbatim under
// segments/<sha256>.pack, then a ref transaction at sequence 0 naming that
// one hash and carrying the updates git wrote to stdin.
func TestRunPreReceiveJournalsAPackAndItsRefTransaction(t *testing.T) {
	f := newHookJournalFixture(t, "repo")
	pack := realPackfile(t)
	f.quarantine(t, "create", pack)

	updates := []journal.RefUpdate{{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: testNewOID}}
	if err := runHook(t, updates); err != nil {
		t.Fatalf("runPreReceive: %v", err)
	}

	hash := journal.ComputeSegmentHash(pack)
	stored, ok := f.object(journal.SegmentKey("repo", hash))
	if !ok {
		t.Fatalf("no segment at %s; keys: %v", journal.SegmentKey("repo", hash), f.fake.Keys())
	}
	if !bytes.Equal(stored, pack) {
		t.Errorf("stored segment is %d bytes, want the packfile's %d, byte for byte", len(stored), len(pack))
	}

	rec := f.refTx(t, 0)
	if len(rec.Segments) != 1 || !strings.EqualFold(rec.Segments[0], hash) {
		t.Errorf("segments = %v, want exactly [%s]", rec.Segments, hash)
	}
	assertUpdates(t, rec.Updates, updates)
	if string(rec.Stream) != "repo" {
		t.Errorf("stream = %q, want %q", rec.Stream, "repo")
	}
}

// TestRunPreReceiveJournalsNoSegmentWhenNoObjectsArrive covers the two
// shapes of "this push introduced no new objects", which are genuinely two
// cases and not one: a delete-only push, for which git creates no
// quarantine directory at all, and a ref moved to an object the repository
// already holds, for which git still writes a pack -- the 32-byte one
// whose header declares zero objects. Both journal a ref transaction with
// an empty segments array and put nothing under segments/.
func TestRunPreReceiveJournalsNoSegmentWhenNoObjectsArrive(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, f *hookJournalFixture)
	}{
		{
			name:  "delete-only push has no quarantine directory",
			setup: func(t *testing.T, f *hookJournalFixture) { f.noQuarantine(t) },
		},
		{
			name: "ref moved to an object already present leaves a zero-object pack",
			setup: func(t *testing.T, f *hookJournalFixture) {
				f.quarantine(t, "empty", zeroObjectPack())
			},
		},
		{
			name: "quarantine directory with an empty pack directory",
			setup: func(t *testing.T, f *hookJournalFixture) {
				f.quarantine(t, "nopack", nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newHookJournalFixture(t, "repo")
			tt.setup(t, f)

			updates := []journal.RefUpdate{{Ref: "refs/heads/feature", OldOID: testOldOID, NewOID: journal.ZeroOID40}}
			if err := runHook(t, updates); err != nil {
				t.Fatalf("runPreReceive: %v", err)
			}

			rec := f.refTx(t, 0)
			if len(rec.Segments) != 0 {
				t.Errorf("segments = %v, want an empty array", rec.Segments)
			}
			assertUpdates(t, rec.Updates, updates)
			if keys := f.segmentKeys(); len(keys) != 0 {
				t.Errorf("segments were written for a push that carried no objects: %v", keys)
			}
		})
	}
}

// TestRunPreReceiveAppendsInSequenceAcrossPushes pins that a second
// invocation lands at sequence 1 rather than colliding with the first:
// each push is its own hook process, so Leases.Open rediscovers the head
// by LIST every time.
func TestRunPreReceiveAppendsInSequenceAcrossPushes(t *testing.T) {
	f := newHookJournalFixture(t, "repo")
	pack := realPackfile(t)
	f.quarantine(t, "create", pack)

	first := []journal.RefUpdate{{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: testNewOID}}
	if err := runHook(t, first); err != nil {
		t.Fatalf("runPreReceive (first): %v", err)
	}

	f.noQuarantine(t)
	second := []journal.RefUpdate{{Ref: "refs/heads/main", OldOID: testNewOID, NewOID: testOldOID}}
	if err := runHook(t, second); err != nil {
		t.Fatalf("runPreReceive (second): %v", err)
	}

	if rec := f.refTx(t, 0); len(rec.Segments) != 1 {
		t.Errorf("tx 0 segments = %v, want one", rec.Segments)
	}
	rec := f.refTx(t, 1)
	if len(rec.Segments) != 0 {
		t.Errorf("tx 1 segments = %v, want an empty array", rec.Segments)
	}
	assertUpdates(t, rec.Updates, second)
}

// TestRunPreReceiveJournalLessModeMakesNoRequest pins that journal-less
// mode still works and still costs nothing: with WALDEN_JOURNAL unset the
// hook resolves, exits 0, and never touches object storage. The fake here
// is never booted against, so any request at all would show up in Calls().
func TestRunPreReceiveJournalLessModeMakesNoRequest(t *testing.T) {
	dataDir := t.TempDir()
	setJournalCreds(t)
	fake := storetest.New(t)

	repoPath := initBareRepo(t, dataDir, "repo")
	t.Setenv("WALDEN_REPO", "repo")
	t.Setenv("WALDEN_DATA_DIR", dataDir)
	t.Setenv("WALDEN_JOURNAL", "")

	dir := filepath.Join(repoPath, "objects", "tmp_objdir-incoming-x")
	mkdirAll(t, filepath.Join(dir, "pack"))
	writeFile(t, filepath.Join(dir, "pack", "pack-x.pack"), realPackfile(t))
	t.Setenv("GIT_QUARANTINE_PATH", dir)
	t.Setenv("GIT_OBJECT_DIRECTORY", dir)

	updates := []journal.RefUpdate{{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: testNewOID}}
	if err := runHook(t, updates); err != nil {
		t.Fatalf("runPreReceive: %v", err)
	}

	if calls := fake.Calls(); len(calls) != 0 {
		t.Errorf("journal-less mode made %d request(s) to object storage: %+v", len(calls), calls)
	}
}

// TestRunPreReceiveRefusesWithoutAGenesisRecord covers LoadSigner running
// before AppendSegment: a journal with no genesis record refuses in one
// line, and no orphan segment is left in the bucket.
func TestRunPreReceiveRefusesWithoutAGenesisRecord(t *testing.T) {
	dataDir := t.TempDir()
	setJournalCreds(t)
	fake := storetest.New(t)

	repoPath := initBareRepo(t, dataDir, "repo")
	t.Setenv("WALDEN_REPO", "repo")
	t.Setenv("WALDEN_DATA_DIR", dataDir)
	t.Setenv("WALDEN_JOURNAL", journalTestJournalURL(fake))

	dir := filepath.Join(repoPath, "objects", "tmp_objdir-incoming-x")
	mkdirAll(t, filepath.Join(dir, "pack"))
	writeFile(t, filepath.Join(dir, "pack", "pack-x.pack"), realPackfile(t))
	t.Setenv("GIT_QUARANTINE_PATH", dir)
	t.Setenv("GIT_OBJECT_DIRECTORY", dir)

	err := runHook(t, []journal.RefUpdate{{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: testNewOID}})
	if err == nil {
		t.Fatal("runPreReceive succeeded against a journal with no genesis record, want a refusal")
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("expected a single-line refusal, got: %q", err.Error())
	}
	for _, k := range fake.Keys() {
		if strings.Contains(k, "/segments/") {
			t.Errorf("an orphan segment was left in the bucket before the refusal: %s", k)
		}
	}
}

// TestJournalPushHoldsTheClockStill pins journalPush's now parameter,
// which exists so a test can decide the record's timestamp rather than
// reading whatever the wall clock said.
func TestJournalPushHoldsTheClockStill(t *testing.T) {
	f := newHookJournalFixture(t, "repo")
	f.noQuarantine(t)

	req, err := resolveHook(context.Background(), os.LookupEnv, []journal.RefUpdate{
		{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: testNewOID},
	})
	if err != nil {
		t.Fatalf("resolveHook: %v", err)
	}
	if req.Journal == nil {
		t.Fatal("resolveHook returned a nil Journal; the fixture sets WALDEN_JOURNAL")
	}

	stopped := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := journalPush(context.Background(), req, func() time.Time { return stopped }); err != nil {
		t.Fatalf("journalPush: %v", err)
	}

	const want = "2020-01-02T03:04:05Z"
	if got := f.refTx(t, 0).Timestamp; got != want {
		t.Errorf("timestamp = %q, want %q", got, want)
	}
}
