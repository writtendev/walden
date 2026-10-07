// Tests for the pre-receive probe (refprepare.go, WALD-128): the accepted-
// set arithmetic against a real bare repository and the real git binary,
// with no HTTP and no journal involved. journalPush's own use of
// prepareRefUpdates -- where the accepted subset actually gets journaled,
// or skipped -- is covered by prereceive_journal_test.go; the full push,
// through the real git client end to end, is serve_unix_test.go's job.
package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/journal"
)

// newBareRepo creates an empty bare repository (no refs) in a fresh
// t.TempDir and returns its absolute path.
func newBareRepo(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "repo.git")
	if out, err := exec.Command("git", "init", "-q", "--bare", "--initial-branch=main", dir).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v\n%s", err, out)
	}
	return dir
}

// assertNoLocks fails the test if any *.lock file remains anywhere under
// repoPath. probePrepare's own abort (or git's own fatal-triggered
// cleanup) must release every lock it took before returning, on both the
// accepting and the refusing path (WALD-128 Done-when 4).
func assertNoLocks(t *testing.T, repoPath string) {
	t.Helper()
	var stray []string
	err := filepath.WalkDir(repoPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".lock") {
			stray = append(stray, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s for stray locks: %v", repoPath, err)
	}
	if len(stray) > 0 {
		t.Errorf("stray .lock file(s) left under %s: %v", repoPath, stray)
	}
}

// readRef reads ref out of the bare repository at repoPath through the
// real git binary, returning "" when it does not resolve. The counterpart
// to setRef (prereceive_test.go), for the tests that have to show a probe
// left the repository's refs exactly as it found them.
func readRef(t *testing.T, repoPath, ref string) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", "--verify", "--quiet", ref)
	cmd.Dir = repoPath
	cmd.Env = append(cleanGitEnv(), "GIT_DIR=.")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// TestPrepareRefUpdatesAcceptsACleanSet is the common-path case: every
// update in one push applies, so prepareRefUpdates makes exactly one exec
// (proven indirectly by the other tests below driving multi-exec paths;
// this one only pins the outcome) and returns the whole slice, unchanged,
// as the accepted set.
func TestPrepareRefUpdatesAcceptsACleanSet(t *testing.T) {
	repoPath := newBareRepo(t)
	pack, sha := realCommit(t)
	realizeObjects(t, repoPath, pack)

	updates := []journal.RefUpdate{
		{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: sha},
	}
	accepted, err := prepareRefUpdates(context.Background(), repoPath, "", updates)
	if err != nil {
		t.Fatalf("prepareRefUpdates: %v", err)
	}
	assertUpdates(t, accepted, updates)
	assertNoLocks(t, repoPath)
}

// TestPrepareRefUpdatesDFConflictRefusedBothOrders is WALD-128's headline
// case as its 2026-09-28 amendment settled it: two refs of one push in a
// directory/file conflict (refs/heads/feature and refs/heads/feature/x
// cannot both exist) are refused whole, in one line, whichever order the
// push named them in. Both orders are covered because which side git keeps
// is exactly what stopped being predictable -- so the refusal must not
// depend on the order either.
func TestPrepareRefUpdatesDFConflictRefusedBothOrders(t *testing.T) {
	pack, sha := realCommit(t)

	tests := []struct {
		name    string
		updates []journal.RefUpdate
	}{
		{
			name: "parent first",
			updates: []journal.RefUpdate{
				{Ref: "refs/heads/feature", OldOID: journal.ZeroOID40, NewOID: sha},
				{Ref: "refs/heads/feature/x", OldOID: journal.ZeroOID40, NewOID: sha},
			},
		},
		{
			name: "child first",
			updates: []journal.RefUpdate{
				{Ref: "refs/heads/feature/x", OldOID: journal.ZeroOID40, NewOID: sha},
				{Ref: "refs/heads/feature", OldOID: journal.ZeroOID40, NewOID: sha},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repoPath := newBareRepo(t)
			realizeObjects(t, repoPath, pack)

			accepted, err := prepareRefUpdates(context.Background(), repoPath, "", tt.updates)
			if err == nil {
				t.Fatalf("prepareRefUpdates accepted %+v, want the whole push refused", accepted)
			}
			if accepted != nil {
				t.Errorf("accepted = %+v alongside a refusal, want nil", accepted)
			}
			if strings.ContainsAny(err.Error(), "\n\r") {
				t.Errorf("expected a single-line refusal, got: %q", err.Error())
			}
			for _, ref := range []string{"refs/heads/feature", "refs/heads/feature/x"} {
				if !strings.Contains(err.Error(), ref) {
					t.Errorf("refusal %q does not name %s", err.Error(), ref)
				}
			}
			assertNoLocks(t, repoPath)
		})
	}
}

// TestPrepareRefUpdatesDFConflictCountsADeletedRef is the case the rule
// above used to carve out: a push that deletes refs/heads/feature and
// creates refs/heads/feature/x. Real git applies both of those updates
// (confirmed against git 2.50.1 -- see refuseDirFileConflict's own
// comment), so this is the push walden refuses and git would have taken;
// it is refused anyway, because the probe cannot report that outcome. It
// evaluates its batch against the refs on disk, where refs/heads/feature
// still is, so the create fails in every candidate set and the accepted
// set would come back holding the delete alone -- a ref left on disk that
// no journal record names.
//
// This test is the carve-out's own test, rewritten to the opposite
// expectation rather than deleted: it asserted only that walden did not
// refuse, which is why it never saw the under-claim underneath. Both wire
// orders, because a delete is not always sorted where the client typed it.
func TestPrepareRefUpdatesDFConflictCountsADeletedRef(t *testing.T) {
	pack, sha := realCommit(t)

	deleteParent := journal.RefUpdate{Ref: "refs/heads/feature", OldOID: sha, NewOID: journal.ZeroOID40}
	createChild := journal.RefUpdate{Ref: "refs/heads/feature/x", OldOID: journal.ZeroOID40, NewOID: sha}

	tests := []struct {
		name    string
		updates []journal.RefUpdate
	}{
		{name: "delete first", updates: []journal.RefUpdate{deleteParent, createChild}},
		{name: "create first", updates: []journal.RefUpdate{createChild, deleteParent}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repoPath := newBareRepo(t)
			realizeObjects(t, repoPath, pack)
			setRef(t, repoPath, "refs/heads/feature", sha)

			accepted, err := prepareRefUpdates(context.Background(), repoPath, "", tt.updates)
			if err == nil {
				t.Fatalf("prepareRefUpdates accepted %+v, want the whole push refused", accepted)
			}
			if accepted != nil {
				t.Errorf("accepted = %+v alongside a refusal, want nil", accepted)
			}
			if strings.ContainsAny(err.Error(), "\n\r") {
				t.Errorf("expected a single-line refusal, got: %q", err.Error())
			}
			for _, ref := range []string{"refs/heads/feature", "refs/heads/feature/x"} {
				if !strings.Contains(err.Error(), ref) {
					t.Errorf("refusal %q does not name %s", err.Error(), ref)
				}
			}
			// The delete must not have been applied either: a refusal is
			// the whole push refused, and this probe never commits.
			if got := readRef(t, repoPath, "refs/heads/feature"); got != sha {
				t.Errorf("refs/heads/feature = %q after the refusal, want it untouched at %q", got, sha)
			}
			assertNoLocks(t, repoPath)
		})
	}
}

// TestPrepareRefUpdatesStaleOldOIDInTheMiddle covers a three-ref push where
// the middle ref is stale -- its old_oid no longer matches the
// repository's real current value -- and the two refs on either side of it
// are unrelated and both apply. The accepted set must be exactly the first
// and third, in order, never all three and never just one: this is what
// proves the incremental loop keeps walking past a rejected candidate
// rather than stopping at the first refusal.
func TestPrepareRefUpdatesStaleOldOIDInTheMiddle(t *testing.T) {
	repoPath := newBareRepo(t)
	pack, sha := realCommit(t)
	realizeObjects(t, repoPath, pack)
	// "s" already exists, at sha -- the push below claims a stale old_oid
	// (all-zero, i.e. "does not exist yet") for it.
	setRef(t, repoPath, "refs/heads/s", sha)

	updates := []journal.RefUpdate{
		{Ref: "refs/heads/a", OldOID: journal.ZeroOID40, NewOID: sha},
		{Ref: "refs/heads/s", OldOID: journal.ZeroOID40, NewOID: sha},
		{Ref: "refs/heads/c", OldOID: journal.ZeroOID40, NewOID: sha},
	}
	accepted, err := prepareRefUpdates(context.Background(), repoPath, "", updates)
	if err != nil {
		t.Fatalf("prepareRefUpdates: %v", err)
	}
	assertUpdates(t, accepted, []journal.RefUpdate{updates[0], updates[2]})
	assertNoLocks(t, repoPath)
}

// TestPrepareRefUpdatesEmptyAcceptedSet covers the case in which git will
// refuse every update in the push: prepareRefUpdates returns an empty,
// non-nil-error slice, which is not itself a refusal (WALD-128 Done-when
// 9) -- the caller (journalPush) is the one that turns an empty accepted
// set into "skip AppendRefTx, journal the segment only".
func TestPrepareRefUpdatesEmptyAcceptedSet(t *testing.T) {
	repoPath := newBareRepo(t)
	pack, sha := realCommit(t)
	realizeObjects(t, repoPath, pack)
	setRef(t, repoPath, "refs/heads/main", sha)

	// A single stale old_oid: main is really at sha, this claims it does
	// not exist yet.
	updates := []journal.RefUpdate{
		{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: sha},
	}
	accepted, err := prepareRefUpdates(context.Background(), repoPath, "", updates)
	if err != nil {
		t.Fatalf("prepareRefUpdates: %v", err)
	}
	if len(accepted) != 0 {
		t.Errorf("accepted = %+v, want an empty slice", accepted)
	}
	assertNoLocks(t, repoPath)
}

// TestPrepareRefUpdatesNotARepositoryCannotAnswer covers the "anything
// else" row of probePrepare's verdict table: repoPath that is not a git
// repository at all produces a fatal from git that never even reaches
// "start: ok", which is not git refusing content -- it is git unable to
// run the probe at all -- and must refuse the whole push rather than be
// read as an empty accepted set.
func TestPrepareRefUpdatesNotARepositoryCannotAnswer(t *testing.T) {
	notARepo := t.TempDir()
	updates := []journal.RefUpdate{
		{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "8a65c6d3715c0e1e92d6e3e5362e49c7198cfb60"},
	}
	accepted, err := prepareRefUpdates(context.Background(), notARepo, "", updates)
	if err == nil {
		t.Fatalf("prepareRefUpdates over a non-repository succeeded with accepted = %+v, want a refusal", accepted)
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("expected a single-line refusal, got: %q", err.Error())
	}
}

// TestPrepareRefUpdatesLockCollisionCannotAnswer drives the one risk the
// plan surfaced and the human's decision on WALD-128 resolved: a real ref
// lock held by another process for the exact ref this probe is asking
// about. Without the reclassification in probePrepare/
// isLockAcquisitionFailure, this reads exactly like row two of the verdict
// table ("fatal: prepare:", start: ok on stdout) -- git saying no -- and
// the caller would narrow the accepted set on a transient condition that
// says nothing about whether the update is valid. That is the WALD-46-
// class under-claim the decision exists to prevent, so this must refuse
// the whole push instead.
func TestPrepareRefUpdatesLockCollisionCannotAnswer(t *testing.T) {
	repoPath := newBareRepo(t)
	pack, sha := realCommit(t)
	realizeObjects(t, repoPath, pack)
	setRef(t, repoPath, "refs/heads/main", sha)

	// Hold a real lock on refs/heads/main by starting a second
	// `git update-ref --stdin` transaction directly (not through this
	// package's probe, so this test does not depend on its own subject
	// to build the very contention it is trying to observe) and leaving
	// it prepared until this test releases it.
	holder := exec.Command("git", "update-ref", "--stdin")
	holder.Dir = repoPath
	holder.Env = append(cleanGitEnv(), "GIT_DIR=.")
	stdin, err := holder.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	if err := holder.Start(); err != nil {
		t.Fatalf("start lock holder: %v", err)
	}
	t.Cleanup(func() {
		stdin.Write([]byte("abort\n"))
		stdin.Close()
		holder.Wait()
	})
	if _, err := stdin.Write([]byte("start\nupdate refs/heads/main " + sha + " " + sha + "\nprepare\n")); err != nil {
		t.Fatalf("write to lock holder: %v", err)
	}
	// Give the holder time to actually reach and complete "prepare" --
	// which is what takes the lock -- before racing it.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if lockHeld(repoPath, "refs/heads/main") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("lock holder never appears to have taken refs/heads/main.lock")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// A real, different new_oid, so this is a legitimate,
	// otherwise-acceptable update contending only on the lock.
	pack2, sha2 := realCommit(t)
	realizeObjects(t, repoPath, pack2)
	updates := []journal.RefUpdate{
		{Ref: "refs/heads/main", OldOID: sha, NewOID: sha2},
	}

	accepted, err := prepareRefUpdates(context.Background(), repoPath, "", updates)
	if err == nil {
		t.Fatalf("prepareRefUpdates raced a real lock and succeeded with accepted = %+v, want a refusal", accepted)
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("expected a single-line refusal, got: %q", err.Error())
	}
}

// lockHeld reports whether ref's .lock file currently exists in repoPath.
func lockHeld(repoPath, ref string) bool {
	_, err := os.Stat(filepath.Join(repoPath, filepath.FromSlash(ref+".lock")))
	return err == nil
}

// TestPrepareRefUpdatesVariantCEnvironment pins the "variant C" recipe
// (refPrepareEnv's doc comment): with GIT_QUARANTINE_PATH and
// GIT_OBJECT_DIRECTORY polluting this test process's own environment --
// exactly what a real pre-receive hook's os.Environ() carries -- the probe
// must still both (a) not be refused outright as "ref updates forbidden
// inside quarantine environment", and (b) resolve a new_oid that exists
// only inside the quarantine pack, through
// GIT_ALTERNATE_OBJECT_DIRECTORIES. A bogus, pre-existing
// GIT_ALTERNATE_OBJECT_DIRECTORIES value is also set, to pin that
// refPrepareEnv overwrites rather than appends to it -- appending would
// carry the bogus entry through, and either break resolution or prove
// nothing about which behaviour is actually happening.
func TestPrepareRefUpdatesVariantCEnvironment(t *testing.T) {
	repoPath := newBareRepo(t)
	pack, sha := realCommit(t)

	quarantine := filepath.Join(repoPath, "objects", "tmp_objdir-incoming-x")
	if err := os.MkdirAll(filepath.Join(quarantine, "pack"), 0o755); err != nil {
		t.Fatalf("mkdir quarantine: %v", err)
	}
	packPath := filepath.Join(quarantine, "pack", "pack-x.pack")
	if err := os.WriteFile(packPath, pack, 0o644); err != nil {
		t.Fatalf("write quarantine pack: %v", err)
	}
	indexCmd := exec.Command("git", "index-pack", packPath)
	indexCmd.Env = append(cleanGitEnv(), "GIT_DIR="+repoPath)
	if out, err := indexCmd.CombinedOutput(); err != nil {
		t.Fatalf("git index-pack %s: %v\n%s", packPath, err, out)
	}

	// Simulate a real hook's ambient environment: git sets these three
	// for the hook process's own os.Environ(), which refPrepareEnv reads
	// wholesale and edits. GIT_ALTERNATE_OBJECT_DIRECTORIES here is
	// deliberately bogus and colon-joined with a nonexistent path, the
	// shape an append (rather than an overwrite) would carry through.
	t.Setenv("GIT_QUARANTINE_PATH", quarantine)
	t.Setenv("GIT_OBJECT_DIRECTORY", quarantine)
	t.Setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", "/nonexistent-does-not-exist/objects")

	updates := []journal.RefUpdate{
		{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: sha},
	}
	accepted, err := prepareRefUpdates(context.Background(), repoPath, quarantine, updates)
	if err != nil {
		t.Fatalf("prepareRefUpdates: %v (sha %s only exists in the quarantine, not the repository's real object store)", err, sha)
	}
	assertUpdates(t, accepted, updates)
	assertNoLocks(t, repoPath)
}

// TestProbePrepareQuarantineEnvironmentRefused pins the negative control for
// variant C: if GIT_QUARANTINE_PATH is left in the probe's environment, git
// refuses with "fatal: prepare: ref updates forbidden inside quarantine environment".
// walden must classify this environment error as "could not answer" and refuse
// the whole push in one line, rather than misclassifying it as a ref rejection
// and silently dropping valid updates.
func TestProbePrepareQuarantineEnvironmentRefused(t *testing.T) {
	repoPath := newBareRepo(t)
	pack, sha := realCommit(t)
	realizeObjects(t, repoPath, pack)

	updates := []journal.RefUpdate{
		{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: sha},
	}
	env := append(cleanGitEnv(), "GIT_DIR=.", "GIT_QUARANTINE_PATH="+filepath.Join(repoPath, "objects"))
	ok, err := probePrepareWithEnv(context.Background(), repoPath, env, updates)
	if err == nil {
		t.Fatalf("probePrepareWithEnv with GIT_QUARANTINE_PATH set succeeded (ok=%v), want a refusal", ok)
	}
	if ok {
		t.Errorf("ok = true alongside an error, want false")
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("expected a single-line refusal, got: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "ref updates forbidden inside quarantine environment") {
		t.Errorf("refusal %q does not mention quarantine environment error", err.Error())
	}
	assertNoLocks(t, repoPath)
}

// TestPrepareRefUpdatesNonexistentObjectWithoutAlternates pins the second
// negative control for variant C: when incoming objects exist only in the
// quarantine directory and quarantine is omitted from alternates, git rejects
// the ref as pointing to a nonexistent object. This is a genuine ref content
// rejection, so prepareRefUpdates returns an empty accepted set without error.
func TestPrepareRefUpdatesNonexistentObjectWithoutAlternates(t *testing.T) {
	repoPath := newBareRepo(t)
	pack, sha := realCommit(t)

	quarantine := filepath.Join(repoPath, "objects", "tmp_objdir-incoming-x")
	if err := os.MkdirAll(filepath.Join(quarantine, "pack"), 0o755); err != nil {
		t.Fatalf("mkdir quarantine: %v", err)
	}
	packPath := filepath.Join(quarantine, "pack", "pack-x.pack")
	if err := os.WriteFile(packPath, pack, 0o644); err != nil {
		t.Fatalf("write quarantine pack: %v", err)
	}
	indexCmd := exec.Command("git", "index-pack", packPath)
	indexCmd.Env = append(cleanGitEnv(), "GIT_DIR="+repoPath)
	if out, err := indexCmd.CombinedOutput(); err != nil {
		t.Fatalf("git index-pack %s: %v\n%s", packPath, err, out)
	}

	updates := []journal.RefUpdate{
		{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: sha},
	}
	// Passing quarantine="" leaves GIT_ALTERNATE_OBJECT_DIRECTORIES unset,
	// so sha cannot be resolved by git.
	accepted, err := prepareRefUpdates(context.Background(), repoPath, "", updates)
	if err != nil {
		t.Fatalf("prepareRefUpdates: %v, want empty accepted set", err)
	}
	if len(accepted) != 0 {
		t.Fatalf("accepted = %+v, want empty slice because object exists only in quarantine", accepted)
	}
	assertNoLocks(t, repoPath)
}

// TestProbePrepareConcurrentDifferentRefsBothSucceed is a negative control
// for the lock-collision reclassification: two probes racing two
// *different* refs must both succeed normally, proving
// isLockAcquisitionFailure's narrow substring match does not misfire on
// ordinary concurrent, non-contending use.
func TestProbePrepareConcurrentDifferentRefsBothSucceed(t *testing.T) {
	repoPath := newBareRepo(t)
	pack, sha := realCommit(t)
	realizeObjects(t, repoPath, pack)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	refs := []string{"refs/heads/a", "refs/heads/b"}
	for i, ref := range refs {
		wg.Add(1)
		go func(i int, ref string) {
			defer wg.Done()
			_, err := prepareRefUpdates(context.Background(), repoPath, "", []journal.RefUpdate{
				{Ref: ref, OldOID: journal.ZeroOID40, NewOID: sha},
			})
			errs[i] = err
		}(i, ref)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("prepareRefUpdates(%s): %v", refs[i], err)
		}
	}
	assertNoLocks(t, repoPath)
}

// TestIsLockAcquisitionFailure pins the exact, narrow substring match
// against git's own wording, isolated from a real subprocess, so a future
// edit to it is caught here even before the slower tests above would
// catch it.
func TestIsLockAcquisitionFailure(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want bool
	}{
		{
			name: "real lock collision message (git 2.50.1)",
			msg:  "fatal: prepare: cannot lock ref 'refs/heads/main': Unable to create '/repo.git/./refs/heads/main.lock': File exists.\n\nAnother git process seems to be running in this repository...\n",
			want: true,
		},
		{
			name: "D/F conflict is not a lock acquisition failure",
			msg:  "fatal: prepare: cannot lock ref 'refs/heads/feature/x': 'refs/heads/feature' exists; cannot create 'refs/heads/feature/x'\n",
			want: false,
		},
		{
			name: "nonexistent object is not a lock acquisition failure",
			msg:  "fatal: prepare: cannot update ref 'refs/heads/x': trying to write ref 'refs/heads/x' with nonexistent object 8a65c6d3715c0e1e92d6e3e5362e49c7198cfb60\n",
			want: false,
		},
		{
			name: "stale old_oid is not a lock acquisition failure",
			msg:  "fatal: prepare: cannot lock ref 'refs/heads/s': is at abc123 but expected def456\n",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLockAcquisitionFailure(tt.msg); got != tt.want {
				t.Errorf("isLockAcquisitionFailure(%q) = %v, want %v", tt.msg, got, tt.want)
			}
		})
	}
}

// TestIsRefContentRejection pins the exact discrimination between git's
// content-level ref rejections (which narrow the candidate set) and
// system/environment errors (which must refuse the whole push).
func TestIsRefContentRejection(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		{
			name: "stale old_oid: reference already exists",
			line: "fatal: prepare: cannot lock ref 'refs/heads/main': reference already exists",
			want: true,
		},
		{
			name: "stale old_oid: unexpected current sha",
			line: "fatal: prepare: cannot lock ref 'refs/heads/main': is at 1111111111111111111111111111111111111111 but expected 2222222222222222222222222222222222222222",
			want: true,
		},
		{
			name: "D/F conflict against existing ref",
			line: "fatal: prepare: cannot lock ref 'refs/heads/feature/x': 'refs/heads/feature' exists; cannot create 'refs/heads/feature/x'",
			want: true,
		},
		{
			name: "nonexistent object",
			line: "fatal: prepare: cannot update ref 'refs/heads/main': trying to write ref 'refs/heads/main' with nonexistent object 1111111111111111111111111111111111111111",
			want: true,
		},
		{
			name: "cannot update the ref variant",
			line: "fatal: prepare: cannot update the ref 'refs/heads/main': some error",
			want: true,
		},
		{
			name: "delete missing ref",
			line: "fatal: prepare: cannot delete ref 'refs/heads/main': reference is missing",
			want: true,
		},
		{
			name: "batch collision",
			line: "fatal: prepare: cannot process 'refs/heads/a' and 'refs/heads/a/x' at the same time",
			want: true,
		},
		{
			name: "multiple updates for ref in batch",
			line: "fatal: prepare: multiple updates for ref 'refs/heads/main' not allowed",
			want: true,
		},
		{
			name: "quarantine environment error is not a content rejection",
			line: "fatal: prepare: ref updates forbidden inside quarantine environment",
			want: false,
		},
		{
			name: "out of memory is not a content rejection",
			line: "fatal: prepare: out of memory",
			want: false,
		},
		{
			name: "unable to read object is not a content rejection",
			line: "fatal: prepare: unable to read object 1111111111111111111111111111111111111111",
			want: false,
		},
		{
			name: "update fatal is not a prepare fatal",
			line: "fatal: cannot lock ref 'refs/heads/main': reference already exists",
			want: false,
		},
		{
			name: "empty string",
			line: "",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRefContentRejection(tt.line); got != tt.want {
				t.Errorf("isRefContentRejection(%q) = %v, want %v", tt.line, got, tt.want)
			}
		})
	}
}

// TestFirstLine pins that mechanical rule 6's one-line composition takes
// exactly the first line and nothing past it.
func TestFirstLine(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"single line, no newline", "single line, no newline"},
		{"first\nsecond\nthird\n", "first"},
		{"first\r\nsecond\r\n", "first"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := firstLine(tt.in); got != tt.want {
			t.Errorf("firstLine(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
