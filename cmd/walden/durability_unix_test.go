//go:build unix

package main

import (
	"os/exec"
	"testing"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/store/storetest"
)

// TestServeEndToEndStorageFaultOnSegmentPUTBlocksPush is WALD-46's proof
// over real subprocesses: an injected storage failure during segment PUT
// causes the pre-receive hook to refuse the push, git receive-pack to reject
// the update, git push to exit non-zero, and the repository's ref to remain
// unmoved.
func TestServeEndToEndStorageFaultOnSegmentPUTBlocksPush(t *testing.T) {
	s := bootE2EServer(t)

	s.fake.Inject(storetest.Rule{
		Op:    storetest.OpPut,
		Call:  1,
		Count: 10,
		Fault: storetest.Fault{Status: 500, Code: "InternalError"},
	})

	work := t.TempDir()
	runLocalGit(t, work, "init", "-q", "-b", "main")
	runLocalGit(t, work, "config", "user.email", "test@example.com")
	runLocalGit(t, work, "config", "user.name", "Test")
	runLocalGit(t, work, "commit", "-q", "--allow-empty", "-m", "initial")

	pushCmd := exec.Command("git", "push", s.repoURL, "main")
	pushCmd.Dir = work
	pushCmd.Env = e2eGitEnv()
	out, err := pushCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("git push succeeded despite injected storage fault on segment PUT:\n%s", out)
	}

	// Ref was NOT moved in bare repo.
	verifyCmd := exec.Command("git", "--git-dir="+s.repoPath, "rev-parse", "--verify", "refs/heads/main")
	verifyCmd.Env = e2eGitEnv()
	if refOut, verifyErr := verifyCmd.CombinedOutput(); verifyErr == nil {
		t.Fatalf("refs/heads/main moved despite storage fault:\n%s", refOut)
	}

	// No ref transaction was recorded.
	if got, want := s.txCount(), 0; got != want {
		t.Errorf("tx count after failed segment PUT = %d, want %d", got, want)
	}
}

// TestServeEndToEndStorageFaultOnRefTxPUTBlocksPush verifies that a storage
// failure during the conditional ref transaction PUT fails git push and
// leaves the bare repo's ref untouched.
func TestServeEndToEndStorageFaultOnRefTxPUTBlocksPush(t *testing.T) {
	s := bootE2EServer(t)

	s.fake.Inject(storetest.Rule{
		Op:    storetest.OpPutIfAbsent,
		Call:  1,
		Count: 10,
		Fault: storetest.Fault{Status: 500, Code: "InternalError"},
	})

	work := t.TempDir()
	runLocalGit(t, work, "init", "-q", "-b", "main")
	runLocalGit(t, work, "config", "user.email", "test@example.com")
	runLocalGit(t, work, "config", "user.name", "Test")
	runLocalGit(t, work, "commit", "-q", "--allow-empty", "-m", "initial")

	pushCmd := exec.Command("git", "push", s.repoURL, "main")
	pushCmd.Dir = work
	pushCmd.Env = e2eGitEnv()
	out, err := pushCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("git push succeeded despite injected storage fault on ref tx PUT:\n%s", out)
	}

	// Ref was NOT moved in bare repo.
	verifyCmd := exec.Command("git", "--git-dir="+s.repoPath, "rev-parse", "--verify", "refs/heads/main")
	verifyCmd.Env = e2eGitEnv()
	if refOut, verifyErr := verifyCmd.CombinedOutput(); verifyErr == nil {
		t.Fatalf("refs/heads/main moved despite storage fault:\n%s", refOut)
	}
}

// TestServeEndToEndStorageFaultOnLeaseListBlocksPush verifies that an error
// listing stream transactions in Leases.Open refuses the push end to end.
func TestServeEndToEndStorageFaultOnLeaseListBlocksPush(t *testing.T) {
	s := bootE2EServer(t)

	s.fake.Inject(storetest.Rule{
		Op:    storetest.OpList,
		Key:   "prefix/" + journal.TxPrefix(journal.StreamID("repo")),
		Call:  1,
		Count: 10,
		Fault: storetest.Fault{Status: 500, Code: "InternalError"},
	})

	work := t.TempDir()
	runLocalGit(t, work, "init", "-q", "-b", "main")
	runLocalGit(t, work, "config", "user.email", "test@example.com")
	runLocalGit(t, work, "config", "user.name", "Test")
	runLocalGit(t, work, "commit", "-q", "--allow-empty", "-m", "initial")

	pushCmd := exec.Command("git", "push", s.repoURL, "main")
	pushCmd.Dir = work
	pushCmd.Env = e2eGitEnv()
	out, err := pushCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("git push succeeded despite injected storage fault on lease LIST:\n%s", out)
	}

	// Ref was NOT moved in bare repo.
	verifyCmd := exec.Command("git", "--git-dir="+s.repoPath, "rev-parse", "--verify", "refs/heads/main")
	verifyCmd.Env = e2eGitEnv()
	if refOut, verifyErr := verifyCmd.CombinedOutput(); verifyErr == nil {
		t.Fatalf("refs/heads/main moved despite storage fault:\n%s", refOut)
	}

	if got, want := s.txCount(), 0; got != want {
		t.Errorf("tx count after failed lease list = %d, want %d", got, want)
	}
}

// TestServeEndToEndDFConflictLeavesNoJournalRecord is WALD-46's proof
// for direction 2 driven through the real git client end-to-end:
// a push that git refuses due to a directory/file conflict leaves NO
// ref transaction in the journal claiming it happened.
func TestServeEndToEndDFConflictLeavesNoJournalRecord(t *testing.T) {
	s := bootE2EServer(t)

	work := t.TempDir()
	runLocalGit(t, work, "init", "-q", "-b", "main")
	runLocalGit(t, work, "config", "user.email", "test@example.com")
	runLocalGit(t, work, "config", "user.name", "Test")
	runLocalGit(t, work, "commit", "-q", "--allow-empty", "-m", "initial")
	runLocalGit(t, work, "branch", "feature")
	runLocalGit(t, work, "push", "-q", s.repoURL, "feature")

	if got, want := s.txCount(), 1; got != want {
		t.Fatalf("tx count after setup push = %d, want %d", got, want)
	}

	// Single-ref D/F conflict: refs/heads/feature exists; push refs/heads/feature/x
	pushCmd := exec.Command("git", "push", s.repoURL, "feature:refs/heads/feature/x")
	pushCmd.Dir = work
	pushCmd.Env = e2eGitEnv()
	out, err := pushCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("push of refs/heads/feature/x succeeded despite refs/heads/feature already existing:\n%s", out)
	}

	// Direction 2 invariant: no ref transaction was written claiming feature/x moved
	if got, want := s.txCount(), 1; got != want {
		t.Errorf("tx count after the refused D/F push = %d, want %d (no ref transaction recorded)", got, want)
	}

	// The conflicting ref was NOT created in bare repo
	verifyCmd := exec.Command("git", "--git-dir="+s.repoPath, "rev-parse", "--verify", "refs/heads/feature/x")
	verifyCmd.Env = e2eGitEnv()
	if refOut, verifyErr := verifyCmd.CombinedOutput(); verifyErr == nil {
		t.Fatalf("refs/heads/feature/x exists in bare repo after refused D/F push:\n%s", refOut)
	}
}

// TestServeEndToEndBatchDFConflictLeavesNoJournalRecord verifies that
// pushing conflicting D/F refs within a single push command is refused
// and leaves no journal records for the collided refs.
func TestServeEndToEndBatchDFConflictLeavesNoJournalRecord(t *testing.T) {
	s := bootE2EServer(t)

	work := t.TempDir()
	runLocalGit(t, work, "init", "-q", "-b", "main")
	runLocalGit(t, work, "config", "user.email", "test@example.com")
	runLocalGit(t, work, "config", "user.name", "Test")
	runLocalGit(t, work, "commit", "-q", "--allow-empty", "-m", "initial")

	// Push both feature and feature/x in one push via refspecs
	pushCmd := exec.Command("git", "push", s.repoURL, "HEAD:refs/heads/feature", "HEAD:refs/heads/feature/x")
	pushCmd.Dir = work
	pushCmd.Env = e2eGitEnv()
	out, err := pushCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("batch push of colliding D/F refs succeeded, want refusal:\n%s", out)
	}

	// No ref transactions recorded
	if got, want := s.txCount(), 0; got != want {
		t.Errorf("tx count after batch D/F push = %d, want %d", got, want)
	}
}

// TestServeEndToEndStaleRefPushLeavesNoJournalRecord verifies that
// a push with a stale old_oid (losing a concurrent push race) is refused
// and leaves no ref transaction in the journal.
func TestServeEndToEndStaleRefPushLeavesNoJournalRecord(t *testing.T) {
	s := bootE2EServer(t)

	work := t.TempDir()
	runLocalGit(t, work, "init", "-q", "-b", "main")
	runLocalGit(t, work, "config", "user.email", "test@example.com")
	runLocalGit(t, work, "config", "user.name", "Test")
	runLocalGit(t, work, "commit", "-q", "--allow-empty", "-m", "first")
	runLocalGit(t, work, "push", "-q", s.repoURL, "main")

	if got, want := s.txCount(), 1; got != want {
		t.Fatalf("tx count after setup push = %d, want %d", got, want)
	}

	// Clone to a second working directory to create a divergence (stale race)
	work2 := t.TempDir()
	runLocalGit(t, work2, "clone", "-q", s.repoURL, ".")
	runLocalGit(t, work2, "config", "user.email", "test@example.com")
	runLocalGit(t, work2, "config", "user.name", "Test")

	// Advance main in work1 and push
	runLocalGit(t, work, "commit", "-q", "--allow-empty", "-m", "second from work1")
	runLocalGit(t, work, "push", "-q", s.repoURL, "main")

	if got, want := s.txCount(), 2; got != want {
		t.Fatalf("tx count after second push = %d, want %d", got, want)
	}

	// In work2 (stale base), commit and try to push without pulling
	runLocalGit(t, work2, "commit", "-q", "--allow-empty", "-m", "divergent from work2")
	pushCmd := exec.Command("git", "push", s.repoURL, "main")
	pushCmd.Dir = work2
	pushCmd.Env = e2eGitEnv()
	out, err := pushCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("push from work2 with stale base succeeded, want rejection:\n%s", out)
	}

	// Still only 2 ref transactions; the rejected stale push left no ref tx
	if got, want := s.txCount(), 2; got != want {
		t.Errorf("tx count after stale push rejection = %d, want %d", got, want)
	}
}
