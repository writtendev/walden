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
