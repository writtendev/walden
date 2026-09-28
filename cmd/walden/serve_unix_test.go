//go:build unix

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/store/storetest"
)

// e2eGitEnv returns a minimal, isolated environment for a git process
// exec'd by this test: just PATH (so git can be found), GIT_TERMINAL_PROMPT
// so a bad credential never blocks on a prompt, and GIT_CONFIG_GLOBAL /
// GIT_CONFIG_SYSTEM pinned to /dev/null so neither the walden server nor
// the git client it drives depends on whatever git config happens to be
// installed on the machine running the suite. No WALDEN_* variable is set:
// the server under test must resolve everything from --data-dir and
// --listen alone.
func e2eGitEnv() []string {
	env := []string{
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
	}
	if p := os.Getenv("PATH"); p != "" {
		env = append(env, "PATH="+p)
	}
	return env
}

// runLocalGit runs git in dir and fails the test on error. dir must be a
// real directory, never the test process's own working directory, so the
// command can't pick up a repository's local git config by accident.
func runLocalGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = e2eGitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// waitForServerBoot scans a walden serve subprocess's stdout for the
// admin-token line and the start line, and returns the minted token and
// the bound address parsed out of the start line ("walden server starting
// on <addr> (data: ..., git: ...)"). It fails the test if boot does not
// complete within 10s, or if the start line appears before any admin
// token line.
func waitForServerBoot(t *testing.T, stdout io.Reader) (adminToken, addr string) {
	t.Helper()

	const (
		tokenPrefix = "admin token: "
		startPrefix = "walden server starting on "
	)

	type bootResult struct {
		token, addr string
		err         error
	}
	resultCh := make(chan bootResult, 1)

	go func() {
		scanner := bufio.NewScanner(stdout)
		var token string
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case strings.HasPrefix(line, tokenPrefix):
				token = strings.TrimPrefix(line, tokenPrefix)
			case strings.HasPrefix(line, startPrefix):
				fields := strings.Fields(strings.TrimPrefix(line, startPrefix))
				if len(fields) == 0 {
					resultCh <- bootResult{err: fmt.Errorf("could not parse address out of start line %q", line)}
					return
				}
				resultCh <- bootResult{token: token, addr: fields[0]}
				return
			}
		}
		resultCh <- bootResult{err: fmt.Errorf("stdout closed before the start line appeared (scan err: %v)", scanner.Err())}
	}()

	select {
	case res := <-resultCh:
		if res.err != nil {
			t.Fatalf("waiting for walden serve to boot: %v", res.err)
		}
		if res.token == "" {
			t.Fatalf("walden serve printed its start line before an admin token line")
		}
		return res.token, res.addr
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for walden serve to boot")
		return "", ""
	}
}

// TestServeEndToEndCloneAndPush builds the real walden binary, starts it
// as a subprocess bound to a real socket, and drives it with the real git
// client: a create push, an update push, a branch creation and its own
// deletion, then a clone, against a repository that already exists.
// Driving githttp.Handler directly in-process (as every other handler
// test in this codebase does) is exactly what let WALD-112's gap go
// unnoticed -- runServe never actually called net.Listen or
// (*http.Server).Serve -- so this test must go through a socket. The three
// push shapes are what exercise the real pre-receive hook (WALD-43,
// dispatched by argv[0] via the hooks/pre-receive symlink below) against
// git's actual stdin, rather than a line this suite constructs by hand --
// a hook that mis-parses it fails here, not only in prereceive_test.go's
// mocks. It deliberately does not exercise create-on-push; that gap is
// WALD-111's.
func TestServeEndToEndCloneAndPush(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "walden")

	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

	dataDir := t.TempDir()
	repoPath := filepath.Join(dataDir, "repo.git")

	// Build the bare repository by hand, mirroring store.CreateRepo: a
	// bare repo whose hooks/pre-receive is a symlink to the walden
	// binary, dispatched by argv[0] (main.go's "if prog == pre-receive"
	// branch), not a shell shim.
	runLocalGit(t, tmpDir, "init", "-q", "--bare", "--initial-branch=main", repoPath)
	hooksDir := filepath.Join(repoPath, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatalf("mkdir hooks dir: %v", err)
	}
	if err := os.Symlink(binPath, filepath.Join(hooksDir, "pre-receive")); err != nil {
		t.Fatalf("symlink pre-receive hook: %v", err)
	}

	cmd := exec.Command(binPath, "serve", "--data-dir", dataDir, "--listen", "127.0.0.1:0")
	cmd.Env = e2eGitEnv()

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		t.Fatalf("start walden serve: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			// Best-effort: if the test already exited cleanly this is a
			// no-op against a dead process. If SIGINT below didn't take,
			// this is what keeps a hung walden serve from outliving the
			// test binary.
			cmd.Process.Kill()
			cmd.Wait()
		}
	})

	adminToken, addr := waitForServerBoot(t, stdoutPipe)

	// Push a real commit from a scratch work tree to the existing repo.
	work := t.TempDir()
	runLocalGit(t, work, "init", "-q", "-b", "main")
	runLocalGit(t, work, "config", "user.email", "test@example.com")
	runLocalGit(t, work, "config", "user.name", "Test")
	runLocalGit(t, work, "commit", "-q", "--allow-empty", "-m", "initial")
	sha := strings.TrimSpace(runLocalGit(t, work, "rev-parse", "HEAD"))

	repoURL := fmt.Sprintf("http://walden:%s@%s/repo", adminToken, addr)
	runLocalGit(t, work, "push", "-q", repoURL, "main")

	gotRef := strings.TrimSpace(runLocalGit(t, tmpDir, "--git-dir="+repoPath, "rev-parse", "refs/heads/main"))
	if gotRef != sha {
		t.Fatalf("bare repo refs/heads/main = %q, want %q", gotRef, sha)
	}

	// A second push to the same branch exercises the pre-receive hook's
	// other two triple shapes (WALD-43's parseRefUpdates/resolveHook are
	// exercised by a mock everywhere else; this end-to-end test is what
	// catches a hook that mis-parses git's own stdin). First an update:
	// old_oid is now sha, not the all-zero creation OID.
	runLocalGit(t, work, "commit", "-q", "--allow-empty", "-m", "second")
	sha2 := strings.TrimSpace(runLocalGit(t, work, "rev-parse", "HEAD"))
	runLocalGit(t, work, "push", "-q", repoURL, "main")

	gotRef2 := strings.TrimSpace(runLocalGit(t, tmpDir, "--git-dir="+repoPath, "rev-parse", "refs/heads/main"))
	if gotRef2 != sha2 {
		t.Fatalf("bare repo refs/heads/main after update = %q, want %q", gotRef2, sha2)
	}

	// Then a branch creation and its own deletion -- new_oid all-zero.
	// "feature", not "main": before WALD-128, git's own
	// receive.denyDeleteCurrent would have refused deleting the branch
	// the bare repo's HEAD points to, before the hook was ever asked to
	// parse it, and this test is about the hook, not that git default.
	// WALD-128 pins denyDeleteCurrent off on walden's own receive-pack
	// invocation (internal/githttp/receivepack.go) -- deleting "main"
	// itself would work today -- but "feature" stays: this test is still
	// about the hook parsing an ordinary create/update/delete sequence.
	// internal/githttp/receivepack_test.go's TestReceivePackDenyKnobsPinnedOff
	// is where deleting the current branch and force-pushing are the point.
	runLocalGit(t, work, "branch", "feature")
	runLocalGit(t, work, "push", "-q", repoURL, "feature")
	gotFeatureRef := strings.TrimSpace(runLocalGit(t, tmpDir, "--git-dir="+repoPath, "rev-parse", "refs/heads/feature"))
	if gotFeatureRef != sha2 {
		t.Fatalf("bare repo refs/heads/feature = %q, want %q", gotFeatureRef, sha2)
	}

	runLocalGit(t, work, "push", "-q", repoURL, "--delete", "feature")
	verifyFeature := exec.Command("git", "--git-dir="+repoPath, "rev-parse", "--verify", "refs/heads/feature")
	verifyFeature.Env = e2eGitEnv()
	if out, err := verifyFeature.CombinedOutput(); err == nil {
		t.Fatalf("refs/heads/feature still resolves after delete: %s", out)
	}

	// Clone it back over the same socket.
	cloneDir := filepath.Join(t.TempDir(), "clone")
	runLocalGit(t, tmpDir, "clone", "-q", repoURL, cloneDir)
	cloneHead := strings.TrimSpace(runLocalGit(t, cloneDir, "rev-parse", "HEAD"))
	if cloneHead != sha2 {
		t.Fatalf("clone HEAD = %q, want %q", cloneHead, sha2)
	}

	// Send the shutdown signal and wait for a clean exit before
	// inspecting stderr: os/exec's Wait only returns once all output
	// copying has finished, so reading stderrBuf only after Wait avoids
	// racing the copy goroutine that fills it.
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("signal SIGINT: %v", err)
	}
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()
	select {
	case err := <-waitErr:
		if err != nil {
			t.Errorf("expected walden serve to exit 0 after SIGINT, got: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("walden serve did not exit within 10s of SIGINT")
	}

	const warning = "walden: WARNING: journal-less mode: WALDEN_JOURNAL is unset, so durability is this disk alone"
	if got := strings.Count(stderrBuf.String(), warning); got != 1 {
		t.Errorf("expected the journal-less warning exactly once on stderr, got %d:\n%s", got, stderrBuf.String())
	}
}

// TestServeEndToEndJournalsEveryPush is the only test that proves the
// whole write path on the real binaries: `walden serve` as a subprocess
// with a journal configured, the real git client pushing over a real
// socket, the real pre-receive hook dispatched by argv[0], and a real
// object storage endpoint underneath. Every other WALD-44 test builds its
// quarantine directory by hand and would go on passing if git stopped
// leaving a packfile there at all -- which is exactly what git's default
// receive.unpackLimit makes it do.
//
// It walks the same four push shapes as TestServeEndToEndCloneAndPush,
// and each one lands a ref transaction in sequence:
//
//  0. create        -- new objects, so a segment
//  1. fast-forward  -- new objects, so a segment
//  2. branch create -- points at an object the repo already holds, so
//     git writes the 32-byte zero-object pack and there
//     is no segment
//  3. branch delete -- no quarantine directory at all, so no segment
func TestServeEndToEndJournalsEveryPush(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "walden")

	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

	fake := storetest.New(t)
	journalURL := journalTestJournalURL(fake)

	dataDir := t.TempDir()
	repoPath := filepath.Join(dataDir, "repo.git")
	runLocalGit(t, tmpDir, "init", "-q", "--bare", "--initial-branch=main", repoPath)
	hooksDir := filepath.Join(repoPath, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatalf("mkdir hooks dir: %v", err)
	}
	if err := os.Symlink(binPath, filepath.Join(hooksDir, "pre-receive")); err != nil {
		t.Fatalf("symlink pre-receive hook: %v", err)
	}

	cmd := exec.Command(binPath, "serve",
		"--data-dir", dataDir,
		"--listen", "127.0.0.1:0",
		"--journal", journalURL,
	)
	// The hook is a separate process, so it needs credentials of its
	// own: handleReceivePack forwards exactly these names from the
	// server's environment into the hook's.
	cmd.Env = append(e2eGitEnv(),
		"AWS_ACCESS_KEY_ID=AKIAEXAMPLE",
		"AWS_SECRET_ACCESS_KEY=topsecret",
		"AWS_REGION=us-east-1",
	)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		t.Fatalf("start walden serve: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})

	adminToken, addr := waitForServerBoot(t, stdoutPipe)

	work := t.TempDir()
	runLocalGit(t, work, "init", "-q", "-b", "main")
	runLocalGit(t, work, "config", "user.email", "test@example.com")
	runLocalGit(t, work, "config", "user.name", "Test")
	runLocalGit(t, work, "commit", "-q", "--allow-empty", "-m", "initial")
	sha := strings.TrimSpace(runLocalGit(t, work, "rev-parse", "HEAD"))

	repoURL := fmt.Sprintf("http://walden:%s@%s/repo", adminToken, addr)
	runLocalGit(t, work, "push", "-q", repoURL, "main")

	runLocalGit(t, work, "commit", "-q", "--allow-empty", "-m", "second")
	sha2 := strings.TrimSpace(runLocalGit(t, work, "rev-parse", "HEAD"))
	runLocalGit(t, work, "push", "-q", repoURL, "main")

	runLocalGit(t, work, "branch", "feature")
	runLocalGit(t, work, "push", "-q", repoURL, "feature")
	runLocalGit(t, work, "push", "-q", repoURL, "--delete", "feature")

	const stream = journal.StreamID("repo")
	want := []struct {
		name        string
		wantSegment bool
		updates     []journal.RefUpdate
	}{
		{
			name:        "create",
			wantSegment: true,
			updates:     []journal.RefUpdate{{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: sha}},
		},
		{
			name:        "fast-forward",
			wantSegment: true,
			updates:     []journal.RefUpdate{{Ref: "refs/heads/main", OldOID: sha, NewOID: sha2}},
		},
		{
			name:        "branch create pointing at an object already present",
			wantSegment: false,
			updates:     []journal.RefUpdate{{Ref: "refs/heads/feature", OldOID: journal.ZeroOID40, NewOID: sha2}},
		},
		{
			name:        "branch delete",
			wantSegment: false,
			updates:     []journal.RefUpdate{{Ref: "refs/heads/feature", OldOID: sha2, NewOID: journal.ZeroOID40}},
		},
	}

	for seq, tt := range want {
		rec := journalRefTx(t, fake, stream, journal.Seq(seq))
		if tt.wantSegment {
			if len(rec.Segments) != 1 {
				t.Errorf("tx %d (%s): segments = %v, want exactly one", seq, tt.name, rec.Segments)
			} else if _, ok := fake.Object("prefix/" + journal.SegmentKey(stream, rec.Segments[0])); !ok {
				t.Errorf("tx %d (%s): names segment %s, which is not in the bucket", seq, tt.name, rec.Segments[0])
			}
		} else if len(rec.Segments) != 0 {
			t.Errorf("tx %d (%s): segments = %v, want an empty array: this push introduced no objects", seq, tt.name, rec.Segments)
		}
		if len(rec.Updates) != len(tt.updates) {
			t.Errorf("tx %d (%s): updates = %+v, want %+v", seq, tt.name, rec.Updates, tt.updates)
			continue
		}
		for i := range tt.updates {
			if rec.Updates[i] != tt.updates[i] {
				t.Errorf("tx %d (%s): update[%d] = %+v, want %+v", seq, tt.name, i, rec.Updates[i], tt.updates[i])
			}
		}
	}

	// Exactly four ref transactions: a fifth would mean a push was
	// journaled twice, and a missing one would mean a push slipped by
	// unjournaled.
	txPrefix := "prefix/" + journal.TxPrefix(stream)
	got := 0
	for _, k := range fake.Keys() {
		if strings.HasPrefix(k, txPrefix) {
			got++
		}
	}
	if got != len(want) {
		t.Errorf("stream %q holds %d ref transactions, want %d", stream, got, len(want))
	}

	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("signal SIGINT: %v", err)
	}
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()
	select {
	case err := <-waitErr:
		if err != nil {
			t.Errorf("expected walden serve to exit 0 after SIGINT, got: %v\n%s", err, stderrBuf.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("walden serve did not exit within 10s of SIGINT")
	}
}

// e2eServer is one booted `walden serve` subprocess for a WALD-128
// end-to-end test: a fake object storage endpoint underneath, a real bare
// repository with the real pre-receive hook symlinked in
// (hooks/pre-receive, dispatched by argv[0] the same way store.CreateRepo
// leaves it), and the address and admin token a real git client needs to
// push to it.
type e2eServer struct {
	fake     *storetest.Fake
	repoPath string
	repoURL  string
	cmd      *exec.Cmd
	stderr   *strings.Builder
}

// bootE2EServer builds the real walden binary, starts it as a subprocess
// bound to a real socket with a journal configured against a fresh fake
// object store, and creates one bare repository (named repo) with the
// real pre-receive hook already installed -- the shared setup every
// WALD-128 end-to-end test in this file starts from. t.Cleanup stops the
// server; the caller drives it with runLocalGit against repoURL exactly
// as the pre-existing TestServeEndToEnd* tests above do.
func bootE2EServer(t *testing.T) *e2eServer {
	t.Helper()

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "walden")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

	fake := storetest.New(t)
	journalURL := journalTestJournalURL(fake)

	dataDir := t.TempDir()
	repoPath := filepath.Join(dataDir, "repo.git")
	runLocalGit(t, tmpDir, "init", "-q", "--bare", "--initial-branch=main", repoPath)
	hooksDir := filepath.Join(repoPath, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatalf("mkdir hooks dir: %v", err)
	}
	if err := os.Symlink(binPath, filepath.Join(hooksDir, "pre-receive")); err != nil {
		t.Fatalf("symlink pre-receive hook: %v", err)
	}

	cmd := exec.Command(binPath, "serve",
		"--data-dir", dataDir,
		"--listen", "127.0.0.1:0",
		"--journal", journalURL,
	)
	cmd.Env = append(e2eGitEnv(),
		"AWS_ACCESS_KEY_ID=AKIAEXAMPLE",
		"AWS_SECRET_ACCESS_KEY=topsecret",
		"AWS_REGION=us-east-1",
	)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		t.Fatalf("start walden serve: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})

	adminToken, addr := waitForServerBoot(t, stdoutPipe)
	repoURL := fmt.Sprintf("http://walden:%s@%s/repo", adminToken, addr)

	return &e2eServer{fake: fake, repoPath: repoPath, repoURL: repoURL, cmd: cmd, stderr: &stderrBuf}
}

// txCount returns how many ref-transaction records this server's stream
// "repo" currently holds in the bucket.
func (s *e2eServer) txCount() int {
	prefix := "prefix/" + journal.TxPrefix(journal.StreamID("repo"))
	n := 0
	for _, k := range s.fake.Keys() {
		if strings.HasPrefix(k, prefix) {
			n++
		}
	}
	return n
}

// segmentCount returns how many segments this server's stream "repo"
// currently holds in the bucket.
func (s *e2eServer) segmentCount() int {
	prefix := "prefix/" + journal.SegmentPrefix(journal.StreamID("repo"))
	n := 0
	for _, k := range s.fake.Keys() {
		if strings.HasPrefix(k, prefix) {
			n++
		}
	}
	return n
}

// TestServeEndToEndSingleRefDFConflictRefusesUnjournaled is WALD-128
// Done-when 5: a single-ref push whose only ref collides as a directory
// and a file against an existing ref (refs/heads/feature already exists;
// this push creates refs/heads/feature/x) is refused before it is ever
// journaled: after it, the bucket's tx/ prefix must hold exactly the one
// record the setup push left behind, no more.
func TestServeEndToEndSingleRefDFConflictRefusesUnjournaled(t *testing.T) {
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

	pushCmd := exec.Command("git", "push", s.repoURL, "feature:refs/heads/feature/x")
	pushCmd.Dir = work
	pushCmd.Env = e2eGitEnv()
	out, err := pushCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("push of refs/heads/feature/x succeeded despite refs/heads/feature already existing:\n%s", out)
	}

	if got, want := s.txCount(), 1; got != want {
		t.Errorf("tx count after the refused D/F push = %d, want %d (nothing journaled)", got, want)
	}
}

// TestServeEndToEndNoRefAppliesJournalsSegmentOnly is WALD-128 Done-when
// 9: a push whose pack carries a genuinely new object, but whose single
// ref cannot apply (the same D/F conflict as above, with a fresh commit
// as the new ref's target so index-pack leaves a real, non-empty pack in
// quarantine) journals that segment -- the objects are really in the
// store regardless of what happens to the ref, confirmed independently
// against git 2.50.1 -- and no ref transaction, leaving git to refuse the
// ref with its own message. Segment and tx counts are both taken before
// and after the test push, not asserted as absolute totals: the setup
// push above carries the initial commit's own objects and so already
// leaves one segment of its own.
func TestServeEndToEndNoRefAppliesJournalsSegmentOnly(t *testing.T) {
	s := bootE2EServer(t)

	work := t.TempDir()
	runLocalGit(t, work, "init", "-q", "-b", "main")
	runLocalGit(t, work, "config", "user.email", "test@example.com")
	runLocalGit(t, work, "config", "user.name", "Test")
	runLocalGit(t, work, "commit", "-q", "--allow-empty", "-m", "initial")
	runLocalGit(t, work, "branch", "feature")
	runLocalGit(t, work, "push", "-q", s.repoURL, "feature")

	baseTx, baseSeg := s.txCount(), s.segmentCount()

	runLocalGit(t, work, "commit", "-q", "--allow-empty", "-m", "new object for feature/x")
	pushCmd := exec.Command("git", "push", s.repoURL, "HEAD:refs/heads/feature/x")
	pushCmd.Dir = work
	pushCmd.Env = e2eGitEnv()
	out, err := pushCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("push of refs/heads/feature/x succeeded despite refs/heads/feature already existing:\n%s", out)
	}

	if got, want := s.txCount(), baseTx; got != want {
		t.Errorf("tx count after the refused D/F push = %d, want %d (no ref transaction)", got, want)
	}
	if got, want := s.segmentCount(), baseSeg+1; got != want {
		t.Errorf("segment count after the refused D/F push = %d, want %d (the new commit's objects are real regardless)", got, want)
	}
}

// TestServeEndToEndDFConflictRefusedWholeBothOrders is WALD-128 Done-when 8
// as its 2026-09-28 amendment rewrote it: a push naming two refs that
// collide as a directory and a file is refused whole, in one line, with
// nothing journaled for it, in either wire order.
//
// This test used to assert the other thing -- that walden journaled
// exactly the one ref git applied -- and it is the test that caught the
// problem with that: git 2.50.1 applies whichever of the two came first on
// the wire, and git 2.55.0 applies refs/heads/feature/x in both orders, so
// there is no stable answer for walden to match. It keeps both orders for
// that reason: the expectation now has to be the same one either way, and
// a version that guessed a winner would still pass one of these two cases.
func TestServeEndToEndDFConflictRefusedWholeBothOrders(t *testing.T) {
	tests := []struct {
		name     string
		refspecs []string
	}{
		{
			name:     "parent first",
			refspecs: []string{"HEAD:refs/heads/feature", "HEAD:refs/heads/feature/x"},
		},
		{
			name:     "child first",
			refspecs: []string{"HEAD:refs/heads/feature/x", "HEAD:refs/heads/feature"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := bootE2EServer(t)

			work := t.TempDir()
			runLocalGit(t, work, "init", "-q", "-b", "main")
			runLocalGit(t, work, "config", "user.email", "test@example.com")
			runLocalGit(t, work, "config", "user.name", "Test")
			runLocalGit(t, work, "commit", "-q", "--allow-empty", "-m", "initial")

			args := append([]string{"push", s.repoURL}, tt.refspecs...)
			pushCmd := exec.Command("git", args...)
			pushCmd.Dir = work
			pushCmd.Env = e2eGitEnv()
			out, err := pushCmd.CombinedOutput()
			if err == nil {
				t.Fatalf("push %v succeeded, want the whole push refused:\n%s", tt.refspecs, out)
			}
			if !strings.Contains(string(out), "one ref name is a directory prefix of the other") {
				t.Errorf("push output does not carry walden's D/F refusal:\n%s", out)
			}

			for _, ref := range []string{"refs/heads/feature", "refs/heads/feature/x"} {
				verify := exec.Command("git", "--git-dir="+s.repoPath, "rev-parse", "--verify", "--quiet", ref)
				verify.Env = e2eGitEnv()
				if out, err := verify.CombinedOutput(); err == nil {
					t.Errorf("%s resolves to %s after the push, want neither ref applied", ref, strings.TrimSpace(string(out)))
				}
			}

			if got := s.txCount(); got != 0 {
				t.Errorf("tx count after the refused push = %d, want 0 (nothing journaled)", got)
			}
			if got := s.segmentCount(); got != 0 {
				t.Errorf("segment count after the refused push = %d, want 0 (nothing journaled)", got)
			}
		})
	}
}

// helperStaleRefPrePush installs a pre-push hook in the *client* repository
// at workDir that moves ref in the server's repository at repoPath to sha,
// making that one refspec's old_oid stale for the push it is about to send.
//
// An ordinary, non-forced git push computes each refspec's old_oid from the
// ref advertisement it received moments earlier in the same `git push`
// invocation, so a ref has to move in the gap between that advertisement and
// the server processing the push proper. The client's own pre-push hook sits
// in exactly that gap: verified against git 2.50.1 by capturing the hook's
// stdin during a three-ref push while the hook moved one of the three --
// every line still carried the pre-move value as its old_oid, and git went
// on to apply the other two refs and report "! [remote rejected] ... (failed
// to update ref)" for the moved one, with receive-pack printing "cannot lock
// ref 'refs/heads/b': is at <moved> but expected <advertised>".
//
// `--force-with-lease` cannot reach that gap: its lease is checked
// client-side, so the stale value never reaches the server at all.
//
// The move is made straight against repoPath with `git --git-dir`, never
// through a push to walden, so it moves the ref without adding a journal
// record of its own -- the test counts transactions, and a hijack that
// journaled would be counting itself. sha must already be an object in
// repoPath for that to work; the caller gets it there first.
func helperStaleRefPrePush(t *testing.T, workDir, repoPath, ref, sha string) {
	t.Helper()
	hooksDir := filepath.Join(workDir, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatalf("mkdir client hooks dir: %v", err)
	}
	script := "#!/bin/sh\nexec git --git-dir=" + repoPath + " update-ref " + ref + " " + sha + "\n"
	if err := os.WriteFile(filepath.Join(hooksDir, "pre-push"), []byte(script), 0o755); err != nil {
		t.Fatalf("write client pre-push hook: %v", err)
	}
}

// TestServeEndToEndMidPushStaleRefJournalsAcceptedSubset is WALD-128
// Done-when 8's mid-push case: a three-ref push where the middle ref (b)
// is stale by the time the server actually processes it -- moved behind
// the push's back between the ref advertisement and pre-receive running,
// via helperStaleRefPrePush -- while the other two (a, c) are ordinary,
// independent, and unaffected. The accepted set must be exactly {a, c},
// in that order, proving the incremental loop keeps walking past a
// rejected candidate instead of stopping at the first one.
func TestServeEndToEndMidPushStaleRefJournalsAcceptedSubset(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "walden")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

	fake := storetest.New(t)
	journalURL := journalTestJournalURL(fake)

	dataDir := t.TempDir()
	repoPath := filepath.Join(dataDir, "repo.git")
	runLocalGit(t, tmpDir, "init", "-q", "--bare", "--initial-branch=main", repoPath)
	if err := os.MkdirAll(filepath.Join(repoPath, "hooks"), 0o755); err != nil {
		t.Fatalf("mkdir hooks dir: %v", err)
	}
	if err := os.Symlink(binPath, filepath.Join(repoPath, "hooks", "pre-receive")); err != nil {
		t.Fatalf("symlink pre-receive hook: %v", err)
	}

	cmd := exec.Command(binPath, "serve", "--data-dir", dataDir, "--listen", "127.0.0.1:0", "--journal", journalURL)
	cmd.Env = append(e2eGitEnv(),
		"AWS_ACCESS_KEY_ID=AKIAEXAMPLE",
		"AWS_SECRET_ACCESS_KEY=topsecret",
		"AWS_REGION=us-east-1",
	)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start walden serve: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	adminToken, addr := waitForServerBoot(t, stdoutPipe)
	repoURL := fmt.Sprintf("http://walden:%s@%s/repo", adminToken, addr)

	work := t.TempDir()
	runLocalGit(t, work, "init", "-q", "-b", "main")
	runLocalGit(t, work, "config", "user.email", "test@example.com")
	runLocalGit(t, work, "config", "user.name", "Test")
	runLocalGit(t, work, "commit", "-q", "--allow-empty", "-m", "seed")
	seedSHA := strings.TrimSpace(runLocalGit(t, work, "rev-parse", "HEAD"))
	// Seed a, b, c at the same initial commit, and a second, real, already-
	// accepted commit for the hijack to move b onto -- both objects are
	// genuinely present in the repository's own object store by the time
	// the wrapper hook runs, so its plain `git update-ref` needs nothing
	// beyond that.
	runLocalGit(t, work, "push", "-q", repoURL, "HEAD:refs/heads/a", "HEAD:refs/heads/b", "HEAD:refs/heads/c")
	runLocalGit(t, work, "commit", "-q", "--allow-empty", "-m", "hijack target for b")
	hijackSHA := strings.TrimSpace(runLocalGit(t, work, "rev-parse", "HEAD"))
	runLocalGit(t, work, "push", "-q", repoURL, "HEAD:refs/heads/scratch")
	runLocalGit(t, work, "push", "-q", repoURL, "--delete", "scratch")

	baseTx := 0
	for _, k := range fake.Keys() {
		if strings.HasPrefix(k, "prefix/"+journal.TxPrefix("repo")) {
			baseTx++
		}
	}

	// Advance a, b, c locally by one commit each, from the seeded state.
	runLocalGit(t, work, "reset", "-q", "--hard", seedSHA)
	runLocalGit(t, work, "commit", "-q", "--allow-empty", "-m", "advance a")
	shaA := strings.TrimSpace(runLocalGit(t, work, "rev-parse", "HEAD"))
	runLocalGit(t, work, "reset", "-q", "--hard", seedSHA)
	runLocalGit(t, work, "commit", "-q", "--allow-empty", "-m", "advance b (will be refused: stale)")
	shaB := strings.TrimSpace(runLocalGit(t, work, "rev-parse", "HEAD"))
	runLocalGit(t, work, "reset", "-q", "--hard", seedSHA)
	runLocalGit(t, work, "commit", "-q", "--allow-empty", "-m", "advance c")
	shaC := strings.TrimSpace(runLocalGit(t, work, "rev-parse", "HEAD"))

	// Install the client's pre-push hook now, right before the real push:
	// it moves b to hijackSHA after this push's ref advertisement has
	// already given the client b's old value, and before the client sends
	// the commands built from it.
	helperStaleRefPrePush(t, work, repoPath, "refs/heads/b", hijackSHA)

	pushCmd := exec.Command("git", "push", repoURL,
		shaA+":refs/heads/a", shaB+":refs/heads/b", shaC+":refs/heads/c")
	pushCmd.Dir = work
	pushCmd.Env = e2eGitEnv()
	out, err := pushCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("push succeeded, want b's stale old_oid to cause a partial failure:\n%s", out)
	}

	gotA := strings.TrimSpace(runLocalGit(t, work, "--git-dir="+repoPath, "rev-parse", "refs/heads/a"))
	if gotA != shaA {
		t.Errorf("refs/heads/a = %q after the push, want %q (applied)", gotA, shaA)
	}
	gotB := strings.TrimSpace(runLocalGit(t, work, "--git-dir="+repoPath, "rev-parse", "refs/heads/b"))
	if gotB != hijackSHA {
		t.Errorf("refs/heads/b = %q after the push, want %q (the hijack, left untouched by the refused push)", gotB, hijackSHA)
	}
	gotC := strings.TrimSpace(runLocalGit(t, work, "--git-dir="+repoPath, "rev-parse", "refs/heads/c"))
	if gotC != shaC {
		t.Errorf("refs/heads/c = %q after the push, want %q (applied)", gotC, shaC)
	}

	newTx := 0
	for _, k := range fake.Keys() {
		if strings.HasPrefix(k, "prefix/"+journal.TxPrefix("repo")) {
			newTx++
		}
	}
	if newTx != baseTx+1 {
		t.Fatalf("tx count went from %d to %d, want exactly one more", baseTx, newTx)
	}
	rec := journalRefTx(t, fake, journal.StreamID("repo"), journal.Seq(newTx-1))
	assertUpdates(t, rec.Updates, []journal.RefUpdate{
		{Ref: "refs/heads/a", OldOID: seedSHA, NewOID: shaA},
		{Ref: "refs/heads/c", OldOID: seedSHA, NewOID: shaC},
	})
}

// TestServeEndToEndLockCollisionRefusesWholePush drives WALD-128's
// decided reclassification against the real binary with a real lock
// actually held: a separate `git update-ref --stdin` process, started
// directly against the bare repository (never through walden), holds
// refs/heads/main prepared -- exactly the state probePrepare's own
// isLockAcquisitionFailure exists to recognize -- while a real client
// push to that same ref goes through walden's HTTP server. The whole
// push must be refused, in one line, and nothing journaled for it: a
// lock collision must never be read as git saying no.
func TestServeEndToEndLockCollisionRefusesWholePush(t *testing.T) {
	s := bootE2EServer(t)

	work := t.TempDir()
	runLocalGit(t, work, "init", "-q", "-b", "main")
	runLocalGit(t, work, "config", "user.email", "test@example.com")
	runLocalGit(t, work, "config", "user.name", "Test")
	runLocalGit(t, work, "commit", "-q", "--allow-empty", "-m", "initial")
	sha1 := strings.TrimSpace(runLocalGit(t, work, "rev-parse", "HEAD"))
	runLocalGit(t, work, "push", "-q", s.repoURL, "main")

	if got, want := s.txCount(), 1; got != want {
		t.Fatalf("tx count after setup push = %d, want %d", got, want)
	}

	runLocalGit(t, work, "commit", "-q", "--allow-empty", "-m", "second")
	sha2 := strings.TrimSpace(runLocalGit(t, work, "rev-parse", "HEAD"))

	holder := exec.Command("git", "update-ref", "--stdin")
	holder.Dir = s.repoPath
	holder.Env = append(e2eGitEnv(), "GIT_DIR=.")
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
	if _, err := stdin.Write([]byte("start\nupdate refs/heads/main " + sha1 + " " + sha1 + "\nprepare\n")); err != nil {
		t.Fatalf("write to lock holder: %v", err)
	}
	lockPath := filepath.Join(s.repoPath, "refs", "heads", "main.lock")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(lockPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("lock holder never appears to have taken refs/heads/main.lock")
		}
		time.Sleep(10 * time.Millisecond)
	}

	pushCmd := exec.Command("git", "push", s.repoURL, "main")
	pushCmd.Dir = work
	pushCmd.Env = e2eGitEnv()
	out, err := pushCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("push succeeded while refs/heads/main.lock was held, want a refusal:\n%s", out)
	}
	if !strings.Contains(string(out), "could not determine whether git will accept this push") {
		t.Errorf("push output does not mention the lock-collision refusal:\n%s", out)
	}

	if got, want := s.txCount(), 1; got != want {
		t.Errorf("tx count after the lock-collision push = %d, want %d (nothing journaled)", got, want)
	}

	stdin.Write([]byte("abort\n"))
	stdin.Close()
	if err := holder.Wait(); err != nil {
		t.Logf("lock holder exit: %v", err)
	}

	// With the lock released, an ordinary retry of the same push must now
	// succeed and journal normally -- proving the refusal above was
	// genuinely about the transient lock, not a real problem with the
	// update itself.
	retry := exec.Command("git", "push", s.repoURL, "main")
	retry.Dir = work
	retry.Env = e2eGitEnv()
	if out, err := retry.CombinedOutput(); err != nil {
		t.Fatalf("retry after the lock was released failed: %v\n%s", err, out)
	}
	gotRef := strings.TrimSpace(runLocalGit(t, work, "--git-dir="+s.repoPath, "rev-parse", "refs/heads/main"))
	if gotRef != sha2 {
		t.Errorf("refs/heads/main after the retry = %q, want %q", gotRef, sha2)
	}
	if got, want := s.txCount(), 2; got != want {
		t.Errorf("tx count after the retry = %d, want %d", got, want)
	}
}
