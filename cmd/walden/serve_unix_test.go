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
	// "feature", not "main": git's own receive.denyDeleteCurrent refuses
	// deleting the branch the bare repo's HEAD points to, which would
	// fail this push before the hook is ever asked to parse it, and this
	// test is about the hook, not that unrelated git default.
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
