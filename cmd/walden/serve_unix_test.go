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
// client: a push, then a clone, against a repository that already exists.
// Driving githttp.Handler directly in-process (as every other handler
// test in this codebase does) is exactly what let WALD-112's gap go
// unnoticed -- runServe never actually called net.Listen or
// (*http.Server).Serve -- so this test must go through a socket. It
// deliberately does not exercise create-on-push; that gap is WALD-111's.
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

	// Clone it back over the same socket.
	cloneDir := filepath.Join(t.TempDir(), "clone")
	runLocalGit(t, tmpDir, "clone", "-q", repoURL, cloneDir)
	cloneHead := strings.TrimSpace(runLocalGit(t, cloneDir, "rev-parse", "HEAD"))
	if cloneHead != sha {
		t.Fatalf("clone HEAD = %q, want %q", cloneHead, sha)
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
