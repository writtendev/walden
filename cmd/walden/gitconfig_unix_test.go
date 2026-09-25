//go:build unix

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestServeIgnoresHostileSystemGitConfig is WALD-127's end-to-end proof.
//
// gitEnv (internal/githttp/gitcmd.go) forwards nothing to a git child but
// PATH, so a hostile GIT_CONFIG_SYSTEM set on the test process itself would
// never reach the child under test: the naive version of this test passes
// whether or not the pinning fix is present. Instead this test stands up a
// git named git in a temp dir -- a shim -- and puts that directory on the
// walden server subprocess's own PATH (in cmd.Env, never t.Setenv), so only
// the git children that subprocess execs ever see it. The shim's job is to
// reproduce, from inside that one subprocess, what a machine with a hostile
// /etc/gitconfig looks like to git: it sets GIT_CONFIG_SYSTEM to a config
// naming a decoy hooks directory, but only when GIT_CONFIG_SYSTEM is not
// already set -- exactly git's own precedence for how a real
// GIT_CONFIG_SYSTEM in the environment beats /etc/gitconfig. That is why the
// shim goes inert the instant gitEnv pins the variable: the pin is already
// "set" by the time the shim's own default would apply.
//
// The git client driving the push (runLocalGit, e2eGitEnv) never sees the
// shim: it keeps its own /dev/null pins and talks to walden over the loopback
// socket exactly as TestServeEndToEndCloneAndPush does. Only the server
// subprocess's PATH carries the shim.
func TestServeIgnoresHostileSystemGitConfig(t *testing.T) {
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("LookPath(git): %v", err)
	}

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "walden")

	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

	// The decoy: a hooks directory that is not walden's, whose pre-receive
	// drops a marker file and prints a distinctive line to stderr before
	// refusing the push. If this ever runs, the pinning failed to keep
	// /etc/gitconfig's core.hooksPath from reaching the receive-pack child.
	decoyHooksDir := filepath.Join(tmpDir, "decoy-hooks")
	if err := os.MkdirAll(decoyHooksDir, 0o755); err != nil {
		t.Fatalf("mkdir decoy hooks dir: %v", err)
	}
	decoyMarker := filepath.Join(tmpDir, "decoy-ran")
	const decoyLine = "DECOY HOOK RAN"
	decoyScript := fmt.Sprintf("#!/bin/sh\ntouch %s\necho %s >&2\nexit 1\n",
		shellQuote(decoyMarker), shellQuote(decoyLine))
	decoyHookPath := filepath.Join(decoyHooksDir, "pre-receive")
	if err := os.WriteFile(decoyHookPath, []byte(decoyScript), 0o755); err != nil {
		t.Fatalf("write decoy hook: %v", err)
	}

	// The hostile system config: what a core.hooksPath smuggled in via
	// /etc/gitconfig, or the server user's ~/.gitconfig, looks like.
	hostileConfigPath := filepath.Join(tmpDir, "hostile-gitconfig")
	hostileConfig := fmt.Sprintf("[core]\n\thooksPath = %s\n", decoyHooksDir)
	if err := os.WriteFile(hostileConfigPath, []byte(hostileConfig), 0o644); err != nil {
		t.Fatalf("write hostile system config: %v", err)
	}

	// The shim: stands in for the machine, defaulting GIT_CONFIG_SYSTEM to
	// the hostile config exactly when nothing has already pinned it.
	shimDir := filepath.Join(tmpDir, "shim")
	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		t.Fatalf("mkdir shim dir: %v", err)
	}
	// hostileConfigPath is interpolated unquoted: it sits inside a double-quoted
	// parameter expansion ("${VAR:=...}"), where a nested shell quote would be
	// taken literally rather than stripped, corrupting the path. It is safe
	// unquoted because it is t.TempDir()-derived and contains no shell
	// metacharacters or whitespace.
	shimScript := fmt.Sprintf("#!/bin/sh\n: \"${GIT_CONFIG_SYSTEM:=%s}\"\nexport GIT_CONFIG_SYSTEM\nexec %s \"$@\"\n",
		hostileConfigPath, shellQuote(realGit))
	shimPath := filepath.Join(shimDir, "git")
	if err := os.WriteFile(shimPath, []byte(shimScript), 0o755); err != nil {
		t.Fatalf("write git shim: %v", err)
	}

	// The bare repo, built the same way TestServeEndToEndCloneAndPush does:
	// hooks/pre-receive is a symlink to the walden binary, walden's own
	// correct hook. Nothing about the repository itself is malformed; the
	// only thing under test is which hook git actually runs.
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

	// Arm-check (done-when's step 3, and the single most important check in
	// this file): confirm the shim actually redirects hooks/pre-receive to
	// the decoy when nothing pins GIT_CONFIG_SYSTEM, before trusting any
	// assertion made after a real push. Without this, a shim that silently
	// failed to take effect -- a typo in the `:=`, a PATH that resolved to
	// the wrong git first -- would make the rest of this test pass
	// vacuously, pinning or no pinning.
	armCmd := exec.Command(shimPath, "-C", repoPath, "rev-parse", "--git-path", "hooks/pre-receive")
	armHome := t.TempDir()
	armCmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + armHome}
	armOut, err := armCmd.Output()
	if err != nil {
		t.Fatalf("arm-check: shim git rev-parse --git-path: %v", err)
	}
	wantArmed := filepath.Join(decoyHooksDir, "pre-receive")
	gotArmed := strings.TrimSpace(string(armOut))
	if gotArmed != wantArmed {
		t.Fatalf("arm-check: unpinned shim reports hooks/pre-receive = %q, want the decoy path %q: the shim is not reproducing a hostile system config, so this test cannot prove anything", gotArmed, wantArmed)
	}

	// Start walden serve with the shim directory first on PATH -- in this
	// subprocess's own cmd.Env only, never t.Setenv, so nothing outside this
	// one process ever sees the shim. gitEnv reads os.Getenv("PATH") from
	// inside the walden process, so every git child githttp execs --
	// including the receive-pack that runs the pre-receive hook -- inherits
	// this PATH and finds the shim before the real git.
	cmd := exec.Command(binPath, "serve", "--data-dir", dataDir, "--listen", "127.0.0.1:0")
	cmd.Env = []string{
		"PATH=" + shimDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	}

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
	pushCmd := exec.Command("git", "push", "-q", repoURL, "main")
	pushCmd.Dir = work
	pushCmd.Env = e2eGitEnv()
	pushOut, pushErr := pushCmd.CombinedOutput()
	if pushErr != nil {
		t.Fatalf("push against a pinned server subprocess should succeed (the pin must make /etc/gitconfig's core.hooksPath unreachable), got: %v\n%s", pushErr, pushOut)
	}

	if strings.Contains(string(pushOut), decoyLine) {
		t.Errorf("push output contains the decoy hook's line, so the decoy ran:\n%s", pushOut)
	}
	if _, err := os.Stat(decoyMarker); err == nil {
		t.Errorf("decoy marker file exists, so the decoy hook ran despite the pin")
	} else if !os.IsNotExist(err) {
		t.Errorf("stat decoy marker: %v", err)
	}

	gotRef := strings.TrimSpace(runLocalGit(t, tmpDir, "--git-dir="+repoPath, "rev-parse", "refs/heads/main"))
	if gotRef != sha {
		t.Fatalf("bare repo refs/heads/main = %q, want %q: walden's own hook must have run and let the push land", gotRef, sha)
	}
}

// shellQuote wraps s in single quotes for interpolation into a /bin/sh
// script, escaping any single quote s itself contains. The paths embedded
// here are all t.TempDir()-derived, so this is a portability precaution
// rather than a defense against anything adversarial.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
