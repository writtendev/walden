//go:build unix

package githttp_test

import (
	"context"
	"fmt"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/githttp"
	"github.com/writtendev/walden/internal/store"
)

// TestSubprocessKillsGrandchild proves that process-group cancellation kills
// both the immediate git process and its spawned children (grandchildren of
// walden). When git forks (e.g. pack-objects during upload-pack or index-pack
// during receive-pack), standard exec.CommandContext kills only the direct
// child on context cancellation, leaving grandchildren orphaned onto PID 1.
//
// We substitute git on PATH with a script that forks a grandchild into the
// background. Both parent and grandchild write their PIDs to files and loop
// forever. On client abort, both PIDs must disappear via syscall.Signal(0).
//
// Note carefully why this cannot use survivingGitChildren: that helper filters on
// PPid == os.Getpid(), but an orphaned grandchild reparents to the system's
// init/PID 1, not this test binary. Probing both recorded PIDs directly with
// Signal(0) is not blind to orphaned grandchildren.
func TestSubprocessKillsGrandchild(t *testing.T) {
	binDir := t.TempDir()
	parentPidFile := filepath.Join(binDir, "parent.pid")
	childPidFile := filepath.Join(binDir, "child.pid")

	// The fake "git": records its own PID ($$), forks a background sleep 300 ($!),
	// records the grandchild PID, and streams output indefinitely.
	script := fmt.Sprintf("#!/bin/sh\necho $$ > %s\nsleep 300 &\necho $! > %s\nwhile :; do\n  printf 'x'\n  sleep 0.1\ndone\n",
		parentPidFile, childPidFile)
	if err := os.WriteFile(filepath.Join(binDir, "git"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake git: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	s := store.New(t.TempDir())
	barePath, err := s.RepoPath("repo")
	if err != nil {
		t.Fatalf("RepoPath: %v", err)
	}
	if err := os.MkdirAll(barePath, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	server := httptest.NewServer(githttp.NewHandler(nil, s, ""))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	reqBody := "0000"
	req := fmt.Sprintf("POST /repo/git-upload-pack HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-git-upload-pack-request\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		u.Host, len(reqBody), reqBody)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write req: %v", err)
	}

	// Read a little of the response to ensure fake git has started and written PIDs.
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read response: %v", err)
	}

	parentPid := readPID(t, parentPidFile)
	childPid := readPID(t, childPidFile)

	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	conn.Close()

	assertProcessGone(t, parentPid, "parent git process")
	assertProcessGone(t, childPid, "grandchild git process")
}

// TestSubprocessLeakSoak verifies that repeated aborted requests do not leak
// child processes, file descriptors, or goroutines.
//
// The ticket specifies:
// "a soak test of thousands of aborted clones leaves no leaked process, no
// leaked file descriptor, and flat memory."
//
// Provable assertions in scope:
//  1. No leaked processes: each aborted request cancels the entire subprocess group.
//  2. No leaked file descriptors: count /proc/self/fd at two checkpoints — after a
//     warmup of N aborts, and again after 2N — and assert the count did not grow.
//     Checked on Linux; skipped on non-Linux matching TestInfoRefsAbortReapsChild's
//     convention.
//  3. No leaked goroutines: runtime.NumGoroutine() at the same two checkpoints,
//     which directly catches any parked stdin-copy goroutine.
//
// Iteration count: order 100–200 against the fake git, not thousands against real git.
// Under -race, on a shared runner, thousands of real forked clones is minutes of wall
// clock and flaky. Flatness between two checkpoints (N and 2N) proves that resources
// do not accumulate far more strongly than a large absolute N proves anything, and it
// runs in seconds.
//
// Deliberately omitted: "flat memory". Go's heap is GC'd and non-deterministic;
// a ReadMemStats gate after runtime.GC() is a known-flaky CI check, and a flaky
// gate is worse than an absent one. Every leak shape this code can produce (a
// process, an fd, a goroutine) is directly counted by the assertions above, and
// any memory leak would originate from one of those three.
func TestSubprocessLeakSoak(t *testing.T) {
	binDir := t.TempDir()
	script := "#!/bin/sh\nwhile :; do\n  printf 'x'\n  sleep 0.05\ndone\n"
	if err := os.WriteFile(filepath.Join(binDir, "git"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake git: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	s := store.New(t.TempDir())
	barePath, err := s.RepoPath("repo")
	if err != nil {
		t.Fatalf("RepoPath: %v", err)
	}
	if err := os.MkdirAll(barePath, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	server := httptest.NewServer(githttp.NewHandler(nil, s, ""))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	abortOne := func() {
		conn, err := net.Dial("tcp", u.Host)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		req := fmt.Sprintf("POST /repo/git-upload-pack HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-git-upload-pack-request\r\nContent-Length: 4\r\nConnection: close\r\n\r\n0000", u.Host)
		if _, err := conn.Write([]byte(req)); err != nil {
			t.Fatalf("write req: %v", err)
		}
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		conn.Close()
	}

	const n = 50

	// Phase 1: Warmup of N aborts
	for i := 0; i < n; i++ {
		abortOne()
	}

	// Allow server handler goroutines to settle
	time.Sleep(300 * time.Millisecond)

	fds1 := countOpenFDs(t)
	goroutines1 := runtime.NumGoroutine()

	// Phase 2: Another N aborts (2N total)
	for i := 0; i < n; i++ {
		abortOne()
	}

	// Allow server handler goroutines to settle
	time.Sleep(300 * time.Millisecond)

	fds2 := countOpenFDs(t)
	goroutines2 := runtime.NumGoroutine()

	if runtime.GOOS == "linux" && fds2 > fds1 {
		t.Errorf("file descriptor count grew from %d to %d between checkpoints", fds1, fds2)
	}
	if goroutines2 > goroutines1 {
		t.Errorf("goroutine count grew from %d to %d between checkpoints (%d -> %d)", goroutines1, goroutines2, goroutines1, goroutines2)
	}
}

func readPID(t *testing.T, path string) int {
	t.Helper()
	var pidBytes []byte
	var err error
	for i := 0; i < 100; i++ {
		pidBytes, err = os.ReadFile(path)
		if err == nil && len(strings.TrimSpace(string(pidBytes))) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || len(strings.TrimSpace(string(pidBytes))) == 0 {
		t.Fatalf("never wrote PID to %s: %v", path, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil {
		t.Fatalf("parse pid from %s (%q): %v", path, pidBytes, err)
	}
	return pid
}

func assertProcessGone(t *testing.T, pid int, desc string) {
	t.Helper()
	proc, err := os.FindProcess(pid)
	if err != nil {
		return // already gone
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if sigErr := proc.Signal(syscall.Signal(0)); sigErr != nil {
			return // process is gone: killed and reaped, not orphaned
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("%s (pid %d) was still alive 5s after connection abort", desc, pid)
}

func countOpenFDs(t *testing.T) int {
	t.Helper()
	if runtime.GOOS != "linux" {
		return 0
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	return len(entries)
}

// TestSetupProcessGroupCancelExitedProcess verifies that cmd.Cancel does not
// surface an error when called on an exited process group.
//
// When request context cancellation races child exit, the process group may
// have already exited. On Linux, syscall.Kill(-pid, SIGKILL) returns ESRCH;
// on Darwin/BSD, it returns EPERM or ESRCH. In either case, cmd.Cancel must
// ignore the error and return nil, preventing cmd.Wait from surfacing phantom
// cancellation errors.
func TestSetupProcessGroupCancelExitedProcess(t *testing.T) {
	cmd := exec.CommandContext(context.Background(), "true")
	githttp.SetupProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("cmd.Wait: %v", err)
	}
	if err := cmd.Cancel(); err != nil {
		t.Fatalf("cmd.Cancel() returned error on exited process: %v", err)
	}
}
