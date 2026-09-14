//go:build unix

package githttp_test

import (
	"fmt"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/githttp"
	"github.com/writtendev/walden/internal/store"
)

// TestUploadPackAbortKillsChild proves the ticket's cancellation claim: a
// client that hangs up mid-fetch causes the git subprocess to be
// cancelled rather than orphaned. It replaces "git" on PATH with a fake
// script that never exits on its own, so a false pass — the real git
// simply finishing before the connection is aborted — is not possible.
//
// This needs no production seam: handleUploadPack resolves "git" through
// the parent process's own PATH exactly as a real deployment does, so
// putting a different "git" first on PATH substitutes it for this test
// alone (t.Setenv restores the original PATH afterward). The bare
// repository directory itself is never touched by the fake script, so it
// need not contain a real repository — just exist.
//
// The check reads process state directly rather than calling Wait or
// kill itself: an unrelated wait on the same pid could race the
// handler's own cmd.Wait and corrupt exec.Cmd's bookkeeping (and could
// even mask a real leak by reaping it out from under the handler).
// syscall.Signal(0) only probes whether the process still exists; it
// reaps nothing. This mirrors inforefs_test.go's survivingGitChildren.
//
// This test needs "syscall" to send a null signal, which does not build
// portably outside unix; guarded with //go:build unix, which covers CI
// (ubuntu, amd64 and arm64) and macOS development.
func TestUploadPackAbortKillsChild(t *testing.T) {
	binDir := t.TempDir()
	pidFile := filepath.Join(binDir, "git.pid")

	// The fake "git": records its own pid, then streams forever without
	// ever reading its stdin. `sleep` is invoked as a short-lived child
	// process each iteration, not the script's own process, so the pid
	// recorded here stays valid until this process is killed.
	script := fmt.Sprintf("#!/bin/sh\necho $$ > %s\nwhile :; do\n  printf 'x'\n  sleep 0.2\ndone\n", pidFile)
	if err := os.WriteFile(filepath.Join(binDir, "git"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake git script: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	s := store.New(t.TempDir())
	barePath, err := s.RepoPath("repo")
	if err != nil {
		t.Fatalf("RepoPath(%q): %v", "repo", err)
	}
	if err := os.MkdirAll(barePath, 0o755); err != nil {
		t.Fatalf("mkdir %q: %v", barePath, err)
	}

	server := httptest.NewServer(githttp.NewHandler(nil, s, ""))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", server.URL, err)
	}

	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dial %s: %v", u.Host, err)
	}

	reqBody := "0000"
	request := fmt.Sprintf(
		"POST /repo/git-upload-pack HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-git-upload-pack-request\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		u.Host, len(reqBody), reqBody,
	)
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Read a little of the response so the fake git has actually started
	// (and so its pid file exists) before hanging up hard.
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read response: %v", err)
	}

	var pidBytes []byte
	for i := 0; i < 100; i++ {
		pidBytes, err = os.ReadFile(pidFile)
		if err == nil && len(strings.TrimSpace(string(pidBytes))) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || len(strings.TrimSpace(string(pidBytes))) == 0 {
		t.Fatalf("fake git never wrote its pid to %q: %v", pidFile, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil {
		t.Fatalf("parse pid %q: %v", pidBytes, err)
	}

	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0) // close sends RST, not a graceful FIN
	}
	conn.Close()

	proc, err := os.FindProcess(pid)
	if err != nil {
		t.Fatalf("FindProcess(%d): %v", pid, err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if sigErr := proc.Signal(syscall.Signal(0)); sigErr != nil {
			return // process is gone: killed and reaped, not orphaned
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("fake git process (pid %d) was still alive 5s after the connection was aborted", pid)
}
