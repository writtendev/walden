package githttp_test

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/githttp"
	"github.com/writtendev/walden/internal/store"
)

// gitClientEnv returns a minimal environment for a git client exec'd by
// this test suite: just PATH, so git can be found, and nothing else — no
// HOME, no GIT_CONFIG_*, none of the ambient environment's git
// configuration. This mirrors what handleInfoRefs does for its own git
// child (see inforefs.go's "explicit, minimal environment" comment), so
// these tests exercise walden's client behavior rather than whatever git
// config happens to be set on the machine running the suite — a global
// http.proxy in ~/.gitconfig, for instance, would otherwise silently
// change what git ls-remote does here.
func gitClientEnv() []string {
	env := []string{}
	if p := os.Getenv("PATH"); p != "" {
		env = append(env, "PATH="+p)
	}
	return env
}

// runGit runs git in dir and fails the test on error. dir must be a real
// directory — never the test process's own working directory — both so
// the command doesn't depend on wherever the suite happens to be run from,
// and so it can't pick up a repository's local git config by accident.
func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = gitClientEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// newBareRepoWithCommit creates a bare repository under s at repo, seeded
// with one real commit, and returns that commit's SHA.
func newBareRepoWithCommit(t *testing.T, s *store.Store, repo string) string {
	t.Helper()

	work := t.TempDir()
	runGit(t, work, "init", "-q", "-b", "main")
	runGit(t, work, "config", "user.email", "test@example.com")
	runGit(t, work, "config", "user.name", "Test")
	runGit(t, work, "commit", "-q", "--allow-empty", "-m", "initial")
	sha := strings.TrimSpace(runGit(t, work, "rev-parse", "HEAD"))

	barePath, err := s.RepoPath(repo)
	if err != nil {
		t.Fatalf("RepoPath(%q): %v", repo, err)
	}
	runGit(t, t.TempDir(), "clone", "-q", "--bare", work, barePath)

	return sha
}

// TestInfoRefsRealClient is the ticket's headline claim: a real `git
// ls-remote` succeeds against the handler, and sees exactly the fixture
// repo's commit. Run both with the client's own default and with an
// explicit -c protocol.version=0: this handler deliberately does not
// negotiate protocol v2 (see the comment in handleInfoRefs on why), so a
// default modern git client — which asks for v2 up front — must still
// fall back cleanly to v0 against it.
func TestInfoRefsRealClient(t *testing.T) {
	s := store.New(t.TempDir())
	wantSHA := newBareRepoWithCommit(t, s, "repo")

	server := httptest.NewServer(githttp.NewHandler(nil, s))
	defer server.Close()

	for _, tt := range []struct {
		name string
		args []string
	}{
		{"default", nil},
		{"protocol-v0", []string{"-c", "protocol.version=0"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args := append(append([]string{}, tt.args...), "ls-remote", server.URL+"/repo")
			cmd := exec.Command("git", args...)
			cmd.Dir = t.TempDir()
			cmd.Env = gitClientEnv()
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("git ls-remote: %v\n%s", err, out)
			}
			if !strings.Contains(string(out), wantSHA) {
				t.Errorf("ls-remote output %q does not contain expected SHA %q", out, wantSHA)
			}
			if !strings.Contains(string(out), "refs/heads/main") {
				t.Errorf("ls-remote output %q does not contain refs/heads/main", out)
			}
		})
	}
}

// TestInfoRefsGoldenPreamble pins the pkt-line preamble and content type at
// the byte level for both services. The receive-pack advertisement is
// asserted this way rather than with a client, since `git ls-remote` speaks
// only upload-pack — so wantContains is this test's only proof that git's
// own advertisement (not just walden's preamble) reaches the client for
// that service. Without it, a regression that dropped the streamed body
// entirely (e.g. the peekErr fall-through firing when it shouldn't, or the
// io.MultiReader losing its git-output reader) would still pass: only the
// 30/31 bytes walden frames itself were ever checked.
func TestInfoRefsGoldenPreamble(t *testing.T) {
	s := store.New(t.TempDir())
	sha := newBareRepoWithCommit(t, s, "repo")
	h := githttp.NewHandler(nil, s)

	tests := []struct {
		service      string
		wantPreamble string
		wantType     string
		wantContains string // additional content the body must contain; "" skips the check
	}{
		{"git-upload-pack", "001e# service=git-upload-pack\n0000", "application/x-git-upload-pack-advertisement", ""},
		{"git-receive-pack", "001f# service=git-receive-pack\n0000", "application/x-git-receive-pack-advertisement", sha + " refs/heads/main"},
	}

	for _, tt := range tests {
		t.Run(tt.service, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/repo/info/refs?service="+tt.service, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
			}
			if got := rec.Header().Get("Content-Type"); got != tt.wantType {
				t.Errorf("Content-Type = %q, want %q", got, tt.wantType)
			}
			if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
				t.Errorf("Cache-Control = %q, want %q", got, "no-cache")
			}
			if got := rec.Header().Get("Pragma"); got != "no-cache" {
				t.Errorf("Pragma = %q, want %q", got, "no-cache")
			}
			if got := rec.Header().Get("Expires"); got != "Fri, 01 Jan 1980 00:00:00 GMT" {
				t.Errorf("Expires = %q, want %q", got, "Fri, 01 Jan 1980 00:00:00 GMT")
			}
			if !bytes.HasPrefix(rec.Body.Bytes(), []byte(tt.wantPreamble)) {
				t.Errorf("body does not start with preamble %q: got %q", tt.wantPreamble, rec.Body.Bytes())
			}
			if tt.wantContains != "" && !bytes.Contains(rec.Body.Bytes(), []byte(tt.wantContains)) {
				t.Errorf("body does not contain git's advertisement %q: got %q", tt.wantContains, rec.Body.Bytes())
			}
		})
	}
}

// TestInfoRefsRefusals is the refusal table: each case names a status and
// asserts the body is a single line with no embedded newline, per the
// refusal convention.
func TestInfoRefsRefusals(t *testing.T) {
	s := store.New(t.TempDir())
	newBareRepoWithCommit(t, s, "repo")
	h := githttp.NewHandler(nil, s)

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{"unknown-service", http.MethodGet, "/repo/info/refs?service=git-bogus", http.StatusForbidden},
		{"absent-service", http.MethodGet, "/repo/info/refs", http.StatusForbidden},
		{"invalid-identifier", http.MethodGet, "/_meta/info/refs?service=git-upload-pack", http.StatusBadRequest},
		{"unknown-repo", http.MethodGet, "/does-not-exist/info/refs?service=git-upload-pack", http.StatusNotFound},
		{"post-not-allowed", http.MethodPost, "/repo/info/refs?service=git-upload-pack", http.StatusMethodNotAllowed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			body := strings.TrimRight(rec.Body.String(), "\n")
			if strings.Contains(body, "\n") {
				t.Errorf("body contains an embedded newline: %q", body)
			}
			if body == "" {
				t.Errorf("expected a non-empty one-line refusal body")
			}
		})
	}
}

// TestInfoRefsPostMethodNotAllowed pins the specific regression the plan's
// mux assumption produced: relying on net/http.ServeMux to auto-refuse a
// non-GET method for "GET /{repo}/info/refs" doesn't hold once the "/"
// catch-all is also registered (it swallows the request instead). This
// asserts the explicit handleInfoRefsMethodNotAllowed registration keeps
// the refusal in place: a POST here must get 405 and a single-line body,
// never the catch-all's bare 200.
func TestInfoRefsPostMethodNotAllowed(t *testing.T) {
	s := store.New(t.TempDir())
	newBareRepoWithCommit(t, s, "repo")
	h := githttp.NewHandler(nil, s)

	req := httptest.NewRequest(http.MethodPost, "/repo/info/refs", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusMethodNotAllowed, rec.Body.String())
	}
	if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
		t.Errorf("Allow = %q, want %q (RFC 9110 §15.5.6 requires it on a 405, and HEAD is also supported via ServeMux's GET-matches-HEAD rule)", got, "GET, HEAD")
	}
	body := strings.TrimRight(rec.Body.String(), "\n")
	if strings.Contains(body, "\n") {
		t.Errorf("body contains an embedded newline: %q", body)
	}
	if body == "" {
		t.Errorf("expected a non-empty one-line refusal body")
	}
}

// TestInfoRefsAbortReapsChild proves the round-1 fix for the zombie-process
// and leaked-pipe-fd finding: a client that aborts mid-advertisement must
// not leave a defunct git child behind. Before the fix, the io.Copy error
// path in handleInfoRefs returned without ever calling cmd.Wait() — killing
// the child via context cancellation is not reaping it, so that path left a
// permanent <defunct> process and a leaked pipe fd on every abort.
//
// The check reads process state directly out of /proc rather than calling
// wait4 itself: exec.Cmd keeps its own bookkeeping for the children it
// starts, and an unrelated wait4 call on the same pid racing against it is
// a documented way to corrupt that bookkeeping (and could even mask a real
// leak by reaping it out from under the handler). Reading
// /proc/<pid>/status only inspects state and reaps nothing.
//
// /proc is Linux-only, which is what this repo's CI runs (see
// .github/workflows/ci.yml); this skips elsewhere rather than claim
// coverage the environment can't back up.
func TestInfoRefsAbortReapsChild(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("zombie-process check reads /proc, which only exists on Linux; CI runs linux/amd64 and linux/arm64")
	}

	s := store.New(t.TempDir())
	sha := newBareRepoWithCommit(t, s, "big")
	// Enough refs that the advertisement is far larger than a pipe or TCP
	// buffer, so git is still writing it — and so still alive, not merely
	// exited and awaiting Wait — at the moment each connection is aborted.
	seedManyRefs(t, s, "big", sha, 50000)

	server := httptest.NewServer(githttp.NewHandler(nil, s))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", server.URL, err)
	}

	const attempts = 8
	for i := 0; i < attempts; i++ {
		conn, err := net.Dial("tcp", u.Host)
		if err != nil {
			t.Fatalf("dial %s: %v", u.Host, err)
		}
		if _, err := fmt.Fprintf(conn, "GET /big/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", u.Host); err != nil {
			t.Fatalf("write request: %v", err)
		}
		// Read a little of the response so the server has started
		// streaming, then hang up hard rather than draining the rest —
		// the same shape as an aborted clone or a dropped connection.
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0) // close sends RST, not a graceful FIN
		}
		conn.Close()
	}

	// Give the server's handler goroutines time to notice the aborted
	// connections (request-context cancellation) and reap their children.
	// A correct implementation does this within milliseconds; this margin
	// is generous, not load-bearing.
	time.Sleep(2 * time.Second)

	if survivors := survivingGitChildren(t); len(survivors) > 0 {
		t.Errorf("%d git child(ren) survived %d aborted requests: %v", len(survivors), attempts, survivors)
	}
}

// seedManyRefs adds n additional refs, all pointing at sha, directly to
// repo's packed-refs file. This exists purely to make the advertisement
// body large — nothing here exercises how git itself reads refs.
func seedManyRefs(t *testing.T, s *store.Store, repo, sha string, n int) {
	t.Helper()

	barePath, err := s.RepoPath(repo)
	if err != nil {
		t.Fatalf("RepoPath(%q): %v", repo, err)
	}

	var sb strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "%s refs/heads/branch-%06d\n", sha, i)
	}
	if err := os.WriteFile(filepath.Join(barePath, "packed-refs"), []byte(sb.String()), 0o644); err != nil {
		t.Fatalf("write packed-refs: %v", err)
	}
}

// survivingGitChildren returns a description of every process under /proc
// whose parent is this test binary and whose command name is "git" — the
// subprocess handleInfoRefs execs — regardless of whether that process has
// exited and is waiting to be reaped ("Z", zombie) or is still running.
//
// Checking only for zombies misses a worse failure shape: if a future edit
// swapped exec.CommandContext for a plain exec.Command (dropping context
// cancellation), an aborted request would leave git still alive and still
// writing into a stdout pipe nobody is draining — cmd.Wait() would then
// block forever on that still-running child instead of reaping a
// <defunct> one. That is strictly worse than the original zombie leak (a
// live process, a live pipe pair, and a permanently blocked handler
// goroutine, instead of just a zombie entry) and a zombie-only check
// reports zero and passes. TestInfoRefsAbortReapsChild only calls this
// after its settle window, by which point every aborted request's child
// should be gone — so any git process still attached to this test binary
// at that point, zombie or not, is a leak.
//
// It only reads process state and never waits on anything, so it cannot
// itself reap (and thereby mask) a leak.
func survivingGitChildren(t *testing.T) []string {
	t.Helper()

	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatalf("read /proc: %v", err)
	}

	self := strconv.Itoa(os.Getpid())
	var survivors []string
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a pid directory
		}

		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			continue // process gone by the time we looked
		}
		if !strings.Contains(string(status), "\nPPid:\t"+self+"\n") {
			continue
		}

		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil || strings.TrimSpace(string(comm)) != "git" {
			continue
		}

		state := "unknown"
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "State:\t") {
				state = strings.TrimSpace(strings.TrimPrefix(line, "State:\t"))
				break
			}
		}
		survivors = append(survivors, fmt.Sprintf("pid %d (%s)", pid, state))
	}
	return survivors
}
