package githttp_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"log"
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

// newEmptyBareRepo creates an empty bare repository under s at repo — no
// commits, no refs — and returns its on-disk path. This is the receive-pack
// tests' starting point: a repository that already exists (so none of them
// touch the create-on-push gate, which is WALD-40's, not this ticket's) but
// has nothing in it yet, exactly like a fresh `git init --bare` an operator
// made themselves.
func newEmptyBareRepo(t *testing.T, s *store.Store, repo string) string {
	t.Helper()

	barePath, err := s.RepoPath(repo)
	if err != nil {
		t.Fatalf("RepoPath(%q): %v", repo, err)
	}
	runGit(t, t.TempDir(), "init", "-q", "--bare", barePath)
	return barePath
}

// newWorkTreeWithCommit creates a work tree with one commit and returns its
// SHA. Separate from newBareRepoWithCommit (inforefs_test.go), which also
// clones the result into a bare repo; receive-pack tests push a work tree's
// commits themselves rather than starting from an already-populated bare
// repo.
func newWorkTreeWithCommit(t *testing.T) (dir, sha string) {
	t.Helper()

	work := t.TempDir()
	runGit(t, work, "init", "-q", "-b", "main")
	runGit(t, work, "config", "user.email", "test@example.com")
	runGit(t, work, "config", "user.name", "Test")
	runGit(t, work, "commit", "-q", "--allow-empty", "-m", "initial")
	sha = strings.TrimSpace(runGit(t, work, "rev-parse", "HEAD"))
	return work, sha
}

// revParse reads a ref directly out of a bare repository via `git
// --git-dir`, without going through any server. It returns "" (never
// fails the test) when the ref does not exist, which the hook-rejection
// test relies on to assert a declined push never moved the ref.
func revParse(t *testing.T, barePath, ref string) string {
	t.Helper()

	cmd := exec.Command("git", "--git-dir="+barePath, "rev-parse", "--verify", "--quiet", ref)
	cmd.Dir = t.TempDir()
	cmd.Env = gitClientEnv()
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// installHook writes an executable hooks/<name> script into barePath
// containing script verbatim.
func installHook(t *testing.T, barePath, name, script string) {
	t.Helper()

	path := filepath.Join(barePath, "hooks", name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write hook %q: %v", name, err)
	}
}

// statusCapture records the HTTP status code a handler sent, then passes
// every call straight through to the underlying ResponseWriter. Unwrap
// lets http.ResponseController (used by handleReceivePack to flush after
// every write) see past this wrapper to the real ResponseWriter's own
// Flusher, exactly as net/http's ResponseController docs describe for a
// wrapping type like this one.
type statusCapture struct {
	http.ResponseWriter
	code int
}

func (s *statusCapture) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusCapture) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// captureReceivePackStatus wraps h so that the HTTP status code of every
// POST .../git-receive-pack request is recorded into *status, while every
// other request (the GET info/refs negotiation) is served normally. This
// is how TestReceivePackHookRejectionIsACompletedRPC proves the headline
// promise: a declined push is still a 200.
func captureReceivePackStatus(h http.Handler, status *int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git-receive-pack") {
			sc := &statusCapture{ResponseWriter: w, code: http.StatusOK}
			h.ServeHTTP(sc, r)
			*status = sc.code
			return
		}
		h.ServeHTTP(w, r)
	})
}

// TestReceivePackRealClient is the ticket's headline claim: a real `git
// push` succeeds against the handler, moves the ref, and a second push
// fast-forwards it further. Repeated under -c protocol.version=2, since
// handleReceivePack deliberately does not negotiate v2 (see its comment on
// GIT_PROTOCOL) and a modern client defaulting to v2 must still fall back
// to v0 and succeed.
func TestReceivePackRealClient(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
	}{
		{"default", nil},
		{"protocol-v2", []string{"-c", "protocol.version=2"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := store.New(t.TempDir())
			barePath := newEmptyBareRepo(t, s, "repo")
			h, tok := newTestHandler(t, s, "")
			server := httptest.NewServer(h)
			defer server.Close()

			work, sha1 := newWorkTreeWithCommit(t)

			push := func(refspec string) string {
				args := append(append([]string{}, tt.args...), "push", authURL(server.URL, tok)+"/repo", refspec)
				cmd := exec.Command("git", args...)
				cmd.Dir = work
				cmd.Env = gitClientEnv()
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("git push %s: %v\n%s", refspec, err, out)
				}
				return string(out)
			}

			push("main")
			if got := revParse(t, barePath, "refs/heads/main"); got != sha1 {
				t.Fatalf("after first push, refs/heads/main = %q, want %q", got, sha1)
			}

			runGit(t, work, "commit", "-q", "--allow-empty", "-m", "second")
			sha2 := strings.TrimSpace(runGit(t, work, "rev-parse", "HEAD"))

			push("main")
			if got := revParse(t, barePath, "refs/heads/main"); got != sha2 {
				t.Fatalf("after fast-forward push, refs/heads/main = %q, want %q", got, sha2)
			}
		})
	}
}

// TestReceivePackHookRejectionIsACompletedRPC is the clause that names this
// ticket: a pre-receive hook's rejection must reach the developer as git's
// own remote: lines and an ng report in their own terminal, never as a
// broken pipe, and the HTTP status underneath it is 200 because a declined
// push is a completed RPC. Wording asserted here (remote: walden: declined
// for testing, pre-receive hook declined) matches what git-http-backend
// itself produces for the identical hook, confirmed by hand against a real
// git-http-backend CGI instance before writing this test.
func TestReceivePackHookRejectionIsACompletedRPC(t *testing.T) {
	s := store.New(t.TempDir())
	barePath := newEmptyBareRepo(t, s, "repo")
	installHook(t, barePath, "pre-receive", "#!/bin/sh\necho 'walden: declined for testing' >&2\nexit 1\n")

	var pushStatus int
	h, tok := newTestHandler(t, s, "")
	server := httptest.NewServer(captureReceivePackStatus(h, &pushStatus))
	defer server.Close()

	work, _ := newWorkTreeWithCommit(t)

	cmd := exec.Command("git", "push", authURL(server.URL, tok)+"/repo", "main")
	cmd.Dir = work
	cmd.Env = gitClientEnv()
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("git push: expected a non-zero exit for a hook rejection, got success:\n%s", out)
	}

	got := string(out)
	if !strings.Contains(got, "remote: walden: declined for testing") {
		t.Errorf("output does not contain the hook's relayed stderr: %q", got)
	}
	if !strings.Contains(got, "pre-receive hook declined") {
		t.Errorf("output does not contain git's own rejection report: %q", got)
	}
	for _, bad := range []string{"RPC failed", "broken pipe", "unexpected disconnect"} {
		if strings.Contains(got, bad) {
			t.Errorf("output contains %q, meaning the client saw a broken connection instead of a completed RPC: %q", bad, got)
		}
	}

	if pushStatus != http.StatusOK {
		t.Errorf("HTTP status for the declined push = %d, want %d (a declined push is a completed RPC)", pushStatus, http.StatusOK)
	}
	if got := revParse(t, barePath, "refs/heads/main"); got != "" {
		t.Errorf("refs/heads/main = %q, want unset: a declined push must not move the ref", got)
	}
}

// TestReceivePackHookEnvironment proves the environment contract a
// pre-receive hook (WALD-43) depends on: an explicit, enumerable list built
// by this handler, plus whatever git itself adds around a hook invocation —
// never the server's ambient environment forwarded wholesale.
func TestReceivePackHookEnvironment(t *testing.T) {
	// runPush returns the hook's environment and the names git left in
	// the quarantine directory's pack/. The second is what proves the
	// receive.unpackLimit=0 knob (WALD-44) actually took: with git's
	// default, a push this small is unpacked to loose objects and pack/
	// is empty, so the pre-receive hook has no segment to journal.
	// Deliberately asserted as behaviour rather than by grepping the
	// argv -- a test that looks for "-c receive.unpackLimit=0" would go
	// on passing if git stopped honouring it.
	runPush := func(t *testing.T, h http.Handler, token, barePath string) (map[string]string, []string) {
		t.Helper()

		dumpDir := t.TempDir()
		dumpPath := filepath.Join(dumpDir, "env.dump")
		packPath := filepath.Join(dumpDir, "pack.dump")
		installHook(t, barePath, "pre-receive",
			"#!/bin/sh\nenv > "+dumpPath+"\nls \"$GIT_QUARANTINE_PATH/pack\" > "+packPath+" 2>/dev/null\nexit 1\n")

		server := httptest.NewServer(h)
		defer server.Close()

		work, _ := newWorkTreeWithCommit(t)
		cmd := exec.Command("git", "push", authURL(server.URL, token)+"/repo", "main")
		cmd.Dir = work
		cmd.Env = gitClientEnv()
		_, _ = cmd.CombinedOutput() // the hook always exits 1; only its env dump matters

		raw, err := os.ReadFile(dumpPath)
		if err != nil {
			t.Fatalf("read env dump: %v", err)
		}
		env := map[string]string{}
		for _, line := range strings.Split(string(raw), "\n") {
			if line == "" {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			env[k] = v
		}

		var packEntries []string
		if raw, err := os.ReadFile(packPath); err == nil {
			for _, name := range strings.Split(string(raw), "\n") {
				if name != "" {
					packEntries = append(packEntries, name)
				}
			}
		}
		return env, packEntries
	}

	t.Run("core-variables-and-git-owned-ones", func(t *testing.T) {
		s := store.New(t.TempDir())
		barePath := newEmptyBareRepo(t, s, "repo")
		h, tok := newTestHandler(t, s, "https://example.com/bucket/prefix")
		env, packEntries := runPush(t, h, tok, barePath)

		if got := env["WALDEN_REPO"]; got != "repo" {
			t.Errorf("WALDEN_REPO = %q, want %q", got, "repo")
		}
		if got := env["WALDEN_DATA_DIR"]; got != s.DataDir() {
			t.Errorf("WALDEN_DATA_DIR = %q, want %q", got, s.DataDir())
		}
		if got := env["WALDEN_JOURNAL"]; got != "https://example.com/bucket/prefix" {
			t.Errorf("WALDEN_JOURNAL = %q, want %q", got, "https://example.com/bucket/prefix")
		}
		if _, ok := env["GIT_DIR"]; !ok {
			t.Errorf("GIT_DIR is absent from the hook environment; git itself should set it")
		}
		if _, ok := env["GIT_QUARANTINE_PATH"]; !ok {
			t.Errorf("GIT_QUARANTINE_PATH is absent from the hook environment; git itself should set it")
		}
		if _, ok := env["GIT_COMMITTER_NAME"]; ok {
			t.Errorf("GIT_COMMITTER_NAME is present; walden has no identity model and must not invent one")
		}

		// One commit is far below git's default receive.unpackLimit of
		// 100, so without walden setting that knob to 0 this directory
		// is empty and the objects are loose somewhere under the
		// quarantine root instead.
		packs := 0
		for _, name := range packEntries {
			if strings.HasSuffix(name, ".pack") {
				packs++
			}
		}
		if packs != 1 {
			t.Errorf("GIT_QUARANTINE_PATH/pack holds %d packfiles (entries %v), want exactly one; the received objects must reach the hook as a packfile, not as loose objects", packs, packEntries)
		}
	})

	t.Run("journal-less-mode-omits-the-variable-entirely", func(t *testing.T) {
		s := store.New(t.TempDir())
		barePath := newEmptyBareRepo(t, s, "repo")
		h, tok := newTestHandler(t, s, "")
		env, _ := runPush(t, h, tok, barePath)

		if v, ok := env["WALDEN_JOURNAL"]; ok {
			t.Errorf("WALDEN_JOURNAL = %q, want the variable absent entirely (journal-less mode), not empty", v)
		}
	})

	t.Run("aws-credentials-forwarded-selectively", func(t *testing.T) {
		t.Setenv("AWS_ACCESS_KEY_ID", "test-access-key-id")
		t.Setenv("WALDEN_TEST_UNRELATED_VAR", "should-not-be-forwarded")

		s := store.New(t.TempDir())
		barePath := newEmptyBareRepo(t, s, "repo")
		h, tok := newTestHandler(t, s, "")
		env, _ := runPush(t, h, tok, barePath)

		if got := env["AWS_ACCESS_KEY_ID"]; got != "test-access-key-id" {
			t.Errorf("AWS_ACCESS_KEY_ID = %q, want %q", got, "test-access-key-id")
		}
		if _, ok := env["WALDEN_TEST_UNRELATED_VAR"]; ok {
			t.Errorf("an unrelated environment variable reached the hook; the forwarding list must be an allowlist, not the ambient environment")
		}
	})
}

// TestReceivePackRefusals is the refusal table: each case names a status
// and asserts the body is a single line with no embedded newline, per the
// refusal convention. Content-Encoding: gzip is deliberately not a case
// here — see handleReceivePack's comment and TestReceivePackGzipInflate:
// walden accepts and inflates it, matching git-http-backend, rather than
// refusing it as this ticket's plan originally assumed.
func TestReceivePackRefusals(t *testing.T) {
	s := store.New(t.TempDir())
	newEmptyBareRepo(t, s, "repo")
	authorizer, tok := newTestAuthorizer(t, "rw:*")
	h := githttp.NewHandler(authorizer, s, "")

	tests := []struct {
		name        string
		method      string
		path        string
		contentType string
		encoding    string
		wantStatus  int
	}{
		{"get-not-allowed", http.MethodGet, "/repo/git-receive-pack", "", "", http.StatusMethodNotAllowed},
		{"wrong-content-type", http.MethodPost, "/repo/git-receive-pack", "application/octet-stream", "", http.StatusUnsupportedMediaType},
		{"missing-content-type", http.MethodPost, "/repo/git-receive-pack", "", "", http.StatusUnsupportedMediaType},
		{"unsupported-encoding", http.MethodPost, "/repo/git-receive-pack", "application/x-git-receive-pack-request", "br", http.StatusUnsupportedMediaType},
		{"invalid-identifier", http.MethodPost, "/_meta/git-receive-pack", "application/x-git-receive-pack-request", "", http.StatusBadRequest},
		{"unknown-repo", http.MethodPost, "/does-not-exist/git-receive-pack", "application/x-git-receive-pack-request", "", http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(""))
			req.Header.Set("Authorization", "Bearer "+tok)
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			if tt.encoding != "" {
				req.Header.Set("Content-Encoding", tt.encoding)
			}
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

// TestReceivePackMethodNotAllowedHeader pins the Allow header on the 405,
// mirroring TestInfoRefsPostMethodNotAllowed's proof for the opposite
// route: relying on net/http.ServeMux's automatic method-mismatch 405
// does not hold once the package's "/" catch-all is also registered.
func TestReceivePackMethodNotAllowedHeader(t *testing.T) {
	s := store.New(t.TempDir())
	newEmptyBareRepo(t, s, "repo")
	h, _ := newTestHandler(t, s, "")

	req := httptest.NewRequest(http.MethodGet, "/repo/git-receive-pack", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusMethodNotAllowed, rec.Body.String())
	}
	if got := rec.Header().Get("Allow"); got != "POST" {
		t.Errorf("Allow = %q, want %q", got, "POST")
	}
}

// captureRawReceivePackRequest runs a real `git push` against a recording
// server that answers the info/refs negotiation with the real handler (so
// capability negotiation, and the resulting request body, are authentic)
// but intercepts the POST itself, returning the exact bytes git put on the
// wire for the git-receive-pack RPC rather than letting the real handler
// consume them. This is the source of ground truth for
// TestReceivePackGzipInflate: real git never gzips this body itself (see
// handleReceivePack's Content-Encoding comment), so a client that does
// gzip it is simulated by compressing this capture afterwards.
func captureRawReceivePackRequest(t *testing.T, work string) []byte {
	t.Helper()

	s := store.New(t.TempDir())
	newEmptyBareRepo(t, s, "capture")
	authorizer, tok := newTestAuthorizer(t, "rwc:*")
	h := githttp.NewHandler(authorizer, s, "")

	var captured []byte
	recorder := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git-receive-pack") {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("reading captured request body: %v", err)
			}
			captured = b
			// Deliberately not a valid result: this recorder exists only
			// to see the bytes git sends, not to accept the push.
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		h.ServeHTTP(w, r)
	})
	server := httptest.NewServer(recorder)
	defer server.Close()

	cmd := exec.Command("git", "push", authURL(server.URL, tok)+"/capture", "main")
	cmd.Dir = work
	cmd.Env = gitClientEnv()
	_, _ = cmd.CombinedOutput() // expected to fail; only the captured bytes matter

	if len(captured) == 0 {
		t.Fatal("did not capture a git-receive-pack request body")
	}
	return captured
}

// TestReceivePackGzipInflate is the resolution of the contradiction raised
// on WALD-39 between this ticket's plan (refuse Content-Encoding: gzip)
// and WALD-38's finding that git-http-backend accepts and inflates one.
// No real git client observed in this repo's own testing gzips a
// receive-pack body (see handleReceivePack's comment for the evidence),
// so this test constructs the case by hand: capture the exact bytes a real
// `git push` sends, gzip-compress them, and POST that directly with
// Content-Encoding: gzip (and, per round-1's minor finding, its legacy
// alias x-gzip — the same encoding under the spelling git-http-backend's
// own binary also lists, so it must be accepted identically). A server
// that matches git-http-backend accepts either and the ref moves.
func TestReceivePackGzipInflate(t *testing.T) {
	work, sha := newWorkTreeWithCommit(t)
	raw := captureRawReceivePackRequest(t, work)

	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(raw); err != nil {
		t.Fatalf("gzip.Write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip.Close: %v", err)
	}
	compressedBytes := compressed.Bytes()

	for _, encoding := range []string{"gzip", "x-gzip"} {
		t.Run(encoding, func(t *testing.T) {
			s := store.New(t.TempDir())
			barePath := newEmptyBareRepo(t, s, "target")
			h, tok := newTestHandler(t, s, "")
			server := httptest.NewServer(h)
			defer server.Close()

			req, err := http.NewRequest(http.MethodPost, server.URL+"/target/git-receive-pack", bytes.NewReader(compressedBytes))
			if err != nil {
				t.Fatalf("http.NewRequest: %v", err)
			}
			req.Header.Set("Authorization", "Bearer "+tok)
			req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
			req.Header.Set("Content-Encoding", encoding)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("POST %s-encoded push: %v", encoding, err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read response body: %v", err)
			}

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, http.StatusOK, body)
			}
			if !bytes.Contains(body, []byte("unpack ok")) {
				t.Errorf("response does not contain %q: %q", "unpack ok", body)
			}
			if got := revParse(t, barePath, "refs/heads/main"); got != sha {
				t.Errorf("after %s-encoded push, refs/heads/main = %q, want %q", encoding, got, sha)
			}
		})
	}
}

// TestReceivePackInvalidGzip proves a client that lies about
// Content-Encoding — declaring gzip but sending a body that isn't one —
// gets a clean refusal rather than a confusing failure from deep inside
// the git subprocess.
func TestReceivePackInvalidGzip(t *testing.T) {
	s := store.New(t.TempDir())
	newEmptyBareRepo(t, s, "repo")
	h, tok := newTestHandler(t, s, "")

	req := httptest.NewRequest(http.MethodPost, "/repo/git-receive-pack", strings.NewReader("not actually gzip"))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
	req.Header.Set("Content-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	body := strings.TrimRight(rec.Body.String(), "\n")
	if strings.Contains(body, "\n") {
		t.Errorf("body contains an embedded newline: %q", body)
	}
}

// TestReceivePackCleanRefusalDoesNotHangOnDeadBody reproduces round-1's
// medium finding: git can exit with no output at all before the request
// body has finished arriving, and the refusal handleReceivePack has
// already composed for that case must still reach the client promptly.
// Before the fix, cmd.Wait() blocked forever in that shape, because
// os/exec's stdin-copy goroutine was itself blocked reading the request
// body — a client that announces a Content-Length and then simply stops
// sending, without closing the connection, never unblocks it on its own.
//
// The data directory holds "notarepo" as a plain, empty directory (an
// interrupted `git init`, or any half-materialised repository) rather
// than a real bare repository, so os.Stat is satisfied but `git
// receive-pack` fails immediately with no output — exactly round-1's own
// reproduction. The proof is that the refusal still arrives well within
// this test's bound rather than only once the client stops being silent,
// and (on Linux, where /proc lets this be checked) that no git child is
// left behind waiting to be reaped.
func TestReceivePackCleanRefusalDoesNotHangOnDeadBody(t *testing.T) {
	s := store.New(t.TempDir())
	notARepo, err := s.RepoPath("notarepo")
	if err != nil {
		t.Fatalf("RepoPath(%q): %v", "notarepo", err)
	}
	if err := os.MkdirAll(notARepo, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", notARepo, err)
	}

	h, tok := newTestHandler(t, s, "")
	server := httptest.NewServer(h)
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", server.URL, err)
	}

	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dial %s: %v", u.Host, err)
	}
	defer conn.Close()

	request := "POST /notarepo/git-receive-pack HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Authorization: Bearer " + tok + "\r\n" +
		"Content-Type: application/x-git-receive-pack-request\r\n" +
		"Content-Length: 1000000\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("write request headers: %v", err)
	}
	// A handful of bytes toward the declared Content-Length, then
	// silence: the client neither finishes the body nor closes the
	// connection, matching round-1's own reproduction exactly.
	if _, err := conn.Write([]byte("dead")); err != nil {
		t.Fatalf("write partial body: %v", err)
	}

	// Round-1's reproduction saw no response after 10s of this. A fixed
	// handler returns in well under a second once git has exited; this
	// bound is generous, not load-bearing.
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("did not receive a response within 5s -- this is the hang this test guards against: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, http.StatusInternalServerError, body)
	}
	trimmed := strings.TrimRight(string(body), "\n")
	if trimmed == "" || strings.Contains(trimmed, "\n") {
		t.Errorf("expected a non-empty, one-line refusal body, got %q", trimmed)
	}

	if runtime.GOOS != "linux" {
		return // survivingGitChildren (inforefs_test.go) reads /proc, Linux-only.
	}
	// Give the handler a moment to run its deferred reap after the
	// response above was already written.
	time.Sleep(500 * time.Millisecond)
	if survivors := survivingGitChildren(t); len(survivors) > 0 {
		t.Errorf("%d git child(ren) survived: %v", len(survivors), survivors)
	}
}

// TestReceivePackStreamingDoesNotHangOnDeadBody reproduces round-2's medium
// finding: the same unbounded Wait round 1 closed on the no-output branch
// (TestReceivePackCleanRefusalDoesNotHangOnDeadBody, above) was still open
// on the streaming branch -- and there it strands the client after a
// *successful* push rather than merely delaying a refusal.
//
// git's --stateless-rpc does not read its stdin to EOF: it reads the
// commands and exactly the pack index-pack expects, reports, and exits.
// So a client that over-declares its Content-Length by even one byte
// leaves os/exec's stdin-copy goroutine parked in a Read on the request
// body long after git has finished and its stdout has already been
// copied to the client in full. Before the fix, the trailing wait() on
// this branch blocked on that goroutine forever -- receivePackWaitDelay
// never arms against a client that is merely silent, since its timer (per
// go1.25's os/exec) is only created after the request context is
// cancelled -- so the chunked response was left unterminated even though
// the ref had already moved server-side.
//
// This raises a real push's captured raw bytes (captureRawReceivePackRequest,
// above) over a raw connection with a Content-Length one byte higher than
// what is actually sent, then asserts the response reaches its end (the
// closing zero-length chunk) within a bound a fixed handler clears in
// milliseconds, and that the ref moved despite the miscounted framing.
func TestReceivePackStreamingDoesNotHangOnDeadBody(t *testing.T) {
	work, sha := newWorkTreeWithCommit(t)
	raw := captureRawReceivePackRequest(t, work)

	s := store.New(t.TempDir())
	barePath := newEmptyBareRepo(t, s, "target")
	h, tok := newTestHandler(t, s, "")
	server := httptest.NewServer(h)
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", server.URL, err)
	}

	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dial %s: %v", u.Host, err)
	}
	defer conn.Close()

	request := "POST /target/git-receive-pack HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Authorization: Bearer " + tok + "\r\n" +
		"Content-Type: application/x-git-receive-pack-request\r\n" +
		"Content-Length: " + strconv.Itoa(len(raw)+1) + "\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("write request headers: %v", err)
	}
	// The declared Content-Length is one byte more than what follows: the
	// client goes silent right after, the same one-byte miscount round
	// 2's reproduction used, with no hostility beyond that required.
	if _, err := conn.Write(raw); err != nil {
		t.Fatalf("write request body: %v", err)
	}

	// Round 2's reproduction saw the handler still parked 25s after git
	// had already completed the push and exited. A fixed handler
	// terminates the response in well under a second; this bound is
	// generous, not load-bearing.
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("did not receive response headers within 5s: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("did not receive the end of the response body within 5s -- this is the hang this test guards against: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, http.StatusOK, body)
	}
	if !bytes.Contains(body, []byte("unpack ok")) {
		t.Errorf("response does not contain %q: %q", "unpack ok", body)
	}
	if got := revParse(t, barePath, "refs/heads/main"); got != sha {
		t.Errorf("refs/heads/main = %q, want %q -- push should have succeeded despite the miscounted Content-Length", got, sha)
	}
}

// TestReceivePackEmptyBodyDoesNotDoubleWait reproduces round-1's minor
// finding: a bare flush-pkt request body ("0000", with no commands at
// all) is a well-formed receive-pack request that real git answers with
// exit 0 and zero bytes of stdout. That lands exactly on the branch
// br.Peek(1) fails but wait() has already succeeded, and without
// inforefs.go's "if peekErr == nil" guard on the trailing wait() call,
// cmd.Wait() was called a second time -- returning os/exec's "Wait was
// already called" and logging it as though git had failed a request that
// actually succeeded. The response was already correct before this fix;
// what this test pins down is that the log stays quiet, since a bogus
// failure log for a successful push is the kind of thing an operator
// chases for twenty minutes.
func TestReceivePackEmptyBodyDoesNotDoubleWait(t *testing.T) {
	s := store.New(t.TempDir())
	newEmptyBareRepo(t, s, "repo")
	h, tok := newTestHandler(t, s, "")

	var logs bytes.Buffer
	prevOutput := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(prevOutput)
		log.SetFlags(prevFlags)
	}()

	req := httptest.NewRequest(http.MethodPost, "/repo/git-receive-pack", strings.NewReader("0000"))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body = %q, want empty: a bare flush-pkt push produces no output", rec.Body.String())
	}

	if got := logs.String(); strings.Contains(got, "Wait was already called") {
		t.Errorf("log contains a spurious double-Wait failure for a request that succeeded: %q", got)
	}
}

// TestReceivePackPreservesKeepAliveConnection reproduces round-3's major
// finding: waitAfterStdoutSettled set an expired read deadline on w
// unconditionally, which on the healthy success path caused net/http's
// background read on the drained connection to error and invoke
// cancelCtx() on the underlying connection. Any subsequent request reusing
// that keep-alive connection arrived with r.Context() already canceled,
// causing cmd.Start() to fail with 500 "context canceled".
func TestReceivePackPreservesKeepAliveConnection(t *testing.T) {
	work, sha := newWorkTreeWithCommit(t)
	raw := captureRawReceivePackRequest(t, work)

	s := store.New(t.TempDir())
	barePath := newEmptyBareRepo(t, s, "target")
	h, tok := newTestHandler(t, s, "")
	server := httptest.NewServer(h)
	defer server.Close()

	tr := &http.Transport{
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		DisableKeepAlives:   false,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}

	// 1. Push: valid body with exact Content-Length.
	pushReq, err := http.NewRequest(http.MethodPost, server.URL+"/target/git-receive-pack", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	pushReq.Header.Set("Authorization", "Bearer "+tok)
	pushReq.Header.Set("Content-Type", "application/x-git-receive-pack-request")
	pushReq.Header.Set("Content-Length", strconv.Itoa(len(raw)))

	resp, err := client.Do(pushReq)
	if err != nil {
		t.Fatalf("push request failed: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read push response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("push status = %d, want %d; body: %s", resp.StatusCode, http.StatusOK, body)
	}
	if !bytes.Contains(body, []byte("unpack ok")) {
		t.Fatalf("push response does not contain 'unpack ok': %s", body)
	}
	if got := revParse(t, barePath, "refs/heads/main"); got != sha {
		t.Fatalf("ref = %q, want %q", got, sha)
	}

	// 2. Second request on the same connection: info/refs advertisement.
	infoReq, err := http.NewRequest(http.MethodGet, server.URL+"/target/info/refs?service=git-receive-pack", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	infoReq.Header.Set("Authorization", "Bearer "+tok)
	infoResp, err := client.Do(infoReq)
	if err != nil {
		t.Fatalf("second request on keep-alive connection failed: %v", err)
	}
	infoBody, err := io.ReadAll(infoResp.Body)
	infoResp.Body.Close()
	if err != nil {
		t.Fatalf("read second response body: %v", err)
	}
	if infoResp.StatusCode != http.StatusOK {
		t.Fatalf("second request status = %d, want %d; body: %s", infoResp.StatusCode, http.StatusOK, infoBody)
	}
}
