package githttp_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/githttp"
	"github.com/writtendev/walden/internal/store"
)

// runGit runs git in dir and fails the test on error.
func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
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
	runGit(t, "", "clone", "-q", "--bare", work, barePath)

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
// only upload-pack.
func TestInfoRefsGoldenPreamble(t *testing.T) {
	s := store.New(t.TempDir())
	newBareRepoWithCommit(t, s, "repo")
	h := githttp.NewHandler(nil, s)

	tests := []struct {
		service      string
		wantPreamble string
		wantType     string
	}{
		{"git-upload-pack", "001e# service=git-upload-pack\n0000", "application/x-git-upload-pack-advertisement"},
		{"git-receive-pack", "001f# service=git-receive-pack\n0000", "application/x-git-receive-pack-advertisement"},
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
	body := strings.TrimRight(rec.Body.String(), "\n")
	if strings.Contains(body, "\n") {
		t.Errorf("body contains an embedded newline: %q", body)
	}
	if body == "" {
		t.Errorf("expected a non-empty one-line refusal body")
	}
}
