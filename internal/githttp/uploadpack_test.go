package githttp_test

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/githttp"
	"github.com/writtendev/walden/internal/store"
)

// TestUploadPackRealClient is the ticket's headline claim: a real `git
// clone` and `git ls-remote` succeed end to end (info/refs advertisement
// plus this endpoint) under three protocol negotiations. "default" is
// the case that actually broke WALD-36's advertisement handler: a
// default modern git client sends "Git-Protocol: version=2" on its own,
// without any explicit -c flag, so it is asserted here rather than
// assumed to be covered by the explicit protocol-v2 case.
func TestUploadPackRealClient(t *testing.T) {
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
		{"protocol-v2", []string{"-c", "protocol.version=2"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			lsArgs := append(append([]string{}, tt.args...), "ls-remote", server.URL+"/repo")
			cmd := exec.Command("git", lsArgs...)
			cmd.Dir = t.TempDir()
			cmd.Env = gitClientEnv()
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("git ls-remote: %v\n%s", err, out)
			}
			if !strings.Contains(string(out), wantSHA) {
				t.Errorf("ls-remote output %q does not contain expected SHA %q", out, wantSHA)
			}

			dest := filepath.Join(t.TempDir(), "clone")
			cloneArgs := append(append([]string{}, tt.args...), "clone", "-q", server.URL+"/repo", dest)
			cmd = exec.Command("git", cloneArgs...)
			cmd.Dir = t.TempDir()
			cmd.Env = gitClientEnv()
			out, err = cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("git clone: %v\n%s", err, out)
			}

			gotSHA := strings.TrimSpace(runGit(t, dest, "rev-parse", "HEAD"))
			if gotSHA != wantSHA {
				t.Errorf("cloned HEAD = %q, want %q", gotSHA, wantSHA)
			}
		})
	}
}

// TestUploadPackMemoryStaysFlat is the ticket's other headline claim: a
// large clone holds process memory flat. It serves a repo containing one
// large, incompressible blob, clones it as a real subprocess (so
// runtime.MemStats sees only walden's own allocations, never the
// client's), and asserts the server side's TotalAlloc delta stays well
// below the payload size. A buffering implementation allocates at least
// one whole pack and fails this by a wide margin; the threshold is
// deliberately coarse so this is not a flake.
func TestUploadPackMemoryStaysFlat(t *testing.T) {
	if testing.Short() {
		t.Skip("clones a large blob; skipped under -short")
	}

	const blobSize = 16 << 20 // ~16 MiB

	s := store.New(t.TempDir())
	seedLargeBlob(t, s, "big", blobSize)

	server := httptest.NewServer(githttp.NewHandler(nil, s))
	defer server.Close()

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	dest := filepath.Join(t.TempDir(), "clone")
	cmd := exec.Command("git", "clone", "-q", server.URL+"/big", dest)
	cmd.Dir = t.TempDir()
	cmd.Env = gitClientEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git clone: %v\n%s", err, out)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	delta := after.TotalAlloc - before.TotalAlloc
	// An order of magnitude below the payload, generously rounded so
	// this is a real regression detector, not a flake.
	const threshold = blobSize / 4
	if delta > threshold {
		t.Errorf("server-side TotalAlloc grew by %d bytes cloning a %d-byte blob; want well under %d (streaming, not buffering)", delta, blobSize, threshold)
	}
}

// TestUploadPackRefusals is the refusal table: each case names a status
// and asserts the body is a single line with no embedded newline, per
// the refusal convention.
func TestUploadPackRefusals(t *testing.T) {
	s := store.New(t.TempDir())
	newBareRepoWithCommit(t, s, "repo")
	h := githttp.NewHandler(nil, s)

	// A data directory that cannot be resolved at all, for the 500 case
	// — the same technique internal/store's own
	// TestStoreRepoPathUnresolvableDataDir uses.
	badStore := store.New(filepath.Join(t.TempDir(), "does-not-exist"))
	hBadDataDir := githttp.NewHandler(nil, badStore)

	tests := []struct {
		name        string
		handler     *githttp.Handler
		method      string
		path        string
		contentType string
		encoding    string
		body        string
		wantStatus  int
	}{
		{"get-not-allowed", h, http.MethodGet, "/repo/git-upload-pack", "application/x-git-upload-pack-request", "", "0000", http.StatusMethodNotAllowed},
		{"wrong-content-type", h, http.MethodPost, "/repo/git-upload-pack", "text/plain", "", "0000", http.StatusUnsupportedMediaType},
		{"unknown-content-encoding", h, http.MethodPost, "/repo/git-upload-pack", "application/x-git-upload-pack-request", "br", "0000", http.StatusUnsupportedMediaType},
		{"corrupt-gzip-body", h, http.MethodPost, "/repo/git-upload-pack", "application/x-git-upload-pack-request", "gzip", "not actually gzip", http.StatusBadRequest},
		{"invalid-identifier", h, http.MethodPost, "/_meta/git-upload-pack", "application/x-git-upload-pack-request", "", "0000", http.StatusBadRequest},
		{"unknown-repo", h, http.MethodPost, "/does-not-exist/git-upload-pack", "application/x-git-upload-pack-request", "", "0000", http.StatusNotFound},
		{"unresolvable-data-dir", hBadDataDir, http.MethodPost, "/repo/git-upload-pack", "application/x-git-upload-pack-request", "", "0000", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			if tt.encoding != "" {
				req.Header.Set("Content-Encoding", tt.encoding)
			}
			rec := httptest.NewRecorder()
			tt.handler.ServeHTTP(rec, req)

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

// seedLargeBlob creates a bare repository under s at repo, seeded with
// one commit containing a single ~size-byte blob of random, incompressible
// data. It exists purely to make upload-pack's output large enough that a
// buffering implementation's memory footprint would be visible against a
// streaming one's.
func seedLargeBlob(t *testing.T, s *store.Store, repo string, size int) {
	t.Helper()

	work := t.TempDir()
	runGit(t, work, "init", "-q", "-b", "main")
	runGit(t, work, "config", "user.email", "test@example.com")
	runGit(t, work, "config", "user.name", "Test")

	blob := make([]byte, size)
	if _, err := rand.Read(blob); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	if err := os.WriteFile(filepath.Join(work, "blob.bin"), blob, 0o644); err != nil {
		t.Fatalf("write blob: %v", err)
	}
	runGit(t, work, "add", "blob.bin")
	runGit(t, work, "commit", "-q", "-m", "big blob")

	barePath, err := s.RepoPath(repo)
	if err != nil {
		t.Fatalf("RepoPath(%q): %v", repo, err)
	}
	runGit(t, t.TempDir(), "clone", "-q", "--bare", work, barePath)
}
