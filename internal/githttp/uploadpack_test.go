package githttp_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"io"
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

	h, tok := newTestHandler(t, s, "")
	server := httptest.NewServer(h)
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
			lsArgs := append(append([]string{}, tt.args...), "ls-remote", authURL(server.URL, tok)+"/repo")
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
			cloneArgs := append(append([]string{}, tt.args...), "clone", "-q", authURL(server.URL, tok)+"/repo", dest)
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

// TestUploadPackGzipInflate proves the Content-Encoding: gzip branch
// actually inflates the request body before handing it to git's stdin,
// rather than streaming the still-compressed bytes straight through — a
// regression TestUploadPackRealClient cannot catch, because git only
// gzips a request body once it crosses git's own internal size
// threshold, and that fixture's single-branch, single-commit repo never
// gets close (a real clone against it sends 182 uncompressed bytes on
// its git-upload-pack POST). Reaching that threshold with a real client
// takes hundreds of refs — expensive to fixture and slow to run just to
// pin one branch of requestBodyReader.
//
// Instead, a thin handler sits in front of the real one: it lets a real
// `git clone`'s request through untouched except for gzip-compressing
// its git-upload-pack body itself and setting Content-Encoding: gzip —
// the client never knows its request was recompressed in flight. That
// drives the exact same code this endpoint would run against a
// gzip-choosing real client (a real client's own protocol bytes,
// genuinely inflated by requestBodyReader, fed to a real git
// upload-pack, and validated by a real git clone), without needing a
// large fixture. If the gzip branch ever regressed to streaming the
// still-compressed bytes raw (or closed the reader before git could
// read it), git upload-pack would choke on the compressed stream and
// the clone below would fail outright — confirmed by temporarily
// reverting requestBodyReader's gzip branch to "return r.Body, true"
// and observing this test fail with a git protocol error.
func TestUploadPackGzipInflate(t *testing.T) {
	s := store.New(t.TempDir())
	wantSHA := newBareRepoWithCommit(t, s, "repo")

	real, tok := newTestHandler(t, s, "")
	forceGzip := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/git-upload-pack") {
			real.ServeHTTP(w, r)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var compressed bytes.Buffer
		gz := gzip.NewWriter(&compressed)
		if _, err := gz.Write(body); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := gz.Close(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		r.Body = io.NopCloser(&compressed)
		r.ContentLength = int64(compressed.Len())
		r.Header.Set("Content-Encoding", "gzip")
		real.ServeHTTP(w, r)
	})
	server := httptest.NewServer(forceGzip)
	defer server.Close()

	dest := filepath.Join(t.TempDir(), "clone")
	cmd := exec.Command("git", "clone", "-q", authURL(server.URL, tok)+"/repo", dest)
	cmd.Dir = t.TempDir()
	cmd.Env = gitClientEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git clone through gzip-forcing proxy: %v\n%s", err, out)
	}

	gotSHA := strings.TrimSpace(runGit(t, dest, "rev-parse", "HEAD"))
	if gotSHA != wantSHA {
		t.Errorf("cloned HEAD = %q, want %q", gotSHA, wantSHA)
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

	h, tok := newTestHandler(t, s, "")
	server := httptest.NewServer(h)
	defer server.Close()

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	dest := filepath.Join(t.TempDir(), "clone")
	cmd := exec.Command("git", "clone", "-q", authURL(server.URL, tok)+"/big", dest)
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
	// this is a real regression detector, not a flake. Measured on this
	// handler the actual delta is ~515 KiB against a 16 MiB blob, so a
	// blobSize/10 threshold (1.6 MiB) still leaves ~3x headroom above
	// the real number while catching several MiB of accidental
	// per-request buffering that a looser bar would miss.
	const threshold = blobSize / 10
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
	authorizer, tok := newTestAuthorizer(t, "rw:*")
	h := githttp.NewHandler(authorizer, s, "")

	// A data directory that cannot be resolved at all, for the 500 case
	// — the same technique internal/store's own
	// TestStoreRepoPathUnresolvableDataDir uses.
	badStore := store.New(filepath.Join(t.TempDir(), "does-not-exist"))
	hBadDataDir := githttp.NewHandler(authorizer, badStore, "")

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
			req.Header.Set("Authorization", "Bearer "+tok)
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

// captureRawUploadPackRequest runs a real `git clone` against a recording
// server that answers the info/refs negotiation with the real handler but
// intercepts the POST .../git-upload-pack request, capturing the exact bytes
// git put on the wire for the fetch/clone negotiation.
func captureRawUploadPackRequest(t *testing.T, s *store.Store, repo string) ([]byte, string) {
	t.Helper()

	var captured []byte
	var proto string
	authorizer, tok := newTestAuthorizer(t, "rwc:*")
	recorder := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git-upload-pack") {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("reading captured request body: %v", err)
			}
			captured = b
			proto = r.Header.Get("Git-Protocol")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		githttp.NewHandler(authorizer, s, "").ServeHTTP(w, r)
	})
	server := httptest.NewServer(recorder)
	defer server.Close()

	dest := filepath.Join(t.TempDir(), "clone")
	cmd := exec.Command("git", "clone", "-q", authURL(server.URL, tok)+"/"+repo, dest)
	cmd.Dir = t.TempDir()
	cmd.Env = gitClientEnv()
	_, _ = cmd.CombinedOutput()

	if len(captured) == 0 {
		t.Fatal("did not capture a git-upload-pack request body")
	}
	return captured, proto
}

// TestUploadPackStreamingDoesNotHangOnDeadBody reproduces round 1's major finding:
// a client that over-declares its Content-Length by announcing more bytes than sent
// on a fetch/clone request previously hung indefinitely after git finished streaming
// the packfile, because proc.wait() blocked waiting for os/exec's stdin-copy
// goroutine to read the missing body bytes. Calling proc.waitSettled() ensures the
// grace period elapses and release() sets an expired read deadline, terminating
// the response cleanly.
func TestUploadPackStreamingDoesNotHangOnDeadBody(t *testing.T) {
	s := store.New(t.TempDir())
	newBareRepoWithCommit(t, s, "target")
	raw, proto := captureRawUploadPackRequest(t, s, "target")

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

	// Content-Length is declared to be 100 bytes larger than what is actually sent.
	request := "POST /target/git-upload-pack HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Authorization: Bearer " + tok + "\r\n" +
		"Content-Type: application/x-git-upload-pack-request\r\n"
	if proto != "" {
		request += "Git-Protocol: " + proto + "\r\n"
	}
	request += "Content-Length: " + strconv.Itoa(len(raw)+100) + "\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("write request headers: %v", err)
	}
	if _, err := conn.Write(raw); err != nil {
		t.Fatalf("write request body: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("did not receive response within 5s: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("did not receive the end of the response body within 5s -- this is the hang this test guards against: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, http.StatusOK, body)
	}
	if len(body) == 0 {
		t.Errorf("expected non-empty pack response body")
	}
}
