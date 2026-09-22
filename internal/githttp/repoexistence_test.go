package githttp_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/store"
)

// repoExistenceRoute describes one of the three git-HTTP entry points that
// resolve a repository's existence, for this file's cross-product tables:
// every state is driven through all three routes with the same loop rather
// than three copied cases, so a fourth entry point cannot drift in later
// without this file growing to cover it.
type repoExistenceRoute struct {
	name        string
	method      string
	path        string // relative to "/<repo>", e.g. "/info/refs?service=git-upload-pack"
	contentType string
	body        string
}

var repoExistenceRoutes = []repoExistenceRoute{
	{
		name:   "info/refs",
		method: http.MethodGet,
		path:   "/info/refs?service=git-upload-pack",
	},
	{
		name:        "upload-pack",
		method:      http.MethodPost,
		path:        "/git-upload-pack",
		contentType: "application/x-git-upload-pack-request",
		body:        "0000",
	},
	{
		name:        "receive-pack",
		method:      http.MethodPost,
		path:        "/git-receive-pack",
		contentType: "application/x-git-receive-pack-request",
		body:        "0000",
	},
}

// doRepoExistenceRequest sends route's request against h for repo,
// authenticated with tok, and returns the response status and body.
func doRepoExistenceRequest(h http.Handler, tok, repo string, route repoExistenceRoute) (int, string) {
	body := strings.NewReader(route.body)
	req := httptest.NewRequest(route.method, "/"+repo+route.path, body)
	if route.contentType != "" {
		req.Header.Set("Content-Type", route.contentType)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// TestRepoExistenceAgreesAcrossEntryPoints pins WALD-110's done-when #2 and
// #3: a regular file and a dangling symlink sitting at a repository's
// resolved path (a FIFO joins them in repoexistence_unix_test.go, which
// needs syscall.Mkfifo) must produce the identical status code and
// byte-identical response body from all three git-HTTP entry points -- the
// way internal/store/repo_test.go's TestCreateRepoNonDirectoryAgreesWithRepoExists
// pins the same agreement across RepoExists and CreateRepo.
//
// A fourth state done-when #2 originally named -- a symlink escaping the
// data root -- is deliberately NOT asserted to agree here: see
// TestRepoExistenceEscapingSymlinkKnownDisagreement below and WALD-125,
// which owns closing that gap.
func TestRepoExistenceAgreesAcrossEntryPoints(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, dataDir, path string)
	}{
		{
			name: "regular-file",
			setup: func(t *testing.T, dataDir, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("not a repo"), 0o644); err != nil {
					t.Fatalf("WriteFile(%q): %v", path, err)
				}
			},
		},
		{
			name: "dangling-symlink",
			setup: func(t *testing.T, dataDir, path string) {
				t.Helper()
				target := filepath.Join(dataDir, "nonexistent-target")
				if err := os.Symlink(target, path); err != nil {
					t.Fatalf("Symlink(%q, %q): %v", target, path, err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataDir := t.TempDir()
			s := store.New(dataDir)
			const repo = "target"
			path, err := s.RepoPath(repo)
			if err != nil {
				t.Fatalf("RepoPath(%q): %v", repo, err)
			}
			tt.setup(t, dataDir, path)

			h, tok := newTestHandler(t, s, "")

			type result struct {
				route  string
				status int
				body   string
			}
			var results []result
			for _, route := range repoExistenceRoutes {
				status, body := doRepoExistenceRequest(h, tok, repo, route)
				results = append(results, result{route.name, status, body})

				if status != http.StatusInternalServerError {
					t.Errorf("%s: status = %d, want %d", route.name, status, http.StatusInternalServerError)
				}
				// Matches secrets_test.go's positive-control-500 discipline:
				// an operator-fault 500 must never put the data directory's
				// absolute path on the wire.
				if strings.Contains(body, dataDir) {
					t.Errorf("%s: response body contains the data directory path %q: %q", route.name, dataDir, body)
				}
			}

			for i := 1; i < len(results); i++ {
				if results[i].status != results[0].status {
					t.Errorf("%s status = %d, %s status = %d, want agreement",
						results[0].route, results[0].status, results[i].route, results[i].status)
				}
				if results[i].body != results[0].body {
					t.Errorf("%s body = %q, %s body = %q, want byte-identical",
						results[0].route, results[0].body, results[i].route, results[i].body)
				}
			}
		})
	}
}

// TestRepoExistenceEscapingSymlinkKnownDisagreement pins the CURRENT,
// pre-existing disagreement WALD-110's implementer found (and confirmed with
// a throwaway probe test) and that was split out as WALD-125: a symlink at a
// repository's resolved path that escapes the data root classifies as
// store.ErrInvalidRepo, not store.ErrStoreUnavailable. writeAuthRefusal's
// ErrStoreUnavailable case (added by this ticket) does not reach it, so
// info/refs and upload-pack (resolveRepoDir: "any other RepoPath refusal ->
// 400") answer 400, while receive-pack (writeAuthRefusal's unmatched default
// branch) answers 500. This is deliberately asserted as a disagreement, not
// papered over as if the routes agreed.
//
// WALD-125-DELETE-THIS-TEST-WHEN-CLOSED: WALD-125 owns converging this state
// onto one answer -- 400 or 500, decided there, and it may require
// reclassifying a store sentinel rather than adding a handler case. When it
// lands, whichever route's status changes will fail the assertions below;
// delete this test and fold the case into TestRepoExistenceAgreesAcrossEntryPoints
// above instead of editing the expectations here, so the diff shows the
// state moving from "known disagreement" to "agrees."
func TestRepoExistenceEscapingSymlinkKnownDisagreement(t *testing.T) {
	dataDir := t.TempDir()
	outside := t.TempDir()
	s := store.New(dataDir)
	const repo = "escapee"
	path, err := s.RepoPath(repo)
	if err != nil {
		t.Fatalf("RepoPath(%q): %v", repo, err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatalf("Symlink(%q, %q): %v", outside, path, err)
	}

	h, tok := newTestHandler(t, s, "")

	wantStatus := map[string]int{
		"info/refs":    http.StatusBadRequest,
		"upload-pack":  http.StatusBadRequest,
		"receive-pack": http.StatusInternalServerError,
	}

	for _, route := range repoExistenceRoutes {
		status, body := doRepoExistenceRequest(h, tok, repo, route)
		if want := wantStatus[route.name]; status != want {
			t.Errorf("%s: status = %d, want %d (this pins the pre-WALD-125 disagreement; "+
				"if this now fails, WALD-125 likely landed -- delete this test rather than "+
				"adjusting the expectation)", route.name, status, want)
		}
		if strings.Contains(body, dataDir) || strings.Contains(body, outside) {
			t.Errorf("%s: response body contains the data directory or escape-target path: %q", route.name, body)
		}
	}
}

// repoExistenceRouteByName returns the route named name from
// repoExistenceRoutes. A test that is deliberately about one entry point
// drives the same request the cross-product tests above drive, rather than
// spelling a second copy of it that could drift from them.
func repoExistenceRouteByName(t *testing.T, name string) repoExistenceRoute {
	t.Helper()
	for _, route := range repoExistenceRoutes {
		if route.name == name {
			return route
		}
	}
	t.Fatalf("no route named %q in repoExistenceRoutes", name)
	return repoExistenceRoute{}
}

// resolutionFailureBody drives the resolution-side ErrStoreUnavailable -- a
// regular file sitting at a repository's path, the state
// TestRepoExistenceAgreesAcrossEntryPoints pins -- through route and returns
// the response body. The creation-side test below compares against the wording
// this build actually produces rather than against a string literal, so the two
// branches of writeAuthRefusal's ErrStoreUnavailable case cannot quietly
// converge on one message.
func resolutionFailureBody(t *testing.T, route repoExistenceRoute) string {
	t.Helper()
	dataDir := t.TempDir()
	s := store.New(dataDir)
	const repo = "occupied"
	path, err := s.RepoPath(repo)
	if err != nil {
		t.Fatalf("RepoPath(%q): %v", repo, err)
	}
	if err := os.WriteFile(path, []byte("not a repo"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
	h, tok := newTestHandler(t, s, "")
	status, body := doRepoExistenceRequest(h, tok, repo, route)
	if status != http.StatusInternalServerError {
		t.Fatalf("resolution-side control: %s status = %d, want %d; body %q",
			route.name, status, http.StatusInternalServerError, body)
	}
	return body
}

// TestRepoCreationFailureSaysCreationNotResolution pins the other half of
// writeAuthRefusal's ErrStoreUnavailable case: create.go's repoCreateError
// wrap. Both halves refuse with 500 and both wrap store.ErrStoreUnavailable,
// so nothing about the status code or the sentinel distinguishes them -- only
// the wording does, and only because ensureRepoForPush marks the error
// CreateRepo returned. Remove that wrap and this test is what goes red: the
// operator whose data directory is unwritable, or whose git binary is missing,
// is told the server could not resolve the repository path, when the path
// resolved fine and the creation is what failed.
//
// receive-pack is the only route that can reach this branch, because it is the
// only one that ever creates a repository.
func TestRepoCreationFailureSaysCreationNotResolution(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, dataDir string)
	}{
		{
			// The operator-facing case the reviewer named: the data
			// directory resolves and the repository is genuinely absent, but
			// CreateRepo's MkdirTemp cannot write the staging directory.
			name: "unwritable-data-dir",
			setup: func(t *testing.T, dataDir string) {
				t.Helper()
				if err := os.Chmod(dataDir, 0o555); err != nil {
					t.Fatalf("Chmod(%q, 0o555): %v", dataDir, err)
				}
				t.Cleanup(func() {
					// Restore write permission so t.TempDir's own cleanup can
					// remove the directory on every platform.
					_ = os.Chmod(dataDir, 0o700)
				})
				probe := filepath.Join(dataDir, ".write-probe")
				if err := os.Mkdir(probe, 0o700); err == nil {
					_ = os.Remove(probe)
					t.Skipf("LOUD SKIP: %q is still writable at mode 0555, so this process cannot simulate an unwritable data directory -- it is running as root, or on a filesystem that ignores mode bits. The git-not-on-PATH case of this same test exercises the identical repoCreateError wrap and never skips, so the wrap is still covered here.", dataDir)
				}
			},
		},
		{
			// The second failure CreateRepo names, and the one that needs no
			// permission games: it runs as root, and on a filesystem that
			// ignores mode bits, so this test never reports zero coverage of
			// the wrap.
			name: "git-not-on-PATH",
			setup: func(t *testing.T, dataDir string) {
				t.Helper()
				t.Setenv("PATH", "")
			},
		},
	}

	route := repoExistenceRouteByName(t, "receive-pack")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataDir := t.TempDir()
			s := store.New(dataDir)
			const repo = "newrepo"

			// The store is built before the data directory is broken: the
			// repository must be genuinely missing and the path must resolve,
			// so the refusal can only come from CreateRepo.
			tt.setup(t, dataDir)

			h, tok := newTestHandler(t, s, "")
			status, body := doRepoExistenceRequest(h, tok, repo, route)

			if status != http.StatusInternalServerError {
				t.Fatalf("status = %d, want %d; body %q", status, http.StatusInternalServerError, body)
			}
			if !strings.Contains(body, "could not create the repository") {
				t.Errorf("body = %q, want it to describe a creation failure (%q)", body, "could not create the repository")
			}
			if strings.Contains(body, "could not resolve the repository path") {
				t.Errorf("body = %q describes a path-resolution failure, but the path resolved and CreateRepo is what failed", body)
			}
			if other := resolutionFailureBody(t, route); body == other {
				t.Errorf("creation-failure body %q is byte-identical to the resolution-failure body; the two must stay distinguishable", body)
			}
			// Mechanical rule 6: one line, and nothing else.
			if trimmed := strings.TrimRight(body, "\n"); strings.Contains(trimmed, "\n") {
				t.Errorf("refusal body contains an embedded newline: %q", trimmed)
			}
			// Matches secrets_test.go's positive-control-500 discipline: an
			// operator-fault 500 must never put the data directory's absolute
			// path on the wire.
			if strings.Contains(body, dataDir) {
				t.Errorf("response body contains the data directory path %q: %q", dataDir, body)
			}
		})
	}
}

// TestNoDirectRepositoryStat pins done-when #1: no git-HTTP handler calls
// os.Stat on a repository path directly -- existence is decided in exactly
// one place, store.ResolveRepo, and every entry point asks it rather than
// the filesystem. This is the direct-grep check the plan names
// ("grep -n \"os.Stat\" internal/githttp/*.go returns nothing outside
// _test.go files"), run as part of the suite rather than left as a
// side-channel check a future change could silently fail.
func TestNoDirectRepositoryStat(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(\".\"): %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("ReadFile(%q): %v", name, err)
		}
		if strings.Contains(string(data), "os.Stat") {
			t.Errorf("%s calls os.Stat directly; repository existence must be decided through store.ResolveRepo", name)
		}
	}
}
