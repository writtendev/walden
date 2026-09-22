package githttp_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/store"
)

// TestHookPresenceDoesNotGateReads is the assertion that pins where the hook check lives.
// A repository whose pre-receive hook is missing, or is an operator's own script, still
// serves info/refs and upload-pack exactly as a healthy one does: a clone off a repository
// whose pushes are undurable is not itself dangerous, and refusing it would turn a
// durability defect into an availability outage for the one operator trying to get the
// bytes off the box.
//
// It is written against the same three routes as repoexistence_test.go, and it is what goes
// red if the check is ever moved into store.ResolveRepo — which all three share.
func TestHookPresenceDoesNotGateReads(t *testing.T) {
	readRoutes := []repoExistenceRoute{
		repoExistenceRouteByName(t, "info/refs"),
		repoExistenceRouteByName(t, "upload-pack"),
	}

	tests := []struct {
		name   string
		damage func(t *testing.T, hook string)
	}{
		{
			name: "no-hook-at-all",
			damage: func(t *testing.T, hook string) {
				t.Helper()
				if err := os.Remove(hook); err != nil {
					t.Fatalf("Remove(%q): %v", hook, err)
				}
			},
		},
		{
			name: "operator-placed-hook-walden-will-not-replace",
			damage: func(t *testing.T, hook string) {
				t.Helper()
				if err := os.Remove(hook); err != nil {
					t.Fatalf("Remove(%q): %v", hook, err)
				}
				if err := os.WriteFile(hook, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
					t.Fatalf("WriteFile(%q): %v", hook, err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := store.New(t.TempDir())
			createRepoForTest(t, s, "healthy")
			broken := createRepoForTest(t, s, "broken")
			hook := filepath.Join(broken, "hooks", "pre-receive")
			tt.damage(t, hook)

			before, beforeErr := os.Lstat(hook)

			h, tok := newTestHandler(t, s, "")
			for _, route := range readRoutes {
				wantStatus, wantBody := doRepoExistenceRequest(h, tok, "healthy", route)
				gotStatus, gotBody := doRepoExistenceRequest(h, tok, "broken", route)

				if gotStatus != wantStatus {
					t.Errorf("%s: status = %d for a repository without walden's hook, want %d — the same as a healthy one", route.name, gotStatus, wantStatus)
				}
				if gotBody != wantBody {
					t.Errorf("%s: body = %q for a repository without walden's hook, want %q — a read must not notice", route.name, gotBody, wantBody)
				}
			}

			// A read path writes nothing: hooks/pre-receive is in the same state the reads
			// found it in, missing or foreign as it was. Nothing was repaired on a read.
			after, afterErr := os.Lstat(hook)
			if (beforeErr == nil) != (afterErr == nil) {
				t.Fatalf("hooks/pre-receive changed existence across the reads (before %v, after %v)", beforeErr, afterErr)
			}
			if beforeErr == nil && !before.ModTime().Equal(after.ModTime()) {
				t.Errorf("hooks/pre-receive was rewritten by a read (mtime %v -> %v)", before.ModTime(), after.ModTime())
			}
		})
	}
}

// TestHookPresenceRepairsOnPush is the write half: the same repository that served those
// reads untouched has walden's hook installed by the push route before git ever sees it.
func TestHookPresenceRepairsOnPush(t *testing.T) {
	s := store.New(t.TempDir())
	path := createRepoForTest(t, s, "repo")
	hook := filepath.Join(path, "hooks", "pre-receive")
	if err := os.Remove(hook); err != nil {
		t.Fatalf("Remove(%q): %v", hook, err)
	}

	h, tok := newTestHandler(t, s, "")
	route := repoExistenceRouteByName(t, "receive-pack")
	status, body := doRepoExistenceRequest(h, tok, "repo", route)
	if status != http.StatusOK {
		t.Fatalf("receive-pack status = %d, want %d; body %q", status, http.StatusOK, body)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	target, err := os.Readlink(hook)
	if err != nil {
		t.Fatalf("Readlink(%q): %v, want the push to have installed walden's hook", hook, err)
	}
	if target != exe {
		t.Errorf("hooks/pre-receive -> %q, want %q", target, exe)
	}
}

// TestHookPresenceRefusesPushThroughForeignHook is the refusal on the wire: one line, a 500,
// no filesystem path in the body, and wording that says the hook is the problem rather than
// repeating the path-resolution sentence repoexistence_test.go pins for a different failure.
func TestHookPresenceRefusesPushThroughForeignHook(t *testing.T) {
	dataDir := t.TempDir()
	s := store.New(dataDir)
	path := createRepoForTest(t, s, "repo")
	hook := filepath.Join(path, "hooks", "pre-receive")
	if err := os.Remove(hook); err != nil {
		t.Fatalf("Remove(%q): %v", hook, err)
	}
	if err := os.WriteFile(hook, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(%q): %v", hook, err)
	}

	h, tok := newTestHandler(t, s, "")
	route := repoExistenceRouteByName(t, "receive-pack")
	status, body := doRepoExistenceRequest(h, tok, "repo", route)

	if status != http.StatusInternalServerError {
		t.Fatalf("receive-pack status = %d, want %d; body %q", status, http.StatusInternalServerError, body)
	}
	if !strings.Contains(body, "hook") {
		t.Errorf("body = %q, want it to name the hook as the problem", body)
	}
	if strings.Contains(body, "could not resolve the repository path") {
		t.Errorf("body = %q describes a path-resolution failure; the path resolved and the hook is what failed", body)
	}
	// Mechanical rule 6: one line, and nothing else.
	if trimmed := strings.TrimRight(body, "\n"); strings.Contains(trimmed, "\n") {
		t.Errorf("refusal body contains an embedded newline: %q", trimmed)
	}
	// Matches secrets_test.go's positive-control-500 discipline: an operator-fault 500 must
	// never put the data directory's absolute path on the wire.
	if strings.Contains(body, dataDir) {
		t.Errorf("response body contains the data directory path %q: %q", dataDir, body)
	}
}

// createRepoForTest publishes repo through walden's own creation path — hook and all — and
// returns its on-disk path, so a test can then break exactly one thing about it.
func createRepoForTest(t *testing.T, s *store.Store, repo string) string {
	t.Helper()

	if err := s.CreateRepo(context.Background(), repo); err != nil {
		t.Fatalf("CreateRepo(%q): %v", repo, err)
	}
	path, err := s.RepoPath(repo)
	if err != nil {
		t.Fatalf("RepoPath(%q): %v", repo, err)
	}
	return path
}
