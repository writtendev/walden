package store_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/store"
)

func TestStoreRepoPath(t *testing.T) {
	dataDir := t.TempDir()

	// On darwin, t.TempDir() sits under a symlinked /var
	// (/var -> /private/var), so the expected path has to be built from the
	// same EvalSymlinks-resolved root RepoPath itself resolves against.
	// Comparing against the raw t.TempDir() string passes on Linux CI and
	// fails locally on a Mac.
	resolvedRoot, err := filepath.EvalSymlinks(dataDir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", dataDir, err)
	}

	// A syntactically valid identifier whose path is, on disk, a symlink to
	// somewhere outside the data directory entirely.
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dataDir, "evil.git")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	s := store.New(dataDir)

	tests := []struct {
		name    string
		repo    string
		wantErr error
	}{
		{"traversal-dotdot", "..", auth.ErrInvalidRepo},
		{"traversal-dotdot-dotdot", "../..", auth.ErrInvalidRepo},
		{"traversal-etc", "../../etc", auth.ErrInvalidRepo},
		{"traversal-embedded", "repo/../../etc", auth.ErrInvalidRepo},
		{"absolute-etc-passwd", "/etc/passwd", auth.ErrInvalidRepo},
		{"absolute-root", "/", auth.ErrInvalidRepo},
		{"separator-forward", "a/b", auth.ErrInvalidRepo},
		{"separator-backward", `a\b`, auth.ErrInvalidRepo},
		{"reserved-meta", "_meta", auth.ErrInvalidRepo},
		{"empty", "", auth.ErrInvalidRepo},
		{"whitespace-name", "repo name", auth.ErrInvalidRepo},
		{"control-character", "repo\nname", auth.ErrInvalidRepo},
		{"symlink-escape", "evil", store.ErrInvalidRepo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.RepoPath(tt.repo)
			if err == nil {
				t.Fatalf("RepoPath(%q) = %q, want error", tt.repo, got)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("RepoPath(%q): expected error matching %v, got %v", tt.repo, tt.wantErr, err)
			}
			if strings.Contains(err.Error(), "\n") {
				t.Errorf("RepoPath(%q): refusal contains newline: %q", tt.repo, err.Error())
			}
		})
	}

	t.Run("valid-repo", func(t *testing.T) {
		got, err := s.RepoPath("my-repo")
		if err != nil {
			t.Fatalf("RepoPath(%q): unexpected error: %v", "my-repo", err)
		}
		want := filepath.Join(resolvedRoot, "my-repo.git")
		if got != want {
			t.Errorf("RepoPath(%q) = %q, want %q", "my-repo", got, want)
		}
	})
}

// TestStoreRepoPathUnresolvableDataDir asserts that a missing or unreadable
// data directory — a server misconfiguration, not a caller fault — is
// refused with store.ErrStoreUnavailable, and specifically not with
// store.ErrInvalidRepo, even though the identifier itself is valid.
func TestStoreRepoPathUnresolvableDataDir(t *testing.T) {
	s := store.New(filepath.Join(t.TempDir(), "does-not-exist"))

	got, err := s.RepoPath("my-repo")
	if err == nil {
		t.Fatalf("RepoPath(%q) = %q, want error", "my-repo", got)
	}
	if !errors.Is(err, store.ErrStoreUnavailable) {
		t.Errorf("RepoPath(%q): expected error matching %v, got %v", "my-repo", store.ErrStoreUnavailable, err)
	}
	if errors.Is(err, store.ErrInvalidRepo) {
		t.Errorf("RepoPath(%q): error incorrectly also matches store.ErrInvalidRepo: %v", "my-repo", err)
	}
	if strings.Contains(err.Error(), "\n") {
		t.Errorf("RepoPath(%q): refusal contains newline: %q", "my-repo", err.Error())
	}
}

// TestStoreRepoPathRootDataDir asserts that a data directory of "/" still
// resolves a valid identifier instead of refusing it: pathWithinRoot must
// not build a prefix of "//" out of a root that is already "/".
func TestStoreRepoPathRootDataDir(t *testing.T) {
	s := store.New(string(os.PathSeparator))

	got, err := s.RepoPath("my-repo")
	if err != nil {
		t.Fatalf("RepoPath(%q): unexpected error: %v", "my-repo", err)
	}
	want := string(os.PathSeparator) + "my-repo.git"
	if got != want {
		t.Errorf("RepoPath(%q) = %q, want %q", "my-repo", got, want)
	}
}
