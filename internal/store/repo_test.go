package store_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/store"
)

// TestCreateRepoAndRepoExists exercises the happy path against a real git binary: a fresh
// identifier goes from RepoExists = false to a bare repository on disk, with a
// hooks/pre-receive symlink resolving to the running binary (the test binary itself, in this
// case — CreateRepo uses os.Executable(), whatever process that is) and executable.
func TestCreateRepoAndRepoExists(t *testing.T) {
	ctx := context.Background()
	s := store.New(t.TempDir())

	exists, err := s.RepoExists(ctx, "newrepo")
	if err != nil {
		t.Fatalf("RepoExists before creation: %v", err)
	}
	if exists {
		t.Fatalf("RepoExists before creation = true, want false")
	}

	if err := s.CreateRepo(ctx, "newrepo"); err != nil {
		t.Fatalf("CreateRepo: %v", err)
	}

	exists, err = s.RepoExists(ctx, "newrepo")
	if err != nil {
		t.Fatalf("RepoExists after creation: %v", err)
	}
	if !exists {
		t.Fatalf("RepoExists after creation = false, want true")
	}

	path, err := s.RepoPath("newrepo")
	if err != nil {
		t.Fatalf("RepoPath: %v", err)
	}

	out, err := exec.CommandContext(ctx, "git", "-C", path, "rev-parse", "--is-bare-repository").Output()
	if err != nil {
		t.Fatalf("git rev-parse --is-bare-repository: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "true" {
		t.Errorf("git rev-parse --is-bare-repository = %q, want %q", got, "true")
	}

	hook := filepath.Join(path, "hooks", "pre-receive")
	target, err := os.Readlink(hook)
	if err != nil {
		t.Fatalf("Readlink(%q): %v", hook, err)
	}
	wantTarget, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	if target != wantTarget {
		t.Errorf("hooks/pre-receive -> %q, want %q", target, wantTarget)
	}
	info, err := os.Stat(hook)
	if err != nil {
		t.Fatalf("Stat(%q): %v", hook, err)
	}
	if info.Mode()&0o111 == 0 {
		t.Errorf("hooks/pre-receive is not executable: mode %v", info.Mode())
	}
}

// TestCreateRepoTwiceRefusesSecond asserts that creating the same repository twice refuses
// the second call with store.ErrRepoExists rather than reinitializing over it, and that the
// first repository is left untouched by the attempt.
func TestCreateRepoTwiceRefusesSecond(t *testing.T) {
	ctx := context.Background()
	s := store.New(t.TempDir())

	if err := s.CreateRepo(ctx, "dup"); err != nil {
		t.Fatalf("first CreateRepo: %v", err)
	}

	path, err := s.RepoPath("dup")
	if err != nil {
		t.Fatalf("RepoPath: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) after first create: %v", path, err)
	}

	err = s.CreateRepo(ctx, "dup")
	if err == nil {
		t.Fatalf("second CreateRepo = nil, want error")
	}
	if !errors.Is(err, store.ErrRepoExists) {
		t.Errorf("second CreateRepo error = %v, want errors.Is store.ErrRepoExists", err)
	}
	if strings.Contains(err.Error(), "\n") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) after second create attempt: %v", path, err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Errorf("first repository was modified by the second CreateRepo attempt: mtime %v -> %v", before.ModTime(), after.ModTime())
	}
}

// TestRepoExistsAndCreateRepoRejectInvalidIdentifiers asserts that both methods return
// WALD-37's identifier refusals unchanged for identifiers RepoPath rejects, and that
// rejecting one of them never leaves anything behind on disk.
func TestRepoExistsAndCreateRepoRejectInvalidIdentifiers(t *testing.T) {
	ctx := context.Background()
	longName := strings.Repeat("a", 101)

	for _, repo := range []string{"_meta", "..", "a/b", longName} {
		t.Run(repo, func(t *testing.T) {
			dataDir := t.TempDir()
			s := store.New(dataDir)

			if exists, err := s.RepoExists(ctx, repo); err == nil {
				t.Fatalf("RepoExists(%q) = %v, nil, want error", repo, exists)
			} else if !errors.Is(err, auth.ErrInvalidRepo) {
				t.Errorf("RepoExists(%q) error = %v, want errors.Is auth.ErrInvalidRepo", repo, err)
			}

			if err := s.CreateRepo(ctx, repo); err == nil {
				t.Fatalf("CreateRepo(%q) = nil, want error", repo)
			} else if !errors.Is(err, auth.ErrInvalidRepo) {
				t.Errorf("CreateRepo(%q) error = %v, want errors.Is auth.ErrInvalidRepo", repo, err)
			}

			entries, err := os.ReadDir(dataDir)
			if err != nil {
				t.Fatalf("ReadDir(%q): %v", dataDir, err)
			}
			if len(entries) != 0 {
				t.Errorf("rejecting %q left %d entries in the data directory, want 0: %v", repo, len(entries), entries)
			}
		})
	}
}

// TestRepoExistsNonDirectory asserts that a file (not a directory) sitting at a repository's
// resolved path is an operator-fault refusal, not a "does not exist" answer that would send a
// caller into CreateRepo for a confusing second failure.
func TestRepoExistsNonDirectory(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	s := store.New(dataDir)

	path, err := s.RepoPath("blocked")
	if err != nil {
		t.Fatalf("RepoPath: %v", err)
	}
	if err := os.WriteFile(path, []byte("not a repo"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}

	exists, err := s.RepoExists(ctx, "blocked")
	if err == nil {
		t.Fatalf("RepoExists(%q) = %v, nil, want error", "blocked", exists)
	}
	if !errors.Is(err, store.ErrStoreUnavailable) {
		t.Errorf("RepoExists error = %v, want errors.Is store.ErrStoreUnavailable", err)
	}
	if exists {
		t.Errorf("RepoExists(%q) reported true alongside an error", "blocked")
	}
	if strings.Contains(err.Error(), "\n") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
}

// TestCreateRepoAtomicPublishOnGitFailure makes the atomic-publish claim real rather than
// asserted in prose: it forces `git init` itself to fail (a fake "git" on PATH that exits
// non-zero, found and run in place of the real binary) after CreateRepo has already created
// its temporary sibling directory, and checks that no ".create-*" directory — or anything
// else — survives in the data directory, and that RepoExists still reports false.
func TestCreateRepoAtomicPublishOnGitFailure(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	s := store.New(dataDir)

	fakeGitDir := t.TempDir()
	const failureMarker = "fake git init failure marker"
	script := "#!/bin/sh\necho '" + failureMarker + "' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(fakeGitDir, "git"), []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile fake git: %v", err)
	}
	t.Setenv("PATH", fakeGitDir)

	err := s.CreateRepo(ctx, "willfail")
	if err == nil {
		t.Fatalf("CreateRepo = nil, want error")
	}
	if !errors.Is(err, store.ErrStoreUnavailable) {
		t.Errorf("CreateRepo error = %v, want errors.Is store.ErrStoreUnavailable", err)
	}
	// The fake git's stderr must surface in the refusal: this is what proves `git init`
	// itself ran and failed, rather than "git" simply being unresolvable on PATH — a
	// distinction that matters because both would otherwise look identical from here.
	if !strings.Contains(err.Error(), failureMarker) {
		t.Errorf("CreateRepo error = %q, want it to contain the fake git's stderr %q", err.Error(), failureMarker)
	}
	if strings.Contains(err.Error(), "\n") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}

	entries, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dataDir, err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".create-") {
			t.Errorf("temp directory %q survived a forced git init failure", e.Name())
		}
	}
	if len(entries) != 0 {
		t.Errorf("data directory has %d entries after a failed CreateRepo, want 0: %v", len(entries), entries)
	}

	exists, err := s.RepoExists(ctx, "willfail")
	if err != nil {
		t.Fatalf("RepoExists after failed create: %v", err)
	}
	if exists {
		t.Errorf("RepoExists after failed create = true, want false")
	}
}
