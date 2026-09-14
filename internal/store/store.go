// Package store manages local bare git repositories (the disk cache) and the
// object storage the journal lives in.
// Per ARCHITECTURE.md: "Local disk is a cache; the journal is the truth."
package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/refusal"
)

var (
	ErrRepoNotFound = errors.New("repository not found")
	ErrRepoExists   = errors.New("repository already exists")
	ErrInvalidRepo  = errors.New("invalid repository name")
)

// Store manages bare git repositories under a base data directory.
type Store struct {
	dataDir string
}

// New creates a new Store rooted at dataDir.
func New(dataDir string) *Store {
	return &Store{dataDir: dataDir}
}

// RepoPath validates repo and returns the filesystem path to its bare
// repository.
//
// Validation is two independent layers. auth.ValidateRepo checks the
// published character set and length bounds (spec/auth/v1 §2) — the one
// place that syntax is spelled, and its refusal is returned unchanged.
// RepoPath then checks containment on its own account, as defence in depth
// rather than a restatement: it resolves the data directory to an absolute,
// symlink-resolved root, joins the identifier, and requires the result to
// stay under that root. If the joined path already exists, it is
// symlink-resolved too and re-checked, so a symlink planted in the data
// directory under an otherwise valid identifier cannot point outside.
func (s *Store) RepoPath(repo string) (string, error) {
	if err := auth.ValidateRepo(repo); err != nil {
		return "", err
	}

	root, err := filepath.Abs(s.dataDir)
	if err != nil {
		return "", refusal.RefuseWithCause(
			"invalid repository path",
			err.Error(),
			"verify the data directory is configured correctly",
			ErrInvalidRepo,
		)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", refusal.RefuseWithCause(
			"invalid repository path",
			err.Error(),
			"verify the data directory exists and is accessible",
			ErrInvalidRepo,
		)
	}

	path := filepath.Clean(filepath.Join(root, repo+".git"))
	if !pathWithinRoot(path, root) {
		return "", refusal.RefuseWithCause(
			"invalid repository path",
			"repository path escapes the data directory",
			"this identifier resolves outside the data directory root",
			ErrInvalidRepo,
		)
	}

	if _, err := os.Lstat(path); err == nil {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return "", refusal.RefuseWithCause(
				"invalid repository path",
				err.Error(),
				"verify the repository path is accessible",
				ErrInvalidRepo,
			)
		}
		if !pathWithinRoot(resolved, root) {
			return "", refusal.RefuseWithCause(
				"invalid repository path",
				"repository path escapes the data directory via a symlink",
				"remove or fix the symlink under the data directory",
				ErrInvalidRepo,
			)
		}
	}

	return path, nil
}

// pathWithinRoot reports whether path is root itself or a descendant of it.
// Both arguments must already be absolute and symlink-resolved.
func pathWithinRoot(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+string(os.PathSeparator))
}

// RepositoryManager defines the operations on local repository storage.
type RepositoryManager interface {
	// RepoExists checks if a repository exists on disk.
	RepoExists(ctx context.Context, repo string) (bool, error)
	// CreateRepo initializes a new bare git repository.
	CreateRepo(ctx context.Context, repo string) error
	// RepoPath returns the on-disk path to the repository.
	RepoPath(repo string) (string, error)
}
