// Package store manages local bare git repositories (the disk cache) and the
// object storage the journal lives in.
// Per ARCHITECTURE.md: "Local disk is a cache; the journal is the truth."
package store

import (
	"context"
	"errors"
	"path/filepath"
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

// RepoPath returns the filesystem path to a bare repository.
func (s *Store) RepoPath(repo string) string {
	return filepath.Join(s.dataDir, repo+".git")
}

// RepositoryManager defines the operations on local repository storage.
type RepositoryManager interface {
	// RepoExists checks if a repository exists on disk.
	RepoExists(ctx context.Context, repo string) (bool, error)
	// CreateRepo initializes a new bare git repository.
	CreateRepo(ctx context.Context, repo string) error
	// RepoPath returns the on-disk path to the repository.
	RepoPath(repo string) string
}
