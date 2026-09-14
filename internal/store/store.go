// Package store manages local bare git repositories (the disk cache) and the
// object storage the journal lives in.
// Per ARCHITECTURE.md: "Local disk is a cache; the journal is the truth."
package store

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/refusal"
)

var (
	ErrRepoNotFound = errors.New("repository not found")
	ErrRepoExists   = errors.New("repository already exists")
	// ErrInvalidRepo marks a caller-fault refusal: the identifier failed
	// the published syntax rules, or a syntactically valid identifier's
	// path escapes the data directory.
	ErrInvalidRepo = errors.New("invalid repository name")
	// ErrStoreUnavailable marks an operator-fault refusal: the data
	// directory, or a repository's on-disk path within it, could not be
	// resolved. This is independent of whether the caller's identifier is
	// valid, so it never aliases ErrInvalidRepo — a missing or unreadable
	// data directory is a server misconfiguration, not a bad repository
	// name.
	ErrStoreUnavailable = errors.New("repository storage unavailable")
)

// Store manages bare git repositories under a base data directory.
type Store struct {
	dataDir string
}

// New creates a new Store rooted at dataDir.
func New(dataDir string) *Store {
	return &Store{dataDir: dataDir}
}

// DataDir returns the store's configured root directory, unresolved and
// unvalidated. The receive-pack handler forwards this value to the
// pre-receive hook as WALDEN_DATA_DIR, so the hook can resolve repository
// paths without a config file of its own; passing the same path to
// NewHandler a second time would invite the two copies to disagree.
func (s *Store) DataDir() string {
	return s.dataDir
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
			"data directory unavailable",
			err.Error(),
			"verify the data directory is configured correctly",
			ErrStoreUnavailable,
		)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", refusal.RefuseWithCause(
			"data directory unavailable",
			err.Error(),
			"verify the data directory exists and is accessible",
			ErrStoreUnavailable,
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

	switch _, err := os.Lstat(path); {
	case err == nil:
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return "", refusal.RefuseWithCause(
				"repository path unavailable",
				err.Error(),
				"verify the repository path is accessible",
				ErrStoreUnavailable,
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
	case errors.Is(err, fs.ErrNotExist):
		// Nothing at path yet, so there is no symlink to resolve.
	default:
		// Lstat failed for a reason other than "does not exist" — an
		// unsearchable data directory, a permission or ACL denial, an NFS
		// hiccup. That is an operator fault, not license to assume nothing
		// is there: the symlink check above is the only containment check
		// on this path, so an unverifiable Lstat must refuse rather than
		// silently skip it.
		return "", refusal.RefuseWithCause(
			"repository path unavailable",
			err.Error(),
			"verify the repository path is accessible",
			ErrStoreUnavailable,
		)
	}

	return path, nil
}

// pathWithinRoot reports whether path is root itself or a descendant of it.
// Both arguments must already be absolute and symlink-resolved.
func pathWithinRoot(path, root string) bool {
	prefix := strings.TrimSuffix(root, string(os.PathSeparator)) + string(os.PathSeparator)
	return path == root || strings.HasPrefix(path, prefix)
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

// var _ RepositoryManager = (*Store)(nil) pins Store to the interface at
// compile time, so the two cannot drift apart silently.
var _ RepositoryManager = (*Store)(nil)
