package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/writtendev/walden/internal/refusal"
)

// RepoExists reports whether repo has a bare git repository on disk.
//
// RepoPath resolves the identifier first, so the identifier and containment
// refusals from WALD-37 are returned unchanged and never reach the
// filesystem check below. A directory at the resolved path is true;
// fs.ErrNotExist is false, nil. Any other Stat failure, or a file (not a
// directory) sitting at the path, is an operator-fault refusal wrapping
// ErrStoreUnavailable — never reported as "does not exist", which would send
// a caller into CreateRepo for a second, more confusing failure.
func (s *Store) RepoExists(ctx context.Context, repo string) (bool, error) {
	path, err := s.RepoPath(repo)
	if err != nil {
		return false, err
	}

	info, err := os.Stat(path)
	switch {
	case err == nil:
		if !info.IsDir() {
			return false, refusal.RefuseWithCause(
				"repository storage unavailable",
				fmt.Sprintf("%s exists and is not a directory", path),
				"remove the file occupying the repository path",
				ErrStoreUnavailable,
			)
		}
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		return false, refusal.RefuseWithCause(
			"repository storage unavailable",
			err.Error(),
			"verify the repository path is accessible",
			ErrStoreUnavailable,
		)
	}
}

// CreateRepo initializes a new bare git repository at repo's resolved path.
//
// The repository is built out of line, in a temporary directory that is a
// sibling of the destination so the publishing rename stays on one
// filesystem, and is only made visible under its real name by that rename.
// A half-built repository is therefore never observable at repo's path, and
// every failure path removes the temporary directory.
//
// walden never writes a repository layout itself — the real git binary does,
// via `git init --bare`, per AGENTS.md's "wrap git" rule. GIT_CONFIG_GLOBAL
// and GIT_CONFIG_SYSTEM are pinned to /dev/null for that invocation so the
// personal git configuration of whatever account walden runs under cannot
// change what a walden repository is.
func (s *Store) CreateRepo(ctx context.Context, repo string) error {
	path, err := s.RepoPath(repo)
	if err != nil {
		return err
	}

	switch _, statErr := os.Stat(path); {
	case statErr == nil:
		return repoExistsRefusal(repo)
	case errors.Is(statErr, fs.ErrNotExist):
		// Nothing there yet; proceed.
	default:
		return refusal.RefuseWithCause(
			"repository storage unavailable",
			statErr.Error(),
			"verify the repository path is accessible",
			ErrStoreUnavailable,
		)
	}

	root := filepath.Dir(path)
	tmp, err := os.MkdirTemp(root, ".create-*")
	if err != nil {
		return refusal.RefuseWithCause(
			"repository creation failed",
			err.Error(),
			"verify the data directory is writable",
			ErrStoreUnavailable,
		)
	}
	publish := false
	defer func() {
		if !publish {
			os.RemoveAll(tmp)
		}
	}()

	cmd := exec.CommandContext(ctx, "git", "init", "--bare", "--initial-branch=main", tmp)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return refusal.RefuseWithCause(
			"repository creation failed",
			strings.TrimSpace(stderr.String()),
			"verify git is installed and the data directory is writable",
			ErrStoreUnavailable,
		)
	}

	// The symlink — rather than a shell shim — is the point of the argv[0]
	// dispatch in cmd/walden/main.go (`if prog == "pre-receive"`): it needs
	// no shell on the image, and it always points at whatever binary is
	// actually running.
	exe, err := os.Executable()
	if err != nil {
		return refusal.RefuseWithCause(
			"repository creation failed",
			err.Error(),
			"verify the walden binary path is resolvable",
			ErrStoreUnavailable,
		)
	}
	if err := os.Symlink(exe, filepath.Join(tmp, "hooks", "pre-receive")); err != nil {
		return refusal.RefuseWithCause(
			"repository creation failed",
			err.Error(),
			"verify the hooks directory is writable",
			ErrStoreUnavailable,
		)
	}

	// A concurrent creator that won the race makes this rename fail onto a
	// non-empty directory. That is refused as "already exists" rather than
	// clobbering whatever the winner published.
	if err := os.Rename(tmp, path); err != nil {
		return repoExistsRefusal(repo)
	}
	publish = true

	return nil
}

func repoExistsRefusal(repo string) error {
	return refusal.RefuseWithCause(
		"repository already exists",
		fmt.Sprintf("repository %q already exists", repo),
		"push to the existing repository instead of creating it",
		ErrRepoExists,
	)
}
