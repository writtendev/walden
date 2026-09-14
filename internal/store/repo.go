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
	"syscall"

	"github.com/writtendev/walden/internal/refusal"
)

// RepoExists reports whether repo has a bare git repository on disk.
//
// RepoPath resolves the identifier first, so the identifier and containment
// refusals from WALD-37 are returned unchanged and never reach the
// filesystem check below. The rest of the classification is statRepoPath's:
// see it for what a directory, a missing path, and anything else (including
// a non-directory sitting at the path) each mean.
func (s *Store) RepoExists(ctx context.Context, repo string) (bool, error) {
	path, err := s.RepoPath(repo)
	if err != nil {
		return false, err
	}
	return statRepoPath(path)
}

// statRepoPath classifies what is at path in the one place both RepoExists
// and CreateRepo consult, so the two can never again disagree about what the
// same path means — which is exactly what let a plain file at a repo's path
// wear "already exists" out of CreateRepo while RepoExists correctly refused
// it as storage unavailable (PR #35 round 3).
//
// A directory is (true, nil). fs.ErrNotExist is (false, nil). Any other Stat
// failure, or a file (not a directory) sitting at the path, is an
// operator-fault refusal wrapping ErrStoreUnavailable — never reported as
// "does not exist" (which would send a caller into CreateRepo for a second,
// more confusing failure) and never as ErrRepoExists (which would tell a
// caller to push to a repository that cannot be pushed to).
func statRepoPath(path string) (bool, error) {
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
// via `git init --bare`, per AGENTS.md's "wrap git" rule. That invocation
// gets an explicit allowlist environment — PATH plus GIT_CONFIG_GLOBAL and
// GIT_CONFIG_SYSTEM pinned to /dev/null — rather than the server's own
// environment with a few variables denied. An inherited environment plus
// denials is incomplete: GIT_TEMPLATE_DIR can still smuggle a hooksPath into
// the published repository's config, and GIT_CONFIG_COUNT/KEY_n/VALUE_n
// bypass the config-file neutralisation entirely. An allowlist keeps the
// child's inputs enumerable on one screen and closes both, and anything
// else besides, by construction.
func (s *Store) CreateRepo(ctx context.Context, repo string) error {
	path, err := s.RepoPath(repo)
	if err != nil {
		return err
	}

	switch exists, statErr := statRepoPath(path); {
	case statErr != nil:
		// A non-directory at path, or any other Stat failure, comes back
		// here as ErrStoreUnavailable — the same refusal RepoExists gives
		// for the identical condition, never ErrRepoExists. That agreement
		// is what lets ensureRepoForPush's "lost race is success" swallow
		// (errors.Is(err, store.ErrRepoExists)) treat ErrRepoExists as
		// exactly what it claims to be: a repository directory already
		// published here, not a file an operator or a colliding write left
		// behind.
		return statErr
	case exists:
		return repoExistsRefusal(repo)
	default:
		// Nothing there yet; proceed.
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

	env := []string{"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null"}
	if p := os.Getenv("PATH"); p != "" {
		env = append(env, "PATH="+p)
	}

	cmd := exec.CommandContext(ctx, "git", "init", "--bare", "--initial-branch=main", tmp)
	cmd.Env = env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// git's stderr is the informative cause when it wrote one. When it
		// didn't — git missing from PATH, git not executable, a cancelled
		// context — cmd.Run's own error is the only thing that says why, and
		// falling through to refusal's "unspecified reason" would tell the
		// operator nothing.
		cause := strings.TrimSpace(stderr.String())
		if cause == "" {
			cause = err.Error()
		}
		return refusal.RefuseWithCause(
			"repository creation failed",
			cause,
			"verify git is installed and the data directory is writable",
			ErrStoreUnavailable,
		)
	}

	// git only creates hooks/ because the default template ships one; an
	// absent or stripped template (and now GIT_TEMPLATE_DIR is out of the
	// allowlist above, so an operator-set one no longer reaches this exec
	// either) leaves --bare with no hooks/ at all. walden depends on that
	// directory, so it makes it, rather than depending on git's template.
	hooksDir := filepath.Join(tmp, "hooks")
	if err := os.MkdirAll(hooksDir, 0o700); err != nil {
		return refusal.RefuseWithCause(
			"repository creation failed",
			err.Error(),
			"verify the data directory is writable",
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
	hookPath := filepath.Join(hooksDir, "pre-receive")
	if err := os.Symlink(exe, hookPath); err != nil {
		return refusal.RefuseWithCause(
			"repository creation failed",
			err.Error(),
			"verify the hooks directory is writable",
			ErrStoreUnavailable,
		)
	}

	// git accepts a push whose pre-receive is a dangling symlink silently:
	// no error, no hook run, ref moved. A repository published in that state
	// acknowledges pushes it never journals — PHILOSOPHY's first promise
	// failing with no signal. Stat follows the symlink, so this also catches
	// os.Executable's Linux "/path (deleted)" result after an in-place
	// binary upgrade, with no need to special-case that string.
	if err := hookIsRunnable(hookPath); err != nil {
		return refusal.RefuseWithCause(
			"repository creation failed",
			fmt.Sprintf("hooks/pre-receive does not resolve to a runnable file: %v", err),
			"verify the walden binary path is stable and executable",
			ErrStoreUnavailable,
		)
	}

	if err := os.Rename(tmp, path); err != nil {
		return classifyRenameFailure(err, repo)
	}
	publish = true

	return nil
}

// hookIsRunnable reports whether hookPath resolves — following symlinks —
// to a file that exists and is executable. It is the one check that stands
// between a dangling hooks/pre-receive and a published repository that
// silently never journals a push.
func hookIsRunnable(hookPath string) error {
	info, err := os.Stat(hookPath)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", hookPath)
	}
	if info.Mode()&0o111 == 0 {
		return fmt.Errorf("%s is not executable", hookPath)
	}
	return nil
}

// classifyRenameFailure turns a failed publish rename into a refusal. The
// race this package documents — a concurrent creator already published a
// directory at path — fails with ENOTEMPTY or EEXIST and is reported as
// ErrRepoExists. Anything else (a plain file occupying path, a permissions
// problem) does not describe "already exists" and is reported as
// ErrStoreUnavailable with the rename's own error as the cause instead of
// wearing that story.
func classifyRenameFailure(err error, repo string) error {
	if errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, fs.ErrExist) {
		return repoExistsRefusal(repo)
	}
	return refusal.RefuseWithCause(
		"repository creation failed",
		err.Error(),
		"verify the repository path is accessible",
		ErrStoreUnavailable,
	)
}

func repoExistsRefusal(repo string) error {
	return refusal.RefuseWithCause(
		"repository already exists",
		fmt.Sprintf("repository %q already exists", repo),
		"push to the existing repository instead of creating it",
		ErrRepoExists,
	)
}
