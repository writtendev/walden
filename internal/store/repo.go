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

// ResolveRepo resolves repo to its on-disk path and reports whether a bare
// git repository already exists there, in one call. Callers that need both
// — githttp's handlers, chief among them — used to call RepoPath and
// RepoExists separately and re-derive the classification between them; this
// is the one place that does it, so a fourth site cannot drift from the
// other two.
//
// RepoPath resolves the identifier first, so the identifier and containment
// refusals from WALD-37 are returned unchanged and never reach the
// filesystem check below. The rest of the classification is statRepoPath's:
// see it for what a directory, a missing path, and anything else (including
// a non-directory sitting at the path) each mean.
func (s *Store) ResolveRepo(ctx context.Context, repo string) (path string, exists bool, err error) {
	path, err = s.RepoPath(repo)
	if err != nil {
		return "", false, err
	}
	exists, err = statRepoPath(path)
	if err != nil {
		return "", false, err
	}
	return path, exists, nil
}

// RepoExists reports whether repo has a bare git repository on disk. It is
// a one-line delegation to ResolveRepo, kept for callers that only need the
// answer, so there remains a single classifier of what a resolved path
// means.
func (s *Store) RepoExists(ctx context.Context, repo string) (bool, error) {
	_, exists, err := s.ResolveRepo(ctx, repo)
	return exists, err
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

	// The same installer EnsureHook repairs an already-published
	// repository with, so the two cannot disagree about what a correct
	// hook is. It runs against the staging directory, before the
	// publishing rename, so a repository is never observable without one.
	if err := installPreReceiveHook(filepath.Join(tmp, "hooks")); err != nil {
		return refusal.RefuseWithCause(
			"repository creation failed",
			err.Error(),
			"verify the data directory is writable and the walden binary path is stable",
			ErrStoreUnavailable,
		)
	}

	if err := os.Rename(tmp, path); err != nil {
		return classifyRenameFailure(err, repo)
	}
	publish = true

	return nil
}

// preReceiveHookName is the one hook walden owns. git looks for it under
// a repository's hooks/ directory by exactly this name.
const preReceiveHookName = "pre-receive"

// EnsureHook verifies, and repairs where it safely can, the pre-receive
// hook of the repository already resolved to repoPath.
//
// It takes a path rather than a repository identifier so nothing is
// resolved a second time: its caller — githttp's ensureRepoForPush — has
// just re-resolved the path it is about to hand to `git receive-pack`, and
// this has to check that exact directory, not one resolved again after it.
//
// A repository whose pre-receive hook is not walden's is a repository
// whose pushes are silently undurable: git takes the pack, moves the ref,
// reports success, and nothing is ever journaled. So a push through one is
// refused. A read through one is not — a clone off a hook-less repository
// is harmless, and refusing it would turn a durability defect into an
// availability outage — which is why this lives on the push path rather
// than inside ResolveRepo, where all three routes would inherit it.
//
// Three outcomes and no fourth:
//
//   - hooks/pre-receive is a symlink to the running binary and resolves to
//     a runnable file: nothing is written, three Stat-class syscalls.
//   - it is absent, a dangling symlink, or a symlink pointing anywhere
//     other than the running binary: walden replaces the symlink it owns.
//     A symlink left over from a previous install still resolving to some
//     executable is repaired too — it runs a different walden, which is
//     not the same thing as running this one.
//   - it is anything else — a regular file, a directory: one-line refusal
//     wrapping ErrHookUnavailable. An operator's own pre-receive script at
//     that path means walden's hook never runs, so the push cannot be
//     accepted; and walden will not delete a file an operator deliberately
//     placed, because it cannot know what it was for. It says which file
//     is in the way and stops.
func (s *Store) EnsureHook(repoPath string) error {
	hooksDir := filepath.Join(repoPath, "hooks")
	hookPath := filepath.Join(hooksDir, preReceiveHookName)

	switch info, err := os.Lstat(hookPath); {
	case err == nil && info.Mode()&fs.ModeSymlink != 0:
		if hookPointsAtRunningBinary(hookPath) {
			return nil
		}
		// walden's own symlink, pointing at a previous install or at
		// nothing at all. Replacing it is replacing what walden wrote.
	case err == nil:
		return refusal.RefuseWithCause(
			"repository hook unavailable",
			fmt.Sprintf("%s exists and is not walden's pre-receive hook", hookPath),
			"move it aside so walden can install its own pre-receive hook",
			ErrHookUnavailable,
		)
	case errors.Is(err, fs.ErrNotExist):
		// Nothing there — an operator-placed repository, or one whose hook
		// was removed. Install below.
	default:
		return refusal.RefuseWithCause(
			"repository hook unavailable",
			err.Error(),
			"verify the repository's hooks directory is accessible",
			ErrHookUnavailable,
		)
	}

	if err := installPreReceiveHook(hooksDir); err != nil {
		// The staged link is verified before it replaces anything, so a
		// hook that runs is never replaced by one that does not. When the
		// repair could not be made but what is already there still runs
		// this walden's own binary — os.Executable returning "/path
		// (deleted)" on Linux after an in-place upgrade is that case, and
		// the hook symlink still points at the new binary at the same
		// path — the push proceeds rather than the server refusing over a
		// hook that works.
		if hookIsRunnable(hookPath) == nil {
			return nil
		}
		return refusal.RefuseWithCause(
			"repository hook unavailable",
			err.Error(),
			"verify the repository's hooks directory is writable and the walden binary path is stable",
			ErrHookUnavailable,
		)
	}
	return nil
}

// hookPointsAtRunningBinary reports whether hookPath is a symlink to the
// binary this process is running, resolving to a runnable file. It is
// EnsureHook's fast path, and answers a question hookIsRunnable
// deliberately does not: hookIsRunnable follows the symlink, so a link left
// pointing at a previous install that still holds an executable passes it.
// That hook runs, but it runs a different walden.
func hookPointsAtRunningBinary(hookPath string) bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	target, err := os.Readlink(hookPath)
	if err != nil || target != exe {
		return false
	}
	return hookIsRunnable(hookPath) == nil
}

// installPreReceiveHook installs hooksDir/pre-receive as a symlink to the
// running binary, creating hooksDir if it is not already there. It is the
// one place walden writes that hook: CreateRepo calls it against a staging
// directory, EnsureHook against a published repository.
//
// The symlink — rather than a shell shim — is the point of the argv[0]
// dispatch in cmd/walden/main.go (`if prog == "pre-receive"`): it needs
// no shell on the image, and it always points at whatever binary is
// actually running.
//
// The link is staged under a temporary name, checked runnable there, and
// only then renamed into place, so a hook that runs is never replaced by
// one that does not.
//
// It returns plain errors rather than refusals: creating a repository and
// repairing a published one are different refusals for the same failure,
// and each caller says which one happened.
func installPreReceiveHook(hooksDir string) error {
	// git only creates hooks/ because the default template ships one; an
	// absent or stripped template (and GIT_TEMPLATE_DIR is out of
	// CreateRepo's environment allowlist, so an operator-set one does not
	// reach that exec either) leaves --bare with no hooks/ at all. walden
	// depends on that directory, so it makes it, rather than depending on
	// git's template.
	if err := os.MkdirAll(hooksDir, 0o700); err != nil {
		return err
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}

	// os.Symlink refuses to overwrite, so the staged link needs a name
	// nothing holds: CreateTemp reserves one, and the empty file it made
	// is removed to make room for the link itself.
	staged, err := os.CreateTemp(hooksDir, ".pre-receive-*")
	if err != nil {
		return err
	}
	stagedPath := staged.Name()
	staged.Close()
	published := false
	defer func() {
		if !published {
			os.Remove(stagedPath)
		}
	}()
	if err := os.Remove(stagedPath); err != nil {
		return err
	}
	if err := os.Symlink(exe, stagedPath); err != nil {
		return err
	}

	// git accepts a push whose pre-receive is a dangling symlink silently:
	// no error, no hook run, ref moved. A repository left in that state
	// acknowledges pushes it never journals — PHILOSOPHY's first promise
	// failing with no signal. Stat follows the symlink, so this also
	// catches os.Executable's Linux "/path (deleted)" result after an
	// in-place binary upgrade, with no need to special-case that string.
	if err := hookIsRunnable(stagedPath); err != nil {
		return fmt.Errorf("hooks/pre-receive would not resolve to a runnable file: %w", err)
	}

	if err := os.Rename(stagedPath, filepath.Join(hooksDir, preReceiveHookName)); err != nil {
		return err
	}
	published = true
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
