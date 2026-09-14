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

// TestCreateRepoIgnoresGitTemplateDir asserts that the environment CreateRepo builds for
// `git init` is an explicit allowlist, not the server's own environment with a couple of
// GIT_CONFIG_* variables denied. An operator-set GIT_TEMPLATE_DIR pointing at a template
// that ships a `config` file carrying core.hooksPath must not reach the created repository —
// if it did, the published repo's pre-receive would point wherever that hooksPath says, and
// walden's own hook would never run, acknowledging pushes with no journal append.
func TestCreateRepoIgnoresGitTemplateDir(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	s := store.New(dataDir)

	tplDir := t.TempDir()
	const maliciousConfig = "[core]\n\thooksPath = /nonexistent/hooks\n"
	if err := os.WriteFile(filepath.Join(tplDir, "config"), []byte(maliciousConfig), 0o644); err != nil {
		t.Fatalf("WriteFile template config: %v", err)
	}
	t.Setenv("GIT_TEMPLATE_DIR", tplDir)

	if err := s.CreateRepo(ctx, "templated"); err != nil {
		t.Fatalf("CreateRepo: %v", err)
	}

	path, err := s.RepoPath("templated")
	if err != nil {
		t.Fatalf("RepoPath: %v", err)
	}
	config, err := os.ReadFile(filepath.Join(path, "config"))
	if err != nil {
		t.Fatalf("ReadFile(config): %v", err)
	}
	if strings.Contains(string(config), "hooksPath") {
		t.Errorf("published repo's config carries the template's hooksPath, so GIT_TEMPLATE_DIR leaked through:\n%s", config)
	}
}

// TestCreateRepoGitNotFoundIncludesUnderlyingError asserts that when `git init` cannot even
// start — here, no "git" on PATH — and therefore writes nothing to stderr, the refusal still
// names a cause instead of falling back to refusal's "unspecified reason". That fallback is
// indistinguishable from a cancelled context or a non-executable git binary, none of which
// tell an operator anything.
func TestCreateRepoGitNotFoundIncludesUnderlyingError(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	s := store.New(dataDir)

	// A directory with no "git" binary in it: cmd.Run's own Start error, not
	// stderr, is the only source of a cause here.
	t.Setenv("PATH", t.TempDir())

	err := s.CreateRepo(ctx, "nogit")
	if err == nil {
		t.Fatalf("CreateRepo = nil, want error")
	}
	if !errors.Is(err, store.ErrStoreUnavailable) {
		t.Errorf("CreateRepo error = %v, want errors.Is store.ErrStoreUnavailable", err)
	}
	if strings.Contains(err.Error(), "unspecified reason") {
		t.Errorf("CreateRepo error = %q, want the underlying exec error as the cause, not the empty-stderr fallback", err.Error())
	}
	if !strings.Contains(err.Error(), "git") {
		t.Errorf("CreateRepo error = %q, want it to name git as the executable that could not run", err.Error())
	}
	if strings.Contains(err.Error(), "\n") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
}

// TestCreateRepoMakesHooksDirWithoutRelyingOnGit asserts that CreateRepo creates hooks/
// itself rather than depending on `git init --bare` to have supplied it via a template. A
// fake "git" stands in for a real one that mirrors an image whose git template ships no
// hooks/ at all: `git init --bare` on such an image produces no hooks/ directory, and
// without this fix every repository creation would fail there, naming a directory that was
// never created as the thing to check permissions on.
func TestCreateRepoMakesHooksDirWithoutRelyingOnGit(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	s := store.New(dataDir)

	fakeGitDir := t.TempDir()
	// Mimics `git init --bare --initial-branch=main <dir>` on an image whose
	// template ships no hooks/: a minimal bare layout, deliberately missing
	// hooks/, exactly what git init itself would leave with an empty or
	// absent template directory.
	script := `#!/bin/sh
set -e
dir="$4"
mkdir -p "$dir/objects" "$dir/refs/heads" "$dir/refs/tags"
echo "ref: refs/heads/main" > "$dir/HEAD"
cat > "$dir/config" <<'EOF'
[core]
	repositoryformatversion = 0
	filemode = true
	bare = true
EOF
exit 0
`
	if err := os.WriteFile(filepath.Join(fakeGitDir, "git"), []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile fake git: %v", err)
	}
	// The fake "git" is a shell script that calls mkdir/cat/echo itself, so
	// PATH needs real directories behind it for those to resolve — fakeGitDir
	// leads so it is what "git" itself resolves to.
	t.Setenv("PATH", fakeGitDir+":/usr/bin:/bin")

	if err := s.CreateRepo(ctx, "notemplate"); err != nil {
		t.Fatalf("CreateRepo: %v", err)
	}

	path, err := s.RepoPath("notemplate")
	if err != nil {
		t.Fatalf("RepoPath: %v", err)
	}
	hook := filepath.Join(path, "hooks", "pre-receive")
	info, err := os.Stat(hook)
	if err != nil {
		t.Fatalf("Stat(%q): %v, want CreateRepo to have made hooks/ itself", hook, err)
	}
	if info.Mode()&0o111 == 0 {
		t.Errorf("hooks/pre-receive is not executable: mode %v", info.Mode())
	}
}

// TestHookIsRunnable exercises the check that stands between a dangling hooks/pre-receive
// and a published repository whose pre-receive git silently never runs: a bare repo created
// by a process whose own binary has been unlinked out from under it (os.Executable returns
// "/path (deleted)" on Linux after an in-place upgrade) would otherwise publish a hook
// symlink that resolves to nothing, and git accepts a push through it without complaint —
// acknowledging it with no journal append.
func TestHookIsRunnable(t *testing.T) {
	dir := t.TempDir()

	t.Run("dangling-symlink-refused", func(t *testing.T) {
		link := filepath.Join(dir, "dangling")
		if err := os.Symlink(filepath.Join(dir, "does-not-exist"), link); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		if err := store.HookIsRunnableForTest(link); err == nil {
			t.Fatalf("HookIsRunnableForTest(%q) = nil, want error for a dangling symlink", link)
		}
	})

	t.Run("non-executable-target-refused", func(t *testing.T) {
		target := filepath.Join(dir, "not-executable")
		if err := os.WriteFile(target, []byte("not a binary"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		link := filepath.Join(dir, "to-non-executable")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		if err := store.HookIsRunnableForTest(link); err == nil {
			t.Fatalf("HookIsRunnableForTest(%q) = nil, want error for a non-executable target", link)
		}
	})

	t.Run("runnable-target-accepted", func(t *testing.T) {
		target := filepath.Join(dir, "runnable")
		if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		link := filepath.Join(dir, "to-runnable")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		if err := store.HookIsRunnableForTest(link); err != nil {
			t.Errorf("HookIsRunnableForTest(%q) = %v, want nil for an executable target", link, err)
		}
	})
}

// TestClassifyRenameFailure asserts that only the genuine "a concurrent creator already
// published a directory here" race is reported as store.ErrRepoExists; any other rename
// failure — a plain file occupying the destination, which fails with ENOTDIR rather than
// ENOTEMPTY — is reported as store.ErrStoreUnavailable instead of the contradictory
// "already exists" story that TestCreateRepoTwiceRefusesSecond and RepoExists would then
// disagree about.
func TestClassifyRenameFailure(t *testing.T) {
	t.Run("non-empty-directory-is-already-exists", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "src")
		if err := os.Mkdir(src, 0o755); err != nil {
			t.Fatalf("Mkdir(src): %v", err)
		}
		dst := filepath.Join(dir, "dst")
		if err := os.Mkdir(dst, 0o755); err != nil {
			t.Fatalf("Mkdir(dst): %v", err)
		}
		if err := os.WriteFile(filepath.Join(dst, "occupied"), []byte("x"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		renameErr := os.Rename(src, dst)
		if renameErr == nil {
			t.Fatalf("os.Rename(src, dst) = nil, want ENOTEMPTY (test setup did not reproduce the race)")
		}

		err := store.ClassifyRenameFailureForTest(renameErr, "racer")
		if !errors.Is(err, store.ErrRepoExists) {
			t.Errorf("ClassifyRenameFailureForTest = %v, want errors.Is store.ErrRepoExists", err)
		}
	})

	t.Run("file-at-destination-is-store-unavailable-not-already-exists", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "src")
		if err := os.Mkdir(src, 0o755); err != nil {
			t.Fatalf("Mkdir(src): %v", err)
		}
		blocked := filepath.Join(dir, "blocked")
		if err := os.WriteFile(blocked, []byte("not a directory"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		renameErr := os.Rename(src, blocked)
		if renameErr == nil {
			t.Fatalf("os.Rename(src, blocked) = nil, want ENOTDIR (test setup did not reproduce the condition)")
		}

		err := store.ClassifyRenameFailureForTest(renameErr, "blocked")
		if errors.Is(err, store.ErrRepoExists) {
			t.Errorf("ClassifyRenameFailureForTest(%v) = %v, want it NOT to claim ErrRepoExists for a non-directory at the destination", renameErr, err)
		}
		if !errors.Is(err, store.ErrStoreUnavailable) {
			t.Errorf("ClassifyRenameFailureForTest(%v) = %v, want errors.Is store.ErrStoreUnavailable", renameErr, err)
		}
	})
}
