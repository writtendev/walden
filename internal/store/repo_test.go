package store_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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

// TestCreateRepoNonDirectoryAgreesWithRepoExists is PR #35 round 3's finding: CreateRepo's
// top-of-function Stat had no IsDir check, unlike RepoExists twenty lines above, so a plain
// file at a repository's resolved path made CreateRepo report ErrRepoExists — telling a
// caller to "push to the existing repository instead of creating it" — while RepoExists on
// the identical path correctly refused as ErrStoreUnavailable. That contradiction is what let
// ensureRepoForPush's round-2 "lost race is success" swallow (errors.Is(err,
// store.ErrRepoExists)) turn a wrong refusal into a silent success: see
// TestEnsureRepoForPushRefusesLostRaceToNonDirectory in internal/githttp. CreateRepo and
// RepoExists must agree on both the sentinel and the rendered message for the same path.
func TestCreateRepoNonDirectoryAgreesWithRepoExists(t *testing.T) {
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

	createErr := s.CreateRepo(ctx, "blocked")
	if createErr == nil {
		t.Fatalf("CreateRepo(%q) = nil, want error", "blocked")
	}
	if errors.Is(createErr, store.ErrRepoExists) {
		t.Errorf("CreateRepo(%q) = %v, want it NOT to claim ErrRepoExists for a non-directory at the path", "blocked", createErr)
	}
	if !errors.Is(createErr, store.ErrStoreUnavailable) {
		t.Errorf("CreateRepo(%q) = %v, want errors.Is store.ErrStoreUnavailable", "blocked", createErr)
	}
	if strings.Contains(createErr.Error(), "\n") {
		t.Errorf("refusal is not a single line: %q", createErr.Error())
	}

	_, existsErr := s.RepoExists(ctx, "blocked")
	if existsErr == nil {
		t.Fatalf("RepoExists(%q) = nil, want error", "blocked")
	}
	if !errors.Is(existsErr, store.ErrStoreUnavailable) {
		t.Errorf("RepoExists(%q) = %v, want errors.Is store.ErrStoreUnavailable", "blocked", existsErr)
	}

	// The whole point: the two call sites must tell the same story about the same file at
	// the same path, not merely the same sentinel.
	if createErr.Error() != existsErr.Error() {
		t.Errorf("CreateRepo and RepoExists disagree about the same non-directory path:\nCreateRepo:  %v\nRepoExists:  %v", createErr, existsErr)
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

// TestCreateRepoConcurrentCreatorsExactlyOneWins pins CreateRepo's own doc comment claim — "a
// concurrent creator that won the race makes the rename fail onto a non-empty directory" —
// against a real race instead of a synthesized rename error. TestClassifyRenameFailure above
// confirms the classification once ENOTEMPTY happens; this drives N goroutines at the same
// missing repository so ENOTEMPTY (or EEXIST) actually happens, the way PR #35's round-2
// review ran it by hand.
func TestCreateRepoConcurrentCreatorsExactlyOneWins(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	s := store.New(dataDir)

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = s.CreateRepo(ctx, "racer")
		}(i)
	}
	wg.Wait()

	wins, losses := 0, 0
	for i, err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, store.ErrRepoExists):
			losses++
		default:
			t.Errorf("CreateRepo[%d] = %v, want nil or errors.Is store.ErrRepoExists", i, err)
		}
	}
	if wins != 1 {
		t.Errorf("concurrent CreateRepo winners = %d, want exactly 1", wins)
	}
	if losses != n-1 {
		t.Errorf("concurrent CreateRepo losses = %d, want %d", losses, n-1)
	}

	// No loser's .create-* temporary directory survives: the data directory holds only the
	// winner's published repository.
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dataDir, err)
	}
	if len(entries) != 1 || entries[0].Name() != "racer.git" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("data directory entries = %v, want exactly [%q] (no .create-* residue)", names, "racer.git")
	}

	exists, err := s.RepoExists(ctx, "racer")
	if err != nil {
		t.Fatalf("RepoExists: %v", err)
	}
	if !exists {
		t.Errorf("RepoExists after concurrent creators = false, want true")
	}
}

// TestEnsureHook is the repair-then-verify table for the hook of a repository that reached
// disk some way other than CreateRepo — placed there by an operator, restored from a backup,
// or created by a walden that has since been replaced. walden owns hooks/pre-receive, so it
// repairs the symlink it writes; it does not own whatever else may be sitting there, so it
// refuses the push rather than deleting it.
//
// Every fixture is a real bare repository rather than a directory shaped like one, because
// EnsureHook's first act is to ask git which pre-receive hook this repository will run, and
// git only answers that inside a repository it can open. A bare directory is not the state
// this table is about — it is a repository `git receive-pack` would refuse a moment later —
// and EnsureHook now refuses it too, which
// TestEnsureHookRefusesAVanishedRepositoryInsteadOfCreatingOne pins.
func TestEnsureHook(t *testing.T) {
	ctx := context.Background()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	// runnableFile writes an executable file a hook symlink can point at, standing in for a
	// walden binary at some other path.
	runnableFile := func(t *testing.T, path string) string {
		t.Helper()
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("WriteFile(%q): %v", path, err)
		}
		return path
	}

	tests := []struct {
		name  string
		setup func(t *testing.T, repoPath string)
		// refuse is true when EnsureHook must refuse rather than repair: what is at the
		// path is not walden's to replace.
		refuse bool
	}{
		{
			name: "walden-symlink-left-alone",
			setup: func(t *testing.T, repoPath string) {
				t.Helper()
				mustBareRepo(t, repoPath)
				mustSymlink(t, exe, filepath.Join(repoPath, "hooks", "pre-receive"))
			},
		},
		{
			name: "missing-hook-installed",
			setup: func(t *testing.T, repoPath string) {
				t.Helper()
				mustBareRepo(t, repoPath)
			},
		},
		{
			name: "missing-hooks-directory-created",
			setup: func(t *testing.T, repoPath string) {
				t.Helper()
				mustBareRepo(t, repoPath)
				if err := os.RemoveAll(filepath.Join(repoPath, "hooks")); err != nil {
					t.Fatalf("RemoveAll(hooks): %v", err)
				}
			},
		},
		{
			name: "dangling-symlink-repaired",
			setup: func(t *testing.T, repoPath string) {
				t.Helper()
				mustBareRepo(t, repoPath)
				mustSymlink(t, filepath.Join(repoPath, "gone"), filepath.Join(repoPath, "hooks", "pre-receive"))
			},
		},
		{
			name: "non-executable-target-repaired",
			setup: func(t *testing.T, repoPath string) {
				t.Helper()
				mustBareRepo(t, repoPath)
				target := filepath.Join(repoPath, "not-executable")
				if err := os.WriteFile(target, []byte("not a binary"), 0o644); err != nil {
					t.Fatalf("WriteFile(%q): %v", target, err)
				}
				mustSymlink(t, target, filepath.Join(repoPath, "hooks", "pre-receive"))
			},
		},
		{
			// The case hookIsRunnable cannot see, because it follows the symlink: a link
			// left by a previous install that still resolves to an executable. That hook
			// runs, but it runs a different walden.
			name: "symlink-to-another-binary-repointed",
			setup: func(t *testing.T, repoPath string) {
				t.Helper()
				mustBareRepo(t, repoPath)
				other := runnableFile(t, filepath.Join(repoPath, "previous-walden"))
				mustSymlink(t, other, filepath.Join(repoPath, "hooks", "pre-receive"))
			},
		},
		{
			// An operator's own pre-receive script. It is runnable, so git would run it
			// happily — and walden's hook would never run, making every push to this
			// repository silently undurable. walden refuses that push, and does not delete
			// a file an operator deliberately placed: it says what is in the way and stops.
			name:   "operator-placed-regular-file-refused",
			refuse: true,
			setup: func(t *testing.T, repoPath string) {
				t.Helper()
				mustBareRepo(t, repoPath)
				runnableFile(t, filepath.Join(repoPath, "hooks", "pre-receive"))
			},
		},
		{
			name:   "directory-refused",
			refuse: true,
			setup: func(t *testing.T, repoPath string) {
				t.Helper()
				mustBareRepo(t, repoPath)
				mustMkdirAll(t, filepath.Join(repoPath, "hooks", "pre-receive"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataDir := t.TempDir()
			s := store.New(dataDir)
			repoPath := filepath.Join(dataDir, "repo.git")
			tt.setup(t, repoPath)
			hook := filepath.Join(repoPath, "hooks", "pre-receive")

			err := s.EnsureHook(ctx, repoPath)
			if tt.refuse {
				if err == nil {
					t.Fatalf("EnsureHook = nil, want a refusal")
				}
				if !errors.Is(err, store.ErrHookUnavailable) {
					t.Errorf("EnsureHook error = %v, want it to wrap store.ErrHookUnavailable", err)
				}
				if errors.Is(err, store.ErrStoreUnavailable) {
					t.Errorf("EnsureHook error = %v, want it not to wear ErrStoreUnavailable: the path resolved, the hook is what failed", err)
				}
				if strings.Contains(err.Error(), "\n") {
					t.Errorf("refusal is not one line: %q", err)
				}
				if _, statErr := os.Lstat(hook); statErr != nil {
					t.Errorf("Lstat(%q) after a refusal: %v, want what was there left untouched", hook, statErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("EnsureHook: %v", err)
			}
			assertWaldenHook(t, hook, exe)

			// Idempotent: a second call agrees with the first.
			if err := s.EnsureHook(ctx, repoPath); err != nil {
				t.Fatalf("EnsureHook (second call): %v", err)
			}
			assertWaldenHook(t, hook, exe)

			// No staged .pre-receive-* link survives either call.
			entries, err := os.ReadDir(filepath.Join(repoPath, "hooks"))
			if err != nil {
				t.Fatalf("ReadDir: %v", err)
			}
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), ".pre-receive-") {
					t.Errorf("hooks/ holds staging residue %q", e.Name())
				}
			}
		})
	}
}

// TestEnsureHookLeavesAWaldenSymlinkUntouched pins the fast path: a hook that is already
// walden's is not rewritten, so an ordinary push does no filesystem write at all.
func TestEnsureHookLeavesAWaldenSymlinkUntouched(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	ctx := context.Background()
	dataDir := t.TempDir()
	s := store.New(dataDir)
	repoPath := filepath.Join(dataDir, "repo.git")
	hook := filepath.Join(repoPath, "hooks", "pre-receive")
	mustBareRepo(t, repoPath)
	mustSymlink(t, exe, hook)

	before, err := os.Lstat(hook)
	if err != nil {
		t.Fatalf("Lstat(%q): %v", hook, err)
	}
	if err := s.EnsureHook(ctx, repoPath); err != nil {
		t.Fatalf("EnsureHook: %v", err)
	}
	after, err := os.Lstat(hook)
	if err != nil {
		t.Fatalf("Lstat(%q) after EnsureHook: %v", hook, err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Errorf("EnsureHook replaced a hook that was already correct (mtime %v -> %v)", before.ModTime(), after.ModTime())
	}
}

// TestEnsureHookRefusesUnwritableHooksDirectory covers the one repair that cannot be made
// and has no runnable hook to fall back on: the hook is missing and hooks/ cannot be written.
// The push is refused in one line naming ErrHookUnavailable rather than proceeding into a
// repository whose pushes would never be journaled.
func TestEnsureHookRefusesUnwritableHooksDirectory(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	s := store.New(dataDir)
	repoPath := filepath.Join(dataDir, "repo.git")
	hooksDir := filepath.Join(repoPath, "hooks")
	mustBareRepo(t, repoPath)

	mustBeUnwritable(t, hooksDir)

	err := s.EnsureHook(ctx, repoPath)
	if err == nil {
		t.Fatalf("EnsureHook = nil, want a refusal: the hook is missing and cannot be installed")
	}
	if !errors.Is(err, store.ErrHookUnavailable) {
		t.Errorf("EnsureHook error = %v, want it to wrap store.ErrHookUnavailable", err)
	}
	if strings.Contains(err.Error(), "\n") {
		t.Errorf("refusal is not one line: %q", err)
	}
}

// TestEnsureHookRefusesAForeignRunnableHookItCannotReplace is the case a fallback on "does
// hooks/pre-receive resolve to some executable" silently re-admitted: a symlink to a runnable
// binary that is not walden's, in a hooks/ directory the repair cannot be written to. git would
// run that hook happily, journal nothing, move the ref, and acknowledge the push — the one
// failure this ticket exists to stop. Runnable is not the question; walden's own is.
func TestEnsureHookRefusesAForeignRunnableHookItCannotReplace(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	s := store.New(dataDir)
	repoPath := filepath.Join(dataDir, "repo.git")
	hooksDir := filepath.Join(repoPath, "hooks")
	mustBareRepo(t, repoPath)

	// A previous install, /bin/true, an operator's compiled hook: anything runnable that is
	// not this binary. It lives outside hooks/ so locking that directory down does not also
	// make the target unreadable.
	foreign := filepath.Join(dataDir, "not-walden")
	if err := os.WriteFile(foreign, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(%q): %v", foreign, err)
	}
	hook := filepath.Join(hooksDir, "pre-receive")
	mustSymlink(t, foreign, hook)

	mustBeUnwritable(t, hooksDir)

	err := s.EnsureHook(ctx, repoPath)
	if err == nil {
		t.Fatalf("EnsureHook = nil, want a refusal: hooks/pre-receive runs %q, which is not walden", foreign)
	}
	if !errors.Is(err, store.ErrHookUnavailable) {
		t.Errorf("EnsureHook error = %v, want it to wrap store.ErrHookUnavailable", err)
	}
	if errors.Is(err, store.ErrStoreUnavailable) {
		t.Errorf("EnsureHook error = %v, want it not to wear ErrStoreUnavailable: the path resolved, the hook is what failed", err)
	}
	if strings.Contains(err.Error(), "\n") {
		t.Errorf("refusal is not one line: %q", err)
	}

	// Nothing is deleted on the way out: the refusal leaves the foreign link where it was.
	target, readErr := os.Readlink(hook)
	if readErr != nil {
		t.Fatalf("Readlink(%q) after a refusal: %v", hook, readErr)
	}
	if target != foreign {
		t.Errorf("hooks/pre-receive -> %q after a refusal, want %q left untouched", target, foreign)
	}
}

// TestEnsureHookAcceptsItsOwnHookWhenRepairIsImpossible is the other half of the case above,
// and the reason refusing a failed repair costs nothing: an in-place binary upgrade — the new
// walden back at the path the existing link already names — never reaches the repair at all.
// It matches on the fast path and returns before a single byte is written, so an unwritable
// hooks/ directory is irrelevant to it.
func TestEnsureHookAcceptsItsOwnHookWhenRepairIsImpossible(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	ctx := context.Background()
	dataDir := t.TempDir()
	s := store.New(dataDir)
	repoPath := filepath.Join(dataDir, "repo.git")
	hooksDir := filepath.Join(repoPath, "hooks")
	mustBareRepo(t, repoPath)
	mustSymlink(t, exe, filepath.Join(hooksDir, "pre-receive"))

	mustBeUnwritable(t, hooksDir)

	if err := s.EnsureHook(ctx, repoPath); err != nil {
		t.Fatalf("EnsureHook = %v, want nil: the hook already points at the running binary, so no repair is needed", err)
	}
}

// TestEnsureHookRefusesARepositoryThatRedirectsItsHooks covers the bypass that made every
// other check in EnsureHook beside the point: git runs <repo>/hooks/pre-receive only while
// core.hooksPath is unset. Set, it runs <core.hooksPath>/pre-receive and never looks at
// hooks/ at all — so a repository copied off another server or restored from a backup taken
// on a host with a hook manager could carry a perfect walden symlink at hooks/pre-receive,
// pass EnsureHook, take the push, move the ref, and journal nothing.
//
// Every case installs walden's own correct hook first, so the refusal can only be about the
// redirect. The four of them are four ways the same redirect arrives, and each one defeated
// a narrower probe than the one this now uses:
//
//   - set-directly is the plain case.
//   - arriving-through-an-include needed git's include resolution, which git turns off once
//     a config scope is named.
//   - set-to-the-empty-string reads back from `git config --get` byte-for-byte like a key
//     that was never set, while git treats it as a redirect to /pre-receive.
//   - set-in-the-worktree-config lives in $GIT_DIR/config.worktree, which --local never
//     consults at all.
//
// The lesson of the list is that there is always one more scope and one more spelling, so
// EnsureHook stopped asking about config and started asking `git rev-parse --git-path
// hooks/pre-receive` — which git answers by resolving the hook path itself, and which
// therefore covers all four without knowing any of them.
func TestEnsureHookRefusesARepositoryThatRedirectsItsHooks(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	tests := []struct {
		name     string
		redirect func(t *testing.T, repoPath string)
	}{
		{
			name: "set-directly",
			redirect: func(t *testing.T, repoPath string) {
				t.Helper()
				mustGitConfig(t, repoPath, "core.hooksPath", "/etc/walden/elsewhere")
			},
		},
		{
			name: "arriving-through-an-include",
			redirect: func(t *testing.T, repoPath string) {
				t.Helper()
				included := filepath.Join(repoPath, "hooks-config")
				if err := os.WriteFile(included, []byte("[core]\n\thooksPath = /etc/walden/elsewhere\n"), 0o644); err != nil {
					t.Fatalf("WriteFile(%q): %v", included, err)
				}
				mustGitConfig(t, repoPath, "include.path", included)
			},
		},
		{
			// core.hooksPath = "" is a redirect that reads as an absence. `git config --get`
			// prints an empty line and exits 0, which is indistinguishable after TrimSpace
			// from the exit-1 "not set" answer — while git itself joins the empty directory
			// with the hook name and looks for /pre-receive, at the filesystem root. A
			// repository in this state has no hook of walden's on any path git will consult.
			name: "set-to-the-empty-string",
			redirect: func(t *testing.T, repoPath string) {
				t.Helper()
				mustGitConfig(t, repoPath, "core.hooksPath", "")
			},
		},
		{
			// $GIT_DIR/config.worktree, which git reads whenever extensions.worktreeConfig is
			// on and which --local does not consult at any setting. Both halves are set through
			// the real git binary, so this is a repository state git produced rather than one
			// the test guessed at the file format for.
			name: "set-in-the-worktree-config",
			redirect: func(t *testing.T, repoPath string) {
				t.Helper()
				mustGitConfig(t, repoPath, "extensions.worktreeConfig", "true")
				mustGitConfigWorktree(t, repoPath, "core.hooksPath", "/etc/walden/elsewhere")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			dataDir := t.TempDir()
			s := store.New(dataDir)

			// A real repository, because this asks git what its config says and git will
			// only answer --local inside one.
			if err := s.CreateRepo(ctx, "redirected"); err != nil {
				t.Fatalf("CreateRepo: %v", err)
			}
			repoPath, err := s.RepoPath("redirected")
			if err != nil {
				t.Fatalf("RepoPath: %v", err)
			}
			hook := filepath.Join(repoPath, "hooks", "pre-receive")
			assertWaldenHook(t, hook, exe)

			tt.redirect(t, repoPath)

			err = s.EnsureHook(ctx, repoPath)
			if err == nil {
				t.Fatalf("EnsureHook = nil, want a refusal: core.hooksPath sends git somewhere walden's hook is not")
			}
			if !errors.Is(err, store.ErrHookUnavailable) {
				t.Errorf("EnsureHook error = %v, want it to wrap store.ErrHookUnavailable", err)
			}
			if errors.Is(err, store.ErrStoreUnavailable) {
				t.Errorf("EnsureHook error = %v, want it not to wear ErrStoreUnavailable: the path resolved, the hook is what failed", err)
			}
			if strings.Contains(err.Error(), "\n") {
				t.Errorf("refusal is not one line: %q", err)
			}
			if !strings.Contains(err.Error(), "core.hooksPath") {
				t.Errorf("refusal %q does not name core.hooksPath, so an operator cannot act on it", err)
			}

			// walden does not install into the directory core.hooksPath names, and does not
			// edit the repository's config to get its own way: it says what is wrong and stops.
			assertWaldenHook(t, hook, exe)
			if _, statErr := os.Stat("/etc/walden/elsewhere"); statErr == nil {
				t.Errorf("walden created the directory core.hooksPath named; it must not guess at an operator's intent")
			}
		})
	}
}

// TestEnsureHookRefusesWhenGitCannotReportTheHookPath is the fail-closed half of the same
// question. The probe used to treat every exit it did not recognise as "no redirect here",
// on the reasoning that anything git refuses to open, `git receive-pack` refuses a moment
// later too. That reasoning does not hold: the probe pins GIT_CONFIG_SYSTEM=/dev/null and
// githttp's gitEnv does not, so a safe.directory in /etc/gitconfig opens a repository for
// receive-pack and not for this — and a fork that failed with EAGAIN or EMFILE says nothing
// about the repository at all. A probe that could not answer must refuse.
//
// The directory here holds walden's own correct hook, so nothing but the unanswered probe
// can be the reason for the refusal: under the old branch this returned nil.
func TestEnsureHookRefusesWhenGitCannotReportTheHookPath(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	newRepoShapedDirectory := func(t *testing.T) string {
		t.Helper()
		dataDir := t.TempDir()
		repoPath := filepath.Join(dataDir, "repo.git")
		mustMkdirAll(t, filepath.Join(repoPath, "hooks"))
		mustSymlink(t, exe, filepath.Join(repoPath, "hooks", "pre-receive"))
		return repoPath
	}

	tests := []struct {
		name string
		// ctx is the context EnsureHook is called with, and setup returns the path.
		run func(t *testing.T) (context.Context, *store.Store, string)
	}{
		{
			// git exits 128: this is a directory shaped like a repository, not one git will
			// open. Nothing about the hook that is sitting there has been established.
			name: "not-a-repository-git-will-open",
			run: func(t *testing.T) (context.Context, *store.Store, string) {
				t.Helper()
				repoPath := newRepoShapedDirectory(t)
				return context.Background(), store.New(filepath.Dir(repoPath)), repoPath
			},
		},
		{
			// A real repository with walden's own hook already correctly installed, so the
			// cancelled context is the only thing that can refuse it — which is what pins
			// that EnsureHook takes a context at all, and that the probe honours it rather
			// than parking the handler goroutine past the client's disconnect.
			name: "cancelled-context",
			run: func(t *testing.T) (context.Context, *store.Store, string) {
				t.Helper()
				dataDir := t.TempDir()
				repoPath := filepath.Join(dataDir, "repo.git")
				mustBareRepo(t, repoPath)
				mustSymlink(t, exe, filepath.Join(repoPath, "hooks", "pre-receive"))
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, store.New(dataDir), repoPath
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, s, repoPath := tt.run(t)

			err := s.EnsureHook(ctx, repoPath)
			if err == nil {
				t.Fatalf("EnsureHook = nil, want a refusal: git never reported which hook %q runs", repoPath)
			}
			if !errors.Is(err, store.ErrHookUnavailable) {
				t.Errorf("EnsureHook error = %v, want it to wrap store.ErrHookUnavailable", err)
			}
			if strings.Contains(err.Error(), "\n") {
				t.Errorf("refusal is not one line: %q", err)
			}
		})
	}
}

// TestEnsureHookRefusesAVanishedRepositoryInsteadOfCreatingOne pins that the repair path does
// not create storage. EnsureHook is handed a path, not an identifier, and an installer built
// on MkdirAll would happily build <repo>/hooks/ — and <repo> with it — for a repository an
// operator removed between ensureRepoForPush's re-resolve and this call. statRepoPath calls
// any directory a repository, so that phantom would occupy the identifier permanently: pushes
// handing git receive-pack a non-repository, and CreateRepo refusing "repository already
// exists" for a repository that does not exist.
//
// Two things stop it now, and neither is a check that could go stale between the looking and
// the writing: git will not report a hook path for a directory that is not there, and the
// installer makes hooks/ with a single os.Mkdir, which fails rather than building the parent.
// The guard this replaced was an os.Stat of repoPath immediately before the MkdirAll — the
// same rm -rf race, just narrowed to the width of two syscalls.
func TestEnsureHookRefusesAVanishedRepositoryInsteadOfCreatingOne(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	s := store.New(dataDir)
	repoPath := filepath.Join(dataDir, "vanished.git")

	err := s.EnsureHook(ctx, repoPath)
	if err == nil {
		t.Fatalf("EnsureHook = nil, want a refusal: there is no repository at %q to repair", repoPath)
	}
	if !errors.Is(err, store.ErrHookUnavailable) {
		t.Errorf("EnsureHook error = %v, want it to wrap store.ErrHookUnavailable", err)
	}
	if strings.Contains(err.Error(), "\n") {
		t.Errorf("refusal is not one line: %q", err)
	}

	if _, statErr := os.Lstat(repoPath); statErr == nil {
		t.Fatalf("EnsureHook created %q; the repair path must not conjure a repository", repoPath)
	}

	// The identifier is still free, which is the whole point: the phantom would have made
	// creation refuse "already exists" forever.
	exists, err := s.RepoExists(ctx, "vanished")
	if err != nil {
		t.Fatalf("RepoExists: %v", err)
	}
	if exists {
		t.Errorf("RepoExists(%q) = true after a refused repair, want false", "vanished")
	}
	if err := s.CreateRepo(ctx, "vanished"); err != nil {
		t.Errorf("CreateRepo after a refused repair: %v, want it to still be creatable", err)
	}
}

// TestEnsureHookAgreesWithCreateRepo is what fails if CreateRepo's installer and EnsureHook's
// ever drift apart: a repository walden has just created must need no repair. They share one
// installer today, and this notices if a later change gives them two.
func TestEnsureHookAgreesWithCreateRepo(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	s := store.New(dataDir)

	if err := s.CreateRepo(ctx, "fresh"); err != nil {
		t.Fatalf("CreateRepo: %v", err)
	}
	path, err := s.RepoPath("fresh")
	if err != nil {
		t.Fatalf("RepoPath: %v", err)
	}

	hook := filepath.Join(path, "hooks", "pre-receive")
	before, err := os.Lstat(hook)
	if err != nil {
		t.Fatalf("Lstat(%q): %v", hook, err)
	}

	if err := s.EnsureHook(ctx, path); err != nil {
		t.Fatalf("EnsureHook on a freshly created repository: %v", err)
	}

	after, err := os.Lstat(hook)
	if err != nil {
		t.Fatalf("Lstat(%q) after EnsureHook: %v", hook, err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Errorf("EnsureHook rewrote the hook CreateRepo had just installed (mtime %v -> %v); the two installers have drifted apart", before.ModTime(), after.ModTime())
	}
}

// mustMkdirAll creates dir, failing the test if it cannot.
func mustMkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll(%q): %v", dir, err)
	}
}

// mustBeUnwritable takes write permission off dir for the rest of the test, so the repair
// EnsureHook would make cannot be made — the ENOSPC, EDQUOT and EPERM cases an operator hits,
// reachable without a full filesystem. It restores the mode on cleanup so t.TempDir can remove
// the tree, and skips loudly where mode bits do not bite: as root, or on a filesystem that
// ignores them, the directory stays writable and the test would assert nothing.
func mustBeUnwritable(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatalf("Chmod(%q, 0o555): %v", dir, err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o700)
	})
	probe := filepath.Join(dir, ".write-probe")
	if err := os.Mkdir(probe, 0o700); err == nil {
		_ = os.Remove(probe)
		t.Skipf("LOUD SKIP: %q is still writable at mode 0555, so this process cannot simulate an unwritable hooks directory — it is running as root, or on a filesystem that ignores mode bits. EnsureHook's refusal path is still covered by TestEnsureHook's operator-placed-regular-file case, which needs no permission games.", dir)
	}
}

// mustGitConfig sets key to value in the local config of the repository at repoPath, through
// the real git binary rather than by writing the file, so the fixture is a config git itself
// wrote and the test is not asserting against a format it guessed at.
func mustGitConfig(t *testing.T, repoPath, key, value string) {
	t.Helper()
	cmd := exec.Command("git", "-C", repoPath, "config", "--local", key, value)
	cmd.Env = []string{"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "PATH=" + os.Getenv("PATH")}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git config %s %s in %q: %v: %s", key, value, repoPath, err, out)
	}
}

// mustGitConfigWorktree sets key to value in $GIT_DIR/config.worktree for the repository at
// repoPath — the scope `git config --local` never reads. It is the caller's business to have
// turned extensions.worktreeConfig on first; git refuses the write otherwise, and the test
// fails here rather than silently fixturing nothing.
func mustGitConfigWorktree(t *testing.T, repoPath, key, value string) {
	t.Helper()
	cmd := exec.Command("git", "-C", repoPath, "config", "--worktree", key, value)
	cmd.Env = []string{"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "PATH=" + os.Getenv("PATH")}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git config --worktree %s %s in %q: %v: %s", key, value, repoPath, err, out)
	}
}

// mustBareRepo initializes a real bare repository at path with the real git binary, so a
// fixture EnsureHook will ask git about is a repository git will actually open. It is not
// store.CreateRepo: these tests are about repositories that reached disk some way other than
// walden, so they must not arrive with walden's hook already installed.
func mustBareRepo(t *testing.T, path string) {
	t.Helper()
	cmd := exec.Command("git", "init", "-q", "--bare", "--initial-branch=main", path)
	cmd.Env = []string{"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "PATH=" + os.Getenv("PATH")}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init --bare %q: %v: %s", path, err, out)
	}
}

// mustSymlink creates the symlink name pointing at target, failing the test if it cannot.
func mustSymlink(t *testing.T, target, name string) {
	t.Helper()
	if err := os.Symlink(target, name); err != nil {
		t.Fatalf("Symlink(%q, %q): %v", target, name, err)
	}
}

// assertWaldenHook asserts that hook is a symlink to exe resolving to a runnable file — the
// one shape EnsureHook leaves behind.
func assertWaldenHook(t *testing.T, hook, exe string) {
	t.Helper()
	target, err := os.Readlink(hook)
	if err != nil {
		t.Fatalf("Readlink(%q): %v", hook, err)
	}
	if target != exe {
		t.Errorf("hooks/pre-receive -> %q, want %q", target, exe)
	}
	if err := store.HookIsRunnableForTest(hook); err != nil {
		t.Errorf("hooks/pre-receive is not runnable: %v", err)
	}
}
