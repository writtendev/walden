package githttp

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/store"
)

// authPair holds one Authorizer implementation and a credential it accepts.
type authPair struct {
	authorizer auth.Authorizer
	token      string
}

// mountAuthorizers builds both Authorizer implementations for the same scope string, each
// holding a credential that carries exactly that scope, so a test drives the identical
// question through both providers of "one question, one pluggable answer" — mirroring
// internal/auth/decision_test.go's own mount helper, since ensureRepoForPush must not behave
// differently depending on which one answers it.
func mountAuthorizers(t *testing.T, scope string) map[string]authPair {
	t.Helper()
	ctx := context.Background()

	scopes, err := auth.ParseScopes([]string{scope})
	if err != nil {
		t.Fatalf("ParseScopes(%q): %v", scope, err)
	}

	priv, pub, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	const builtinToken = "walden_create_test_token"
	tokenStore := auth.NewMemoryTokenStore()
	if err := tokenStore.CreateToken(ctx, &auth.TokenRecord{
		TokenID:   "tok_create_test",
		TokenHash: auth.HashToken(builtinToken),
		Scopes:    scopes,
	}); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	now := time.Now().UTC()
	capToken, err := auth.SignCapability(priv, &auth.CapabilityPayload{
		Version:   "v1",
		ID:        "cap_create_test_" + scope,
		Scopes:    []string{scope},
		IssuedAt:  now.Format(time.RFC3339),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("SignCapability: %v", err)
	}

	return map[string]authPair{
		"built-in":  {auth.NewBuiltinAuthorizer(tokenStore), builtinToken},
		"delegated": {auth.NewDelegatedAuthorizer(pub), capToken},
	}
}

// TestEnsureRepoForPushCreatesOnFullScope covers "rwc:* + missing repo": the repository is
// created and its path returned, and RepoExists reports true afterward.
func TestEnsureRepoForPushCreatesOnFullScope(t *testing.T) {
	ctx := context.Background()
	for name, p := range mountAuthorizers(t, "rwc:*") {
		t.Run(name, func(t *testing.T) {
			s := store.New(t.TempDir())
			h := NewHandler(p.authorizer, s, "")

			path, err := h.ensureRepoForPush(ctx, p.token, "newrepo")
			if err != nil {
				t.Fatalf("ensureRepoForPush: %v", err)
			}

			wantPath, err := s.RepoPath("newrepo")
			if err != nil {
				t.Fatalf("RepoPath: %v", err)
			}
			if path != wantPath {
				t.Errorf("ensureRepoForPush path = %q, want %q", path, wantPath)
			}

			exists, err := s.RepoExists(ctx, "newrepo")
			if err != nil {
				t.Fatalf("RepoExists: %v", err)
			}
			if !exists {
				t.Errorf("RepoExists after ensureRepoForPush = false, want true")
			}
		})
	}
}

// TestEnsureRepoForPushRefusesMissingCreateScope covers "rw:* + missing repo": nothing is
// created, and the refusal is spec/auth/v1 §3.4's line verbatim — pinned byte for byte, minus
// the "refusal: " display prefix internal/auth does not bake into its own refusals (see
// AGENTS.md's note on WALD-102).
func TestEnsureRepoForPushRefusesMissingCreateScope(t *testing.T) {
	ctx := context.Background()
	for name, p := range mountAuthorizers(t, "rw:*") {
		t.Run(name, func(t *testing.T) {
			s := store.New(t.TempDir())
			h := NewHandler(p.authorizer, s, "")

			_, err := h.ensureRepoForPush(ctx, p.token, "newrepo")
			if err == nil {
				t.Fatalf("ensureRepoForPush = nil, want error")
			}

			const want = `repository not found: repository 'newrepo' does not exist and token lacks create scope 'c' (request create scope 'c' or push to an existing repository)`
			if err.Error() != want {
				t.Errorf("ensureRepoForPush error = %q, want %q", err.Error(), want)
			}
			if !errors.Is(err, store.ErrRepoNotFound) {
				t.Errorf("ensureRepoForPush error = %v, want errors.Is store.ErrRepoNotFound", err)
			}
			if strings.ContainsAny(err.Error(), "\n\r") {
				t.Errorf("refusal is not a single line: %q", err.Error())
			}

			exists, existsErr := s.RepoExists(ctx, "newrepo")
			if existsErr != nil {
				t.Fatalf("RepoExists: %v", existsErr)
			}
			if exists {
				t.Errorf("RepoExists after refused create = true, want false")
			}
		})
	}
}

// TestEnsureRepoForPushSucceedsWriteOnlyAgainstExistingRepo covers "rw:* + existing repo":
// this is the regression the existence-first ordering exists for. Asking for
// Actions{Write, Create} unconditionally would refuse this rw-only push for want of a scope
// it does not need.
func TestEnsureRepoForPushSucceedsWriteOnlyAgainstExistingRepo(t *testing.T) {
	ctx := context.Background()
	for name, p := range mountAuthorizers(t, "rw:*") {
		t.Run(name, func(t *testing.T) {
			s := store.New(t.TempDir())
			if err := s.CreateRepo(ctx, "existing"); err != nil {
				t.Fatalf("CreateRepo (setup): %v", err)
			}
			h := NewHandler(p.authorizer, s, "")

			path, err := h.ensureRepoForPush(ctx, p.token, "existing")
			if err != nil {
				t.Fatalf("ensureRepoForPush: %v", err)
			}

			wantPath, err := s.RepoPath("existing")
			if err != nil {
				t.Fatalf("RepoPath: %v", err)
			}
			if path != wantPath {
				t.Errorf("ensureRepoForPush path = %q, want %q", path, wantPath)
			}
		})
	}
}

// TestEnsureRepoForPushRefusesReadOnlyMissingRepo covers "r:* + missing repo": the refusal
// must be the generic "forbidden" naming the missing 'w', never the §3.4 create-specific
// line, because auth.Missing reports the first missing action in canonical r, w, c order.
func TestEnsureRepoForPushRefusesReadOnlyMissingRepo(t *testing.T) {
	ctx := context.Background()
	for name, p := range mountAuthorizers(t, "r:*") {
		t.Run(name, func(t *testing.T) {
			s := store.New(t.TempDir())
			h := NewHandler(p.authorizer, s, "")

			_, err := h.ensureRepoForPush(ctx, p.token, "newrepo")
			if err == nil {
				t.Fatalf("ensureRepoForPush = nil, want error")
			}
			if !errors.Is(err, auth.ErrForbidden) {
				t.Errorf("ensureRepoForPush error = %v, want errors.Is auth.ErrForbidden", err)
			}
			if errors.Is(err, store.ErrRepoNotFound) {
				t.Errorf("ensureRepoForPush error incorrectly also matches store.ErrRepoNotFound: %v", err)
			}
			if !strings.Contains(err.Error(), `"w"`) {
				t.Errorf("ensureRepoForPush error %q does not name 'w'", err.Error())
			}
			if strings.ContainsAny(err.Error(), "\n\r") {
				t.Errorf("refusal is not a single line: %q", err.Error())
			}

			exists, existsErr := s.RepoExists(ctx, "newrepo")
			if existsErr != nil {
				t.Fatalf("RepoExists: %v", existsErr)
			}
			if exists {
				t.Errorf("RepoExists after refused push = true, want false")
			}
		})
	}
}

// TestEnsureRepoForPushRefusesReadOnlyExistingRepo covers "r:* + existing repo": forbidden,
// naming 'w'.
func TestEnsureRepoForPushRefusesReadOnlyExistingRepo(t *testing.T) {
	ctx := context.Background()
	for name, p := range mountAuthorizers(t, "r:*") {
		t.Run(name, func(t *testing.T) {
			s := store.New(t.TempDir())
			if err := s.CreateRepo(ctx, "existing"); err != nil {
				t.Fatalf("CreateRepo (setup): %v", err)
			}
			h := NewHandler(p.authorizer, s, "")

			_, err := h.ensureRepoForPush(ctx, p.token, "existing")
			if err == nil {
				t.Fatalf("ensureRepoForPush = nil, want error")
			}
			if !errors.Is(err, auth.ErrForbidden) {
				t.Errorf("ensureRepoForPush error = %v, want errors.Is auth.ErrForbidden", err)
			}
			if !strings.Contains(err.Error(), `"w"`) {
				t.Errorf("ensureRepoForPush error %q does not name 'w'", err.Error())
			}
			if strings.ContainsAny(err.Error(), "\n\r") {
				t.Errorf("refusal is not a single line: %q", err.Error())
			}
		})
	}
}

// raceAuthorizer wraps a real Authorizer and runs before immediately prior to delegating to
// it, so a test can inject a filesystem change at the exact point ensureRepoForPush has
// already established RepoExists = false but has not yet reached CreateRepo — the window
// PR #35's round 3 review found unprotected: CreateRepo's own top-of-function Stat had no
// IsDir check, so a plain file appearing in that window made CreateRepo report ErrRepoExists,
// which ensureRepoForPush's round-2 "lost race is success" swallow then treated as a win.
type raceAuthorizer struct {
	auth.Authorizer
	before func()
}

func (r *raceAuthorizer) Authorize(ctx context.Context, token string, required auth.Actions, repo string) error {
	if r.before != nil {
		r.before()
	}
	return r.Authorizer.Authorize(ctx, token, required, repo)
}

// TestEnsureRepoForPushRefusesLostRaceToNonDirectory pins PR #35 round 3's finding directly
// against ensureRepoForPush, not just against store.CreateRepo in isolation: a non-directory
// planted at the repository's path in the window between RepoExists reporting false and
// CreateRepo's own check must make ensureRepoForPush refuse, never silently return that path
// as if a concurrent creator had merely won a legitimate race.
func TestEnsureRepoForPushRefusesLostRaceToNonDirectory(t *testing.T) {
	ctx := context.Background()
	for name, p := range mountAuthorizers(t, "rwc:*") {
		t.Run(name, func(t *testing.T) {
			s := store.New(t.TempDir())

			path, err := s.RepoPath("racer")
			if err != nil {
				t.Fatalf("RepoPath: %v", err)
			}

			wrapped := &raceAuthorizer{
				Authorizer: p.authorizer,
				before: func() {
					if err := os.WriteFile(path, []byte("not a repo"), 0o644); err != nil {
						t.Fatalf("WriteFile(%q): %v", path, err)
					}
				},
			}
			h := NewHandler(wrapped, s, "")

			gotPath, err := h.ensureRepoForPush(ctx, p.token, "racer")
			if err == nil {
				t.Fatalf("ensureRepoForPush = (%q, nil), want a refusal: CreateRepo found a non-directory at the path, not a lost creation race", gotPath)
			}
			if errors.Is(err, store.ErrRepoExists) {
				t.Errorf("ensureRepoForPush error = %v, treated a non-directory at the path as a lost creation race and swallowed it as success", err)
			}
			if !errors.Is(err, store.ErrStoreUnavailable) {
				t.Errorf("ensureRepoForPush error = %v, want errors.Is store.ErrStoreUnavailable", err)
			}
		})
	}
}

// TestEnsureRepoForPushRefusesEscapingSymlinkSwappedDuringAuthorize is the other half of the
// raceAuthorizer window, and the one the exists == true branch depends on: a repository that
// exists when ResolveRepo answers is replaced, during Authorize, by a symlink pointing at a
// directory outside the data root. CreateRepo never runs on this branch, so its own
// statRepoPath is not the guard here — ensureRepoForPush's trailing RepoPath is the only
// thing between the swapped-in symlink and handleReceivePack exec'ing git against it. Drop
// that re-resolution and return the path captured before Authorize, and this test is what
// goes red.
func TestEnsureRepoForPushRefusesEscapingSymlinkSwappedDuringAuthorize(t *testing.T) {
	ctx := context.Background()
	// rw:* is the whole point: the repository already exists, so Create is not required and
	// the push takes the exists == true path.
	for name, p := range mountAuthorizers(t, "rw:*") {
		t.Run(name, func(t *testing.T) {
			s := store.New(t.TempDir())
			if err := s.CreateRepo(ctx, "racer"); err != nil {
				t.Fatalf("CreateRepo (setup): %v", err)
			}

			path, err := s.RepoPath("racer")
			if err != nil {
				t.Fatalf("RepoPath: %v", err)
			}

			// A sibling of the data directory, so it is outside the resolved root.
			outside := t.TempDir()

			wrapped := &raceAuthorizer{
				Authorizer: p.authorizer,
				before: func() {
					if err := os.RemoveAll(path); err != nil {
						t.Fatalf("RemoveAll(%q): %v", path, err)
					}
					if err := os.Symlink(outside, path); err != nil {
						t.Fatalf("Symlink(%q, %q): %v", outside, path, err)
					}
				},
			}
			h := NewHandler(wrapped, s, "")

			gotPath, err := h.ensureRepoForPush(ctx, p.token, "racer")
			if err == nil {
				t.Fatalf("ensureRepoForPush = (%q, nil), want a refusal: the repository path now escapes the data directory via a symlink", gotPath)
			}
			if !errors.Is(err, store.ErrInvalidRepo) {
				t.Errorf("ensureRepoForPush error = %v, want errors.Is store.ErrInvalidRepo", err)
			}
			if gotPath != "" {
				t.Errorf("ensureRepoForPush path = %q, want %q: a refused push must not hand any path to git", gotPath, "")
			}
			if strings.ContainsAny(err.Error(), "\n\r") {
				t.Errorf("refusal is not a single line: %q", err.Error())
			}
		})
	}
}

// TestEnsureRepoForPushConcurrentCreatorsAllSucceed drives the race PR #35's round-2 review
// found rather than reasoning about it: several rwc:* pushes reaching the same missing
// repository at once. Before the fix, store.CreateRepo's ErrRepoExists passed straight
// through as a refusal telling every loser to "push to the existing repository instead of
// creating it" — the exact push that had just failed. Every authorized caller must come out
// of ensureRepoForPush able to push, against a repository created exactly once, with no
// loser's .create-* temporary directory left behind.
func TestEnsureRepoForPushConcurrentCreatorsAllSucceed(t *testing.T) {
	ctx := context.Background()
	const n = 8

	for name, p := range mountAuthorizers(t, "rwc:*") {
		t.Run(name, func(t *testing.T) {
			dataDir := t.TempDir()
			s := store.New(dataDir)
			h := NewHandler(p.authorizer, s, "")

			var wg sync.WaitGroup
			paths := make([]string, n)
			errs := make([]error, n)
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					paths[i], errs[i] = h.ensureRepoForPush(ctx, p.token, "racer")
				}(i)
			}
			wg.Wait()

			wantPath, err := s.RepoPath("racer")
			if err != nil {
				t.Fatalf("RepoPath: %v", err)
			}

			for i := 0; i < n; i++ {
				if errs[i] != nil {
					t.Errorf("ensureRepoForPush[%d] = %v, want nil (an authorized caller must not be refused for losing a creation race)", i, errs[i])
				}
				if paths[i] != wantPath {
					t.Errorf("ensureRepoForPush[%d] path = %q, want %q", i, paths[i], wantPath)
				}
			}

			exists, err := s.RepoExists(ctx, "racer")
			if err != nil {
				t.Fatalf("RepoExists: %v", err)
			}
			if !exists {
				t.Fatalf("RepoExists after concurrent creators = false, want true")
			}

			// The repository was created exactly once and no loser's temporary directory
			// survived: the data directory holds only "racer.git", nothing else.
			entries, err := os.ReadDir(dataDir)
			if err != nil {
				t.Fatalf("ReadDir(%q): %v", dataDir, err)
			}
			if len(entries) != 1 || entries[0].Name() != filepath.Base(wantPath) {
				names := make([]string, len(entries))
				for i, e := range entries {
					names[i] = e.Name()
				}
				t.Errorf("data directory entries = %v, want exactly [%q]", names, filepath.Base(wantPath))
			}
		})
	}
}

// TestEnsureRepoForPushInstallsHookOnOperatorPlacedRepo is the case this ticket exists for:
// a bare repository an operator made themselves and dropped into the data directory. walden
// never created it, so nothing has ever installed its pre-receive hook, and a push through
// it would move refs that were never journaled. The push proceeds — and the hook is walden's
// afterwards.
func TestEnsureRepoForPushInstallsHookOnOperatorPlacedRepo(t *testing.T) {
	ctx := context.Background()
	for name, p := range mountAuthorizers(t, "rw:*") {
		t.Run(name, func(t *testing.T) {
			s := store.New(t.TempDir())
			wantPath := initBareRepoByHand(t, s, "byhand")

			h := NewHandler(p.authorizer, s, "")
			path, err := h.ensureRepoForPush(ctx, p.token, "byhand")
			if err != nil {
				t.Fatalf("ensureRepoForPush: %v", err)
			}
			if path != wantPath {
				t.Errorf("ensureRepoForPush = %q, want %q", path, wantPath)
			}

			hook := filepath.Join(path, "hooks", "pre-receive")
			target, err := os.Readlink(hook)
			if err != nil {
				t.Fatalf("Readlink(%q): %v, want walden's hook installed by the push", hook, err)
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatalf("os.Executable: %v", err)
			}
			if target != exe {
				t.Errorf("hooks/pre-receive -> %q, want %q", target, exe)
			}
		})
	}
}

// TestEnsureRepoForPushRefusesForeignHook is the other half of the same decision: an
// operator's own pre-receive script at that path means walden's hook never runs, so the push
// cannot be accepted — and the script is not walden's to delete, so it is not deleted. The
// refusal carries store.ErrHookUnavailable and not store.ErrStoreUnavailable: the path
// resolved perfectly well.
func TestEnsureRepoForPushRefusesForeignHook(t *testing.T) {
	ctx := context.Background()
	for name, p := range mountAuthorizers(t, "rw:*") {
		t.Run(name, func(t *testing.T) {
			s := store.New(t.TempDir())
			path := initBareRepoByHand(t, s, "byhand")

			hook := filepath.Join(path, "hooks", "pre-receive")
			const script = "#!/bin/sh\nexit 0\n"
			if err := os.WriteFile(hook, []byte(script), 0o755); err != nil {
				t.Fatalf("WriteFile(%q): %v", hook, err)
			}

			h := NewHandler(p.authorizer, s, "")
			gotPath, err := h.ensureRepoForPush(ctx, p.token, "byhand")
			if err == nil {
				t.Fatalf("ensureRepoForPush = (%q, nil), want a refusal: walden's hook would never run", gotPath)
			}
			if !errors.Is(err, store.ErrHookUnavailable) {
				t.Errorf("ensureRepoForPush error = %v, want errors.Is store.ErrHookUnavailable", err)
			}
			if errors.Is(err, store.ErrStoreUnavailable) {
				t.Errorf("ensureRepoForPush error = %v, want it not to wear ErrStoreUnavailable: the repository path resolved", err)
			}

			got, err := os.ReadFile(hook)
			if err != nil {
				t.Fatalf("ReadFile(%q): %v, want the operator's own hook left where they put it", hook, err)
			}
			if string(got) != script {
				t.Errorf("hooks/pre-receive = %q, want %q: walden must not rewrite a file it did not put there", got, script)
			}
		})
	}
}

// initBareRepoByHand creates repo's bare repository with the real git binary and nothing
// else — no walden, so no hook — exactly as an operator would by running `git init --bare`
// inside the data directory. It returns the repository's path.
func initBareRepoByHand(t *testing.T, s *store.Store, repo string) string {
	t.Helper()

	path, err := s.RepoPath(repo)
	if err != nil {
		t.Fatalf("RepoPath(%q): %v", repo, err)
	}
	cmd := exec.Command("git", "init", "-q", "--bare", "--initial-branch=main", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init --bare %q: %v\n%s", path, err, out)
	}
	if _, err := os.Lstat(filepath.Join(path, "hooks", "pre-receive")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Lstat(hooks/pre-receive) = %v, want it absent: git's own template must not be installing one", err)
	}
	return path
}
