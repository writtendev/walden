package githttp

import (
	"context"
	"errors"
	"strings"
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
	if err := tokenStore.SaveToken(ctx, &auth.TokenRecord{
		TokenID:   "tok_create_test",
		TokenHash: auth.HashToken(builtinToken),
		Scopes:    scopes,
	}); err != nil {
		t.Fatalf("SaveToken: %v", err)
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
			h := NewHandler(p.authorizer, s)

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
			h := NewHandler(p.authorizer, s)

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
			h := NewHandler(p.authorizer, s)

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
			h := NewHandler(p.authorizer, s)

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
			h := NewHandler(p.authorizer, s)

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
