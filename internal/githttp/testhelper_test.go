package githttp_test

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/githttp"
	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/store"
)

const defaultTestToken = "walden_test_token_rwc_abcdef123456"

// writeStandInGit writes an executable "git" into binDir that answers
// walden's repository-config probe the way a real git answers it for a bare
// repository, and runs serving for every other invocation.
//
// The tests that put a stand-in git on PATH are about process lifetime — that
// cancelling a request kills the git child and its whole process group, and
// that aborted requests leak nothing. Their stand-ins stream forever and
// ignore their arguments, which was fine while the ref advertisement was the
// first git a request execs. It no longer is: walden asks each repository for
// its own config key names before it will serve it, so a stand-in that
// answers that probe by streaming forever hangs the request before the part
// under test is reached, and one that records its pid records the probe's
// rather than the server child's.
//
// The answer is written from Go as the exact bytes `git config --list
// --show-scope --name-only -z` prints for a freshly initialized bare
// repository — scope and key NUL-terminated in pairs, no values — rather than
// being escaped through a shell printf, which cannot express a NUL portably
// across the shells /bin/sh is on Linux and macOS.
func writeStandInGit(t *testing.T, binDir, serving string) {
	t.Helper()

	answer := filepath.Join(binDir, "config-answer")
	if err := os.WriteFile(answer, []byte(
		"local\x00core.repositoryformatversion\x00local\x00core.filemode\x00local\x00core.bare\x00",
	), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", answer, err)
	}

	// The probe is the only invocation carrying "config" as a word of its
	// own; every subcommand walden serves with is upload-pack or
	// receive-pack. Matching on the word rather than on an argument position
	// keeps this working if the probe's flags are ever reordered.
	script := "#!/bin/sh\ncase \" $* \" in\n  *\" config \"*)\n    cat " + answer + "\n    exit 0\n    ;;\nesac\n" + serving
	if err := os.WriteFile(filepath.Join(binDir, "git"), []byte(script), 0o755); err != nil {
		t.Fatalf("write stand-in git: %v", err)
	}
}

// newTestAuthorizer creates an Authorizer in built-in mode with scopes (defaults to "rwc:*")
// and returns the Authorizer and the valid raw token.
func newTestAuthorizer(t *testing.T, scopes ...string) (auth.Authorizer, string) {
	t.Helper()
	if len(scopes) == 0 {
		scopes = []string{"rwc:*"}
	}
	parsedScopes, err := auth.ParseScopes(scopes)
	if err != nil {
		t.Fatalf("ParseScopes(%v): %v", scopes, err)
	}

	tokenStore := auth.NewMemoryTokenStore()
	if err := tokenStore.CreateToken(context.Background(), &auth.TokenRecord{
		TokenID:   "tok_test",
		TokenHash: auth.HashToken(defaultTestToken),
		Scopes:    parsedScopes,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	return auth.NewBuiltinAuthorizer(tokenStore), defaultTestToken
}

// newTestHandler creates a *githttp.Handler with a valid "rwc:*" authorizer and returns the handler and token.
func newTestHandler(t *testing.T, s *store.Store, journalURL string) (*githttp.Handler, string) {
	t.Helper()
	authorizer, tok := newTestAuthorizer(t, "rwc:*")
	return githttp.NewHandler(authorizer, s, journalURL), tok
}

// authURL attaches HTTP Basic auth credentials (user "walden", password token) to rawURL.
func authURL(rawURL, token string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.User = url.UserPassword("walden", token)
	return u.String()
}

// testAuthPair holds an Authorizer and a matching credential string.
type testAuthPair struct {
	Authorizer auth.Authorizer
	Token      string
}

// mountTestAuthorizers creates both built-in and delegated authorizers for testing.
func mountTestAuthorizers(t *testing.T, scope string) map[string]testAuthPair {
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

	const builtinTok = "walden_test_builtin_token_9876543210"
	tokenStore := auth.NewMemoryTokenStore()
	if err := tokenStore.CreateToken(ctx, &auth.TokenRecord{
		TokenID:   "tok_test_pair",
		TokenHash: auth.HashToken(builtinTok),
		Scopes:    scopes,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	now := time.Now().UTC()
	capToken, err := auth.SignCapability(priv, &auth.CapabilityPayload{
		Version:   "v1",
		ID:        "cap_test_" + scope,
		Scopes:    []string{scope},
		IssuedAt:  now.Format(time.RFC3339),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("SignCapability: %v", err)
	}

	return map[string]testAuthPair{
		"built-in":  {auth.NewBuiltinAuthorizer(tokenStore), builtinTok},
		"delegated": {auth.NewDelegatedAuthorizer(pub), capToken},
	}
}
