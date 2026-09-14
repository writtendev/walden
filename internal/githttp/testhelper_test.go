package githttp_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/githttp"
	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/store"
)

const defaultTestToken = "walden_test_token_rwc_abcdef123456"

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
