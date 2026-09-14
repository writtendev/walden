package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/journal"
)

func TestActions(t *testing.T) {
	if auth.ActionRead != "r" {
		t.Errorf("expected ActionRead to be 'r', got %q", auth.ActionRead)
	}
	if auth.ActionWrite != "w" {
		t.Errorf("expected ActionWrite to be 'w', got %q", auth.ActionWrite)
	}
	if auth.ActionCreate != "c" {
		t.Errorf("expected ActionCreate to be 'c', got %q", auth.ActionCreate)
	}
}

// TestExclusiveModes pins the ruling in ARCHITECTURE.md's auth section: the two
// auth modes are mutually exclusive, and the mode not selected is not consulted.
//
// TestNewAuthorizerFactory already checks which concrete type NewAuthorizer
// hands back, which an authorizer delegating to both sources would still
// satisfy. This checks the property the ruling is actually about — a credential
// valid in the other mode is refused — so a fallback added later fails here
// instead of passing a type assertion.
func TestExclusiveModes(t *testing.T) {
	ctx := context.Background()

	priv, pub, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	trustKey := journal.FormatPublicKey(pub)

	const builtinToken = "walden_exclusive_admin"
	adminScopes, err := auth.ParseScopes([]string{"rwc:*"})
	if err != nil {
		t.Fatalf("ParseScopes: %v", err)
	}
	newStore := func() auth.TokenStore {
		t.Helper()
		store := auth.NewMemoryTokenStore()
		if err := store.SaveToken(ctx, &auth.TokenRecord{
			TokenID:   "tok_exclusive_admin",
			TokenHash: auth.HashToken(builtinToken),
			Scopes:    adminScopes,
		}); err != nil {
			t.Fatalf("SaveToken: %v", err)
		}
		return store
	}

	actions := []auth.Action{auth.ActionRead, auth.ActionWrite, auth.ActionCreate}

	// Control. In built-in mode this token grants everything, so a refusal below
	// is the mode boundary doing its job and not a token that never worked.
	builtin, err := auth.NewAuthorizer("", newStore())
	if err != nil {
		t.Fatalf("NewAuthorizer(built-in): %v", err)
	}
	for _, action := range actions {
		ok, err := builtin.Authorize(ctx, builtinToken, action, "repo-alpha")
		if !ok || err != nil {
			t.Fatalf("built-in mode refused action %q to its own admin token: ok=%v, err=%v", action, ok, err)
		}
	}

	// The ruling: the same store handed to a delegated instance is never asked.
	delegated, err := auth.NewAuthorizer(trustKey, newStore())
	if err != nil {
		t.Fatalf("NewAuthorizer(delegated): %v", err)
	}
	for _, action := range actions {
		ok, err := delegated.Authorize(ctx, builtinToken, action, "repo-alpha")
		if ok {
			t.Errorf("delegated mode granted action %q to a built-in token; under a trust key the built-in store must not be consulted", action)
		}
		// Forbidden would mean the scopes were read out of the built-in store and
		// then failed to match. The token has to be refused as unverifiable well
		// before anything weighs what it claims.
		if errors.Is(err, auth.ErrForbidden) {
			t.Errorf("delegated mode weighed the scopes of a built-in token for action %q: %v", action, err)
		}
	}

	// And the other direction. A built-in instance holds no key to verify a
	// capability against, so one signed by the trusted key is just an unknown
	// bearer token to it.
	now := time.Now().UTC()
	capToken, err := auth.SignCapability(priv, &auth.CapabilityPayload{
		Version:   "v1",
		ID:        "cap_exclusive",
		Scopes:    []string{"rwc:*"},
		IssuedAt:  now.Format(time.RFC3339),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("SignCapability: %v", err)
	}
	ok, err := builtin.Authorize(ctx, capToken, auth.ActionRead, "repo-alpha")
	if ok || !errors.Is(err, auth.ErrUnauthorized) {
		t.Errorf("built-in mode accepted a capability token: ok=%v, err=%v", ok, err)
	}
}
