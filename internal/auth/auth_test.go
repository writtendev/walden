package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/journal"
)

// onlyAction returns an Actions set containing exactly action. Several tests here and in
// fixtures_test.go loop over the three auth.Action values to probe them one at a time;
// this is the single place that turns a loop variable back into the Actions set Authorize
// now takes.
func onlyAction(action auth.Action) auth.Actions {
	switch action {
	case auth.ActionRead:
		return auth.Actions{Read: true}
	case auth.ActionWrite:
		return auth.Actions{Write: true}
	case auth.ActionCreate:
		return auth.Actions{Create: true}
	default:
		return auth.Actions{}
	}
}

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
		if err := store.CreateToken(ctx, &auth.TokenRecord{
			TokenID:   "tok_exclusive_admin",
			TokenHash: auth.HashToken(builtinToken),
			Scopes:    adminScopes,
		}); err != nil {
			t.Fatalf("CreateToken: %v", err)
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
		if err := builtin.Authorize(ctx, builtinToken, onlyAction(action), "repo-alpha"); err != nil {
			t.Fatalf("built-in mode refused action %q to its own admin token: err=%v", action, err)
		}
	}

	// The ruling: the same store handed to a delegated instance is never asked.
	delegated, err := auth.NewAuthorizer(trustKey, newStore())
	if err != nil {
		t.Fatalf("NewAuthorizer(delegated): %v", err)
	}
	for _, action := range actions {
		err := delegated.Authorize(ctx, builtinToken, onlyAction(action), "repo-alpha")
		if err == nil {
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
	err = builtin.Authorize(ctx, capToken, auth.Actions{Read: true}, "repo-alpha")
	if !errors.Is(err, auth.ErrUnauthorized) {
		t.Errorf("built-in mode accepted a capability token: err=%v", err)
	}
}

// TestCheckRepoAndTokenOrdering pins that CheckRepoAndToken validates the
// repo identifier before it does any token work. An invalid identifier with
// an empty token must fail as ErrInvalidRepo, not ErrUnauthorized — otherwise
// a later edit could quietly swap the two checks and identifier validation
// would stop happening before authentication work, which is the property
// WALD-37 requires.
func TestCheckRepoAndTokenOrdering(t *testing.T) {
	err := auth.CheckRepoAndToken("", "repo/sub")
	if !errors.Is(err, auth.ErrInvalidRepo) {
		t.Errorf("expected ErrInvalidRepo for invalid repo with empty token, got %v", err)
	}
	if errors.Is(err, auth.ErrUnauthorized) {
		t.Errorf("expected repo validation to precede the token check, got ErrUnauthorized: %v", err)
	}
}
