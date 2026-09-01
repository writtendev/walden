package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/journal"
)

func TestSignAndVerifyCapability(t *testing.T) {
	priv, pub, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	refTime := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	payload := &auth.CapabilityPayload{
		Version:   "v1",
		ID:        "cap_test_01",
		Issuer:    "test-issuer",
		Subject:   "test-user",
		Scopes:    []string{"rw:blog-*", "r:docs"},
		IssuedAt:  refTime.Format(time.RFC3339),
		ExpiresAt: refTime.Add(1 * time.Hour).Format(time.RFC3339),
		NotBefore: refTime.Format(time.RFC3339),
	}

	token, err := auth.SignCapability(priv, payload)
	if err != nil {
		t.Fatalf("SignCapability failed: %v", err)
	}

	if !strings.HasPrefix(token, "v1.") {
		t.Errorf("expected token to start with 'v1.', got %q", token)
	}

	// Verify at refTime + 30 mins
	evalTime := refTime.Add(30 * time.Minute)
	parsed, scopes, err := auth.ParseAndVerifyCapability(token, pub, evalTime)
	if err != nil {
		t.Fatalf("ParseAndVerifyCapability failed: %v", err)
	}

	if parsed.ID != "cap_test_01" {
		t.Errorf("parsed ID = %q, want 'cap_test_01'", parsed.ID)
	}
	if len(scopes) != 2 {
		t.Errorf("parsed %d scopes, want 2", len(scopes))
	}
}

func TestCapabilityExpiry(t *testing.T) {
	priv, pub, _ := journal.GenerateKeypair()
	refTime := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	payload := &auth.CapabilityPayload{
		Version:   "v1",
		ID:        "cap_expired",
		Scopes:    []string{"rwc:*"},
		IssuedAt:  refTime.Add(-2 * time.Hour).Format(time.RFC3339),
		ExpiresAt: refTime.Add(-1 * time.Hour).Format(time.RFC3339),
	}

	token, err := auth.SignCapability(priv, payload)
	if err != nil {
		t.Fatalf("SignCapability failed: %v", err)
	}

	// Verify at refTime (1 hour after expiry)
	_, _, err = auth.ParseAndVerifyCapability(token, pub, refTime)
	if err == nil {
		t.Errorf("expected expired capability to fail verification")
	}
	if !errors.Is(err, auth.ErrExpired) {
		t.Errorf("expected ErrExpired, got %v", err)
	}
	if !strings.Contains(err.Error(), "token expired at") {
		t.Errorf("expected refusal message to contain expiry info, got %q", err.Error())
	}
}

func TestCapabilityNotYetValid(t *testing.T) {
	priv, pub, _ := journal.GenerateKeypair()
	refTime := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	payload := &auth.CapabilityPayload{
		Version:   "v1",
		ID:        "cap_future",
		Scopes:    []string{"rwc:*"},
		IssuedAt:  refTime.Format(time.RFC3339),
		ExpiresAt: refTime.Add(2 * time.Hour).Format(time.RFC3339),
		NotBefore: refTime.Add(1 * time.Hour).Format(time.RFC3339),
	}

	token, err := auth.SignCapability(priv, payload)
	if err != nil {
		t.Fatalf("SignCapability failed: %v", err)
	}

	// Verify at refTime (30 min before not_before)
	_, _, err = auth.ParseAndVerifyCapability(token, pub, refTime.Add(30*time.Minute))
	if err == nil {
		t.Errorf("expected future capability to fail verification")
	}
	if !errors.Is(err, auth.ErrNotYetValid) {
		t.Errorf("expected ErrNotYetValid, got %v", err)
	}
}

func TestCapabilitySignatureMismatch(t *testing.T) {
	priv1, _, _ := journal.GenerateKeypair()
	_, pub2, _ := journal.GenerateKeypair()

	refTime := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	payload := &auth.CapabilityPayload{
		Version:   "v1",
		ID:        "cap_mismatch",
		Scopes:    []string{"rwc:*"},
		IssuedAt:  refTime.Format(time.RFC3339),
		ExpiresAt: refTime.Add(1 * time.Hour).Format(time.RFC3339),
	}

	token, _ := auth.SignCapability(priv1, payload)

	// Verify with wrong public key pub2
	_, _, err := auth.ParseAndVerifyCapability(token, pub2, refTime)
	if err == nil {
		t.Errorf("expected signature mismatch to fail")
	}
	if !errors.Is(err, auth.ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestDelegatedAuthorizer(t *testing.T) {
	priv, pub, _ := journal.GenerateKeypair()
	refTime := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	authorizer := auth.NewDelegatedAuthorizerWithClock(pub, func() time.Time {
		return refTime.Add(15 * time.Minute)
	})

	payload := &auth.CapabilityPayload{
		Version:   "v1",
		ID:        "cap_auth",
		Scopes:    []string{"rw:blog-*", "r:docs"},
		IssuedAt:  refTime.Format(time.RFC3339),
		ExpiresAt: refTime.Add(1 * time.Hour).Format(time.RFC3339),
	}
	token, _ := auth.SignCapability(priv, payload)

	ctx := context.Background()

	// Allowed read
	ok, err := authorizer.Authorize(ctx, token, auth.ActionRead, "blog-posts")
	if !ok || err != nil {
		t.Errorf("expected allowed read, got ok=%v, err=%v", ok, err)
	}

	// Allowed write
	ok, err = authorizer.Authorize(ctx, token, auth.ActionWrite, "blog-posts")
	if !ok || err != nil {
		t.Errorf("expected allowed write, got ok=%v, err=%v", ok, err)
	}

	// Forbidden create
	ok, err = authorizer.Authorize(ctx, token, auth.ActionCreate, "blog-posts")
	if ok || !errors.Is(err, auth.ErrForbidden) {
		t.Errorf("expected forbidden create, got ok=%v, err=%v", ok, err)
	}

	// Forbidden repo
	ok, err = authorizer.Authorize(ctx, token, auth.ActionRead, "other-repo")
	if ok || !errors.Is(err, auth.ErrForbidden) {
		t.Errorf("expected forbidden on other repo, got ok=%v, err=%v", ok, err)
	}
}

func TestNewAuthorizerFactory(t *testing.T) {
	priv, pub, _ := journal.GenerateKeypair()
	pubStr := journal.FormatPublicKey(pub)

	// Delegated mode
	delegated, err := auth.NewAuthorizer(pubStr, nil)
	if err != nil {
		t.Fatalf("NewAuthorizer with trust key failed: %v", err)
	}
	if _, ok := delegated.(*auth.DelegatedAuthorizer); !ok {
		t.Errorf("expected *DelegatedAuthorizer, got %T", delegated)
	}

	// Builtin mode
	builtin, err := auth.NewAuthorizer("", nil)
	if err != nil {
		t.Fatalf("NewAuthorizer with empty trust key failed: %v", err)
	}
	if _, ok := builtin.(*auth.BuiltinAuthorizer); !ok {
		t.Errorf("expected *BuiltinAuthorizer, got %T", builtin)
	}

	// Invalid trust key
	_, err = auth.NewAuthorizer("invalid-key", nil)
	if err == nil {
		t.Errorf("expected error for invalid trust key")
	}
	_ = priv
}
