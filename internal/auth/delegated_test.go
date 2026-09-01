package auth_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

func TestJSONEnvelopeCapability(t *testing.T) {
	priv, pub, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	refTime := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	payload := auth.CapabilityPayload{
		Version:   "v1",
		ID:        "cap_json_01",
		Issuer:    "forge.example.com",
		Subject:   "user_42",
		Scopes:    []string{"rw:blog-*", "r:docs"},
		IssuedAt:  refTime.Format(time.RFC3339),
		ExpiresAt: refTime.Add(1 * time.Hour).Format(time.RFC3339),
		NotBefore: refTime.Format(time.RFC3339),
	}

	canonicalBytes := auth.CanonicalCapabilityPayload(&payload)
	sigBytes := ed25519.Sign(priv, canonicalBytes)
	sigHex := journal.FormatSignature(sigBytes)

	// Case 1: JSON envelope with ed25519:<hex> signature and version at envelope level
	envHex := fmt.Sprintf(`{
		"version": "v1",
		"payload": {
			"id": "%s",
			"issuer": "%s",
			"subject": "%s",
			"scopes": ["rw:blog-*", "r:docs"],
			"issued_at": "%s",
			"expires_at": "%s",
			"not_before": "%s"
		},
		"signature": "%s"
	}`, payload.ID, payload.Issuer, payload.Subject, payload.IssuedAt, payload.ExpiresAt, payload.NotBefore, sigHex)

	evalTime := refTime.Add(30 * time.Minute)
	parsed, scopes, err := auth.ParseAndVerifyCapability(envHex, pub, evalTime)
	if err != nil {
		t.Fatalf("ParseAndVerifyCapability failed for JSON envelope (hex sig): %v", err)
	}
	if parsed.ID != "cap_json_01" || len(scopes) != 2 {
		t.Errorf("unexpected parsed result: %+v, scopes: %v", parsed, scopes)
	}

	// Case 2: JSON envelope with base64url signature
	sigB64 := base64.RawURLEncoding.EncodeToString(sigBytes)
	envB64 := fmt.Sprintf(`{
		"version": "v1",
		"payload": {
			"version": "v1",
			"id": "%s",
			"issuer": "%s",
			"subject": "%s",
			"scopes": ["rw:blog-*", "r:docs"],
			"issued_at": "%s",
			"expires_at": "%s",
			"not_before": "%s"
		},
		"signature": "%s"
	}`, payload.ID, payload.Issuer, payload.Subject, payload.IssuedAt, payload.ExpiresAt, payload.NotBefore, sigB64)

	parsed, scopes, err = auth.ParseAndVerifyCapability(envB64, pub, evalTime)
	if err != nil {
		t.Fatalf("ParseAndVerifyCapability failed for JSON envelope (b64 sig): %v", err)
	}
	if parsed.ID != "cap_json_01" || len(scopes) != 2 {
		t.Errorf("unexpected parsed result: %+v, scopes: %v", parsed, scopes)
	}

	// Case 3: Invalid JSON envelope syntax
	_, _, err = auth.ParseAndVerifyCapability("{invalid-json", pub, evalTime)
	if err == nil || !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for malformed JSON envelope, got %v", err)
	}

	// Case 4: Invalid signature string in envelope
	envBadSig := `{"version":"v1","payload":{"id":"cap1","scopes":["r:*"],"issued_at":"2026-09-01T12:00:00Z","expires_at":"2026-09-01T13:00:00Z"},"signature":"not-a-sig!!!"}`
	_, _, err = auth.ParseAndVerifyCapability(envBadSig, pub, evalTime)
	if err == nil || !errors.Is(err, auth.ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature for bad signature in envelope, got %v", err)
	}
}

func TestSignCapabilityValidation(t *testing.T) {
	priv, _, _ := journal.GenerateKeypair()
	refTime := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		payload auth.CapabilityPayload
		wantErr error
	}{
		{
			name: "empty-id",
			payload: auth.CapabilityPayload{
				Scopes:    []string{"rwc:*"},
				IssuedAt:  refTime.Format(time.RFC3339),
				ExpiresAt: refTime.Add(time.Hour).Format(time.RFC3339),
			},
			wantErr: auth.ErrInvalidToken,
		},
		{
			name: "empty-scopes",
			payload: auth.CapabilityPayload{
				ID:        "cap_1",
				Scopes:    []string{},
				IssuedAt:  refTime.Format(time.RFC3339),
				ExpiresAt: refTime.Add(time.Hour).Format(time.RFC3339),
			},
			wantErr: auth.ErrInvalidScope,
		},
		{
			name: "invalid-scope-syntax",
			payload: auth.CapabilityPayload{
				ID:        "cap_1",
				Scopes:    []string{"invalid-scope"},
				IssuedAt:  refTime.Format(time.RFC3339),
				ExpiresAt: refTime.Add(time.Hour).Format(time.RFC3339),
			},
			wantErr: auth.ErrInvalidScope,
		},
		{
			name: "empty-issued-at",
			payload: auth.CapabilityPayload{
				ID:        "cap_1",
				Scopes:    []string{"rwc:*"},
				ExpiresAt: refTime.Add(time.Hour).Format(time.RFC3339),
			},
			wantErr: auth.ErrInvalidToken,
		},
		{
			name: "invalid-issued-at",
			payload: auth.CapabilityPayload{
				ID:        "cap_1",
				Scopes:    []string{"rwc:*"},
				IssuedAt:  "not-a-timestamp",
				ExpiresAt: refTime.Add(time.Hour).Format(time.RFC3339),
			},
			wantErr: auth.ErrInvalidToken,
		},
		{
			name: "empty-expires-at",
			payload: auth.CapabilityPayload{
				ID:       "cap_1",
				Scopes:   []string{"rwc:*"},
				IssuedAt: refTime.Format(time.RFC3339),
			},
			wantErr: auth.ErrInvalidToken,
		},
		{
			name: "invalid-expires-at",
			payload: auth.CapabilityPayload{
				ID:        "cap_1",
				Scopes:    []string{"rwc:*"},
				IssuedAt:  refTime.Format(time.RFC3339),
				ExpiresAt: "bad-time",
			},
			wantErr: auth.ErrInvalidToken,
		},
		{
			name: "invalid-not-before",
			payload: auth.CapabilityPayload{
				ID:        "cap_1",
				Scopes:    []string{"rwc:*"},
				IssuedAt:  refTime.Format(time.RFC3339),
				ExpiresAt: refTime.Add(time.Hour).Format(time.RFC3339),
				NotBefore: "bad-time",
			},
			wantErr: auth.ErrInvalidToken,
		},
		{
			name: "not-before-after-expires",
			payload: auth.CapabilityPayload{
				ID:        "cap_1",
				Scopes:    []string{"rwc:*"},
				IssuedAt:  refTime.Format(time.RFC3339),
				ExpiresAt: refTime.Add(time.Hour).Format(time.RFC3339),
				NotBefore: refTime.Add(2 * time.Hour).Format(time.RFC3339),
			},
			wantErr: auth.ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := auth.SignCapability(priv, &tt.payload)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tt.name)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("expected error %v for %s, got %v", tt.wantErr, tt.name, err)
			}
			if strings.Contains(err.Error(), "\n") {
				t.Errorf("refusal for %s contains newline: %q", tt.name, err.Error())
			}
		})
	}
}

func TestParseAndVerifyCapabilityEdgeCases(t *testing.T) {
	priv, pub, _ := journal.GenerateKeypair()
	refTime := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	// 1. Bad public key size
	_, _, err := auth.ParseAndVerifyCapability("v1.a.b", []byte{1, 2, 3}, refTime)
	if err == nil || !errors.Is(err, auth.ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature for invalid pubkey length, got %v", err)
	}

	// 2. Empty token string
	_, _, err = auth.ParseAndVerifyCapability("   ", pub, refTime)
	if err == nil || !errors.Is(err, auth.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized for empty token, got %v", err)
	}

	// 3. Unrecognized token format
	_, _, err = auth.ParseAndVerifyCapability("unrecognized_token", pub, refTime)
	if err == nil || !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for unrecognized format, got %v", err)
	}

	// 4. Malformed compact token parts count
	_, _, err = auth.ParseAndVerifyCapability("v1.payload", pub, refTime)
	if err == nil || !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for bad compact parts, got %v", err)
	}

	// 5. Invalid base64url payload
	_, _, err = auth.ParseAndVerifyCapability("v1.invalid*b64.sig", pub, refTime)
	if err == nil || !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for invalid base64url payload, got %v", err)
	}

	// 6. Bad payload JSON
	badPayloadB64 := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	_, _, err = auth.ParseAndVerifyCapability(fmt.Sprintf("v1.%s.sig", badPayloadB64), pub, refTime)
	if err == nil || !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for invalid payload JSON, got %v", err)
	}

	// 7. Unsupported version
	payload := auth.CapabilityPayload{
		Version:   "v2",
		ID:        "cap_v2",
		Scopes:    []string{"rwc:*"},
		IssuedAt:  refTime.Format(time.RFC3339),
		ExpiresAt: refTime.Add(time.Hour).Format(time.RFC3339),
	}
	payloadBytes, _ := json.Marshal(payload)
	canonical := auth.CanonicalCapabilityPayload(&payload)
	sig := ed25519.Sign(priv, canonical)
	tok := fmt.Sprintf("v1.%s.%s", base64.RawURLEncoding.EncodeToString(payloadBytes), base64.RawURLEncoding.EncodeToString(sig))
	_, _, err = auth.ParseAndVerifyCapability(tok, pub, refTime)
	if err == nil || !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for unsupported version, got %v", err)
	}
}

func TestParseAndVerifyCapabilityEncodingVariants(t *testing.T) {
	priv, pub, _ := journal.GenerateKeypair()
	refTime := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	payload := auth.CapabilityPayload{
		Version:   "v1",
		ID:        "cap_enc_var",
		Scopes:    []string{"rw:blog-*"},
		IssuedAt:  refTime.Format(time.RFC3339),
		ExpiresAt: refTime.Add(time.Hour).Format(time.RFC3339),
	}
	payloadBytes, _ := json.Marshal(payload)
	canonical := auth.CanonicalCapabilityPayload(&payload)
	sigBytes := ed25519.Sign(priv, canonical)

	// 1. Padded base64url payload and signature
	payloadPadded := base64.URLEncoding.EncodeToString(payloadBytes)
	sigPadded := base64.URLEncoding.EncodeToString(sigBytes)
	tokenPadded := fmt.Sprintf("v1.%s.%s", payloadPadded, sigPadded)

	parsed, scopes, err := auth.ParseAndVerifyCapability(tokenPadded, pub, refTime.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("ParseAndVerifyCapability failed with padded base64url: %v", err)
	}
	if parsed.ID != "cap_enc_var" || len(scopes) != 1 {
		t.Errorf("unexpected parsed payload: %+v, scopes: %v", parsed, scopes)
	}

	// 2. Raw 128-hex signature (without ed25519: prefix)
	sigRawHex := journal.FormatSignature(sigBytes)[len("ed25519:"):]
	tokenRawHex := fmt.Sprintf("v1.%s.%s", base64.RawURLEncoding.EncodeToString(payloadBytes), sigRawHex)

	parsed, scopes, err = auth.ParseAndVerifyCapability(tokenRawHex, pub, refTime.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("ParseAndVerifyCapability failed with raw hex signature: %v", err)
	}
	if parsed.ID != "cap_enc_var" || len(scopes) != 1 {
		t.Errorf("unexpected parsed payload: %+v, scopes: %v", parsed, scopes)
	}
}

func TestDelegatedNilGuards(t *testing.T) {
	// 1. CanonicalCapabilityPayload with nil
	if b := auth.CanonicalCapabilityPayload(nil); b != nil {
		t.Errorf("CanonicalCapabilityPayload(nil) expected nil, got %v", b)
	}

	// 2. SignCapability with nil payload
	priv, _, _ := journal.GenerateKeypair()
	_, err := auth.SignCapability(priv, nil)
	if err == nil || !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("SignCapability(priv, nil) expected ErrInvalidToken, got %v", err)
	}

	// 3. SignCapability with bad private key length
	_, err = auth.SignCapability([]byte{1, 2, 3}, &auth.CapabilityPayload{ID: "c1", Scopes: []string{"rwc:*"}})
	if err == nil || !errors.Is(err, auth.ErrInvalidSignature) {
		t.Errorf("SignCapability(badPriv, ...) expected ErrInvalidSignature, got %v", err)
	}

	// 4. DelegatedAuthorizer with nil / empty key
	nilAuth := auth.NewDelegatedAuthorizer(nil)
	ok, err := nilAuth.Authorize(context.Background(), "v1.a.b", auth.ActionRead, "repo-alpha")
	if ok || !errors.Is(err, auth.ErrUnauthorized) {
		t.Errorf("expected unauthorized for nil DelegatedAuthorizer, got ok=%v, err=%v", ok, err)
	}
}
