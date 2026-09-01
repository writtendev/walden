package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
)

// CapabilityPayload represents the claims of a delegated authorization capability.
type CapabilityPayload struct {
	Version   string   `json:"version"`
	ID        string   `json:"id"`
	Issuer    string   `json:"issuer,omitempty"`
	Subject   string   `json:"subject,omitempty"`
	Scopes    []string `json:"scopes"`
	IssuedAt  string   `json:"issued_at"`
	ExpiresAt string   `json:"expires_at"`
	NotBefore string   `json:"not_before,omitempty"`
}

// CapabilityEnvelope represents a structured JSON envelope for a capability token.
type CapabilityEnvelope struct {
	Version   string            `json:"version"`
	Payload   CapabilityPayload `json:"payload"`
	Signature string            `json:"signature"`
}

// CanonicalCapabilityPayload produces the deterministic byte sequence for Ed25519 signing and verification.
func CanonicalCapabilityPayload(p *CapabilityPayload) []byte {
	if p == nil {
		return nil
	}
	var sb strings.Builder
	sb.WriteString("walden-auth-capability:v1\n")
	sb.WriteString(fmt.Sprintf("id:%s\n", p.ID))
	if p.Issuer != "" {
		sb.WriteString(fmt.Sprintf("issuer:%s\n", p.Issuer))
	}
	if p.Subject != "" {
		sb.WriteString(fmt.Sprintf("subject:%s\n", p.Subject))
	}
	for _, sc := range p.Scopes {
		sb.WriteString(fmt.Sprintf("scope:%s\n", sc))
	}
	sb.WriteString(fmt.Sprintf("issued_at:%s\n", p.IssuedAt))
	sb.WriteString(fmt.Sprintf("expires_at:%s\n", p.ExpiresAt))
	if p.NotBefore != "" {
		sb.WriteString(fmt.Sprintf("not_before:%s\n", p.NotBefore))
	}
	return []byte(sb.String())
}

// SignCapability signs a capability payload with an Ed25519 private key and returns a compact token string.
func SignCapability(priv ed25519.PrivateKey, p *CapabilityPayload) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", refusal.RefuseWithCause(
			"invalid signature",
			"invalid private key size for capability signing",
			"provide a valid 64-byte Ed25519 private key",
			ErrInvalidSignature,
		)
	}
	if p == nil {
		return "", refusal.RefuseWithCause(
			"invalid capability",
			"capability payload cannot be nil",
			"provide a valid capability payload",
			ErrInvalidToken,
		)
	}
	if p.Version == "" {
		p.Version = "v1"
	}
	if p.ID == "" {
		return "", refusal.RefuseWithCause(
			"invalid capability",
			"capability ID cannot be empty",
			"provide a unique capability ID",
			ErrInvalidToken,
		)
	}
	if len(p.Scopes) == 0 {
		return "", refusal.RefuseWithCause(
			"invalid capability",
			"capability must contain at least one scope",
			"specify scopes (e.g. ['rwc:*'])",
			ErrInvalidScope,
		)
	}
	if _, err := ParseScopes(p.Scopes); err != nil {
		return "", err
	}
	if p.IssuedAt == "" {
		return "", refusal.RefuseWithCause(
			"invalid capability",
			"missing 'issued_at' timestamp",
			"delegated capabilities must specify an issuance timestamp",
			ErrInvalidToken,
		)
	}
	if _, err := time.Parse(time.RFC3339, p.IssuedAt); err != nil {
		return "", refusal.RefuseWithCause(
			"invalid capability",
			fmt.Sprintf("invalid 'issued_at' timestamp format %q", p.IssuedAt),
			"use RFC 3339 UTC format (e.g. 2026-09-01T12:00:00Z)",
			ErrInvalidToken,
		)
	}
	if p.ExpiresAt == "" {
		return "", refusal.RefuseWithCause(
			"invalid capability",
			"missing 'expires_at' timestamp",
			"delegated capabilities must specify a finite expiration time",
			ErrInvalidToken,
		)
	}
	expTime, err := time.Parse(time.RFC3339, p.ExpiresAt)
	if err != nil {
		return "", refusal.RefuseWithCause(
			"invalid capability",
			fmt.Sprintf("invalid 'expires_at' timestamp format %q", p.ExpiresAt),
			"use RFC 3339 UTC format (e.g. 2026-09-01T13:00:00Z)",
			ErrInvalidToken,
		)
	}
	if p.NotBefore != "" {
		nbTime, err := time.Parse(time.RFC3339, p.NotBefore)
		if err != nil {
			return "", refusal.RefuseWithCause(
				"invalid capability",
				fmt.Sprintf("invalid 'not_before' timestamp format %q", p.NotBefore),
				"use RFC 3339 UTC format (e.g. 2026-09-01T12:00:00Z)",
				ErrInvalidToken,
			)
		}
		if !nbTime.Before(expTime) {
			return "", refusal.RefuseWithCause(
				"invalid capability",
				"'not_before' timestamp must be earlier than 'expires_at'",
				"ensure token activation occurs before expiration",
				ErrInvalidToken,
			)
		}
	}

	payloadJSON, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("failed to marshal capability payload: %w", err)
	}

	canonicalBytes := CanonicalCapabilityPayload(p)
	sigBytes := ed25519.Sign(priv, canonicalBytes)

	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	sigB64 := base64.RawURLEncoding.EncodeToString(sigBytes)

	return fmt.Sprintf("v1.%s.%s", payloadB64, sigB64), nil
}

// ParseAndVerifyCapability parses and cryptographically verifies a capability token against pubKey at time now.
func ParseAndVerifyCapability(tokenStr string, pubKey ed25519.PublicKey, now time.Time) (*CapabilityPayload, []Scope, error) {
	tokenStr = strings.TrimSpace(tokenStr)
	if tokenStr == "" {
		return nil, nil, refusal.RefuseWithCause(
			"unauthorized",
			"missing authentication token",
			"provide token via Bearer header or HTTP Basic auth",
			ErrUnauthorized,
		)
	}

	if len(pubKey) != ed25519.PublicKeySize {
		return nil, nil, refusal.RefuseWithCause(
			"invalid signature",
			"invalid public key size for capability verification",
			"ensure WALDEN_AUTH_TRUST is a valid 32-byte Ed25519 public key",
			ErrInvalidSignature,
		)
	}

	var payload CapabilityPayload
	var sigBytes []byte

	if strings.HasPrefix(tokenStr, "v1.") {
		parts := strings.Split(tokenStr, ".")
		if len(parts) != 3 {
			return nil, nil, refusal.RefuseWithCause(
				"invalid capability",
				"malformed compact token structure",
				"expected format 'v1.<payload_base64url>.<signature_base64url>'",
				ErrInvalidToken,
			)
		}

		decodedPayload, err := decodeBase64URL(parts[1])
		if err != nil {
			return nil, nil, refusal.RefuseWithCause(
				"invalid capability",
				"invalid base64url payload encoding",
				"provide a valid v1 capability token",
				ErrInvalidToken,
			)
		}
		if err := json.Unmarshal(decodedPayload, &payload); err != nil {
			return nil, nil, refusal.RefuseWithCause(
				"invalid capability",
				"failed to parse capability payload JSON",
				"provide a valid v1 JSON capability payload",
				ErrInvalidToken,
			)
		}

		sig, err := decodeSignatureBytes(parts[2])
		if err != nil {
			return nil, nil, refusal.RefuseWithCause(
				"invalid capability",
				"invalid signature encoding in compact token",
				"provide a valid v1 capability token",
				ErrInvalidSignature,
			)
		}
		sigBytes = sig
	} else if strings.HasPrefix(tokenStr, "{") {
		// Structured JSON envelope
		var env CapabilityEnvelope
		if err := json.Unmarshal([]byte(tokenStr), &env); err != nil {
			return nil, nil, refusal.RefuseWithCause(
				"invalid capability",
				"invalid JSON envelope",
				"provide a valid JSON capability envelope",
				ErrInvalidToken,
			)
		}
		payload = env.Payload
		if payload.Version == "" && env.Version != "" {
			payload.Version = env.Version
		}

		sig, err := decodeSignatureBytes(env.Signature)
		if err != nil {
			return nil, nil, refusal.RefuseWithCause(
				"invalid capability",
				"invalid signature in JSON envelope",
				"signature must be ed25519:<128-hex> or base64url encoded",
				ErrInvalidSignature,
			)
		}
		sigBytes = sig
	} else {
		return nil, nil, refusal.RefuseWithCause(
			"invalid capability",
			"unrecognized token format",
			"expected compact format 'v1.<payload>.<sig>' or JSON envelope",
			ErrInvalidToken,
		)
	}

	if len(sigBytes) != ed25519.SignatureSize {
		return nil, nil, refusal.RefuseWithCause(
			"invalid capability",
			fmt.Sprintf("signature length %d does not match expected Ed25519 size %d", len(sigBytes), ed25519.SignatureSize),
			"provide a valid Ed25519 signature",
			ErrInvalidSignature,
		)
	}

	if payload.Version != "v1" {
		return nil, nil, refusal.RefuseWithCause(
			"invalid capability",
			fmt.Sprintf("unsupported format version %q", payload.Version),
			"walden currently supports version 'v1'",
			ErrInvalidToken,
		)
	}

	if payload.ID == "" {
		return nil, nil, refusal.RefuseWithCause(
			"invalid capability",
			"missing capability ID",
			"capability payload must specify 'id'",
			ErrInvalidToken,
		)
	}

	if len(payload.Scopes) == 0 {
		return nil, nil, refusal.RefuseWithCause(
			"invalid capability",
			"capability contains no scopes",
			"capability payload must contain at least one scope",
			ErrInvalidScope,
		)
	}

	canonicalBytes := CanonicalCapabilityPayload(&payload)
	if !ed25519.Verify(pubKey, canonicalBytes, sigBytes) {
		return nil, nil, refusal.RefuseWithCause(
			"invalid signature",
			"capability signature verification failed",
			"verify token was signed with the trusted WALDEN_AUTH_TRUST key",
			ErrInvalidSignature,
		)
	}

	if payload.IssuedAt == "" {
		return nil, nil, refusal.RefuseWithCause(
			"invalid capability",
			"missing 'issued_at' timestamp",
			"delegated capabilities must specify an issuance timestamp",
			ErrInvalidToken,
		)
	}

	if _, err := time.Parse(time.RFC3339, payload.IssuedAt); err != nil {
		return nil, nil, refusal.RefuseWithCause(
			"invalid capability",
			fmt.Sprintf("invalid 'issued_at' timestamp format %q", payload.IssuedAt),
			"use RFC 3339 UTC format (e.g. 2026-09-01T12:00:00Z)",
			ErrInvalidToken,
		)
	}

	if payload.ExpiresAt == "" {
		return nil, nil, refusal.RefuseWithCause(
			"invalid capability",
			"missing 'expires_at' timestamp",
			"delegated capabilities must specify a finite expiration time",
			ErrInvalidToken,
		)
	}

	expTime, err := time.Parse(time.RFC3339, payload.ExpiresAt)
	if err != nil {
		return nil, nil, refusal.RefuseWithCause(
			"invalid capability",
			fmt.Sprintf("invalid 'expires_at' timestamp format %q", payload.ExpiresAt),
			"use RFC 3339 UTC format (e.g. 2026-09-01T13:00:00Z)",
			ErrInvalidToken,
		)
	}

	utcNow := now.UTC()

	if payload.NotBefore != "" {
		nbTime, err := time.Parse(time.RFC3339, payload.NotBefore)
		if err != nil {
			return nil, nil, refusal.RefuseWithCause(
				"invalid capability",
				fmt.Sprintf("invalid 'not_before' timestamp format %q", payload.NotBefore),
				"use RFC 3339 UTC format (e.g. 2026-09-01T12:00:00Z)",
				ErrInvalidToken,
			)
		}
		if !nbTime.Before(expTime) {
			return nil, nil, refusal.RefuseWithCause(
				"invalid capability",
				"'not_before' timestamp must be earlier than 'expires_at'",
				"ensure token activation occurs before expiration",
				ErrInvalidToken,
			)
		}
		if utcNow.Before(nbTime.UTC()) {
			return nil, nil, refusal.RefuseWithCause(
				"capability not yet valid",
				fmt.Sprintf("token is not valid until %s (current time %s)", payload.NotBefore, utcNow.Format(time.RFC3339)),
				"wait until token activation time",
				ErrNotYetValid,
			)
		}
	}

	if !utcNow.Before(expTime.UTC()) {
		return nil, nil, refusal.RefuseWithCause(
			"capability expired",
			fmt.Sprintf("token expired at %s (current time %s)", payload.ExpiresAt, utcNow.Format(time.RFC3339)),
			"request a fresh token from the issuer",
			ErrExpired,
		)
	}

	scopes, err := ParseScopes(payload.Scopes)
	if err != nil {
		return nil, nil, err
	}

	return &payload, scopes, nil
}

// DelegatedAuthorizer evaluates access requests using signed Ed25519 capability tokens.
type DelegatedAuthorizer struct {
	pubKey  ed25519.PublicKey
	nowFunc func() time.Time
}

// NewDelegatedAuthorizer creates a DelegatedAuthorizer using system time.
func NewDelegatedAuthorizer(pubKey ed25519.PublicKey) *DelegatedAuthorizer {
	return NewDelegatedAuthorizerWithClock(pubKey, time.Now)
}

// NewDelegatedAuthorizerWithClock creates a DelegatedAuthorizer using a custom clock provider.
func NewDelegatedAuthorizerWithClock(pubKey ed25519.PublicKey, nowFunc func() time.Time) *DelegatedAuthorizer {
	if nowFunc == nil {
		nowFunc = time.Now
	}
	return &DelegatedAuthorizer{
		pubKey:  pubKey,
		nowFunc: nowFunc,
	}
}

// decodeBase64URL decodes a base64url string, accepting either unpadded (standard) or padded representations.
func decodeBase64URL(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// decodeSignatureBytes parses an Ed25519 signature from hex ("ed25519:<128-hex>" or 128 raw hex) or base64url.
func decodeSignatureBytes(sigStr string) ([]byte, error) {
	sigStr = strings.TrimSpace(sigStr)
	if strings.HasPrefix(sigStr, journal.SignaturePrefix) {
		return journal.ParseSignature(sigStr)
	}
	if len(sigStr) == 128 {
		b, err := hex.DecodeString(sigStr)
		if err == nil && len(b) == ed25519.SignatureSize {
			return b, nil
		}
	}
	if b, err := base64.RawURLEncoding.DecodeString(sigStr); err == nil && len(b) == ed25519.SignatureSize {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(sigStr); err == nil && len(b) == ed25519.SignatureSize {
		return b, nil
	}
	return nil, errors.New("invalid signature encoding")
}

// Authorize validates the capability token against the trusted public key and checks permissions.
func (d *DelegatedAuthorizer) Authorize(ctx context.Context, token string, action Action, repo string) (bool, error) {
	if d == nil || len(d.pubKey) == 0 {
		return false, refusal.RefuseWithCause(
			"unauthorized",
			"delegated capability auth is not enabled on this server",
			"configure WALDEN_AUTH_TRUST or use a built-in token",
			ErrUnauthorized,
		)
	}

	if err := CheckRepoAndToken(token, repo); err != nil {
		return false, err
	}

	_, scopes, err := ParseAndVerifyCapability(token, d.pubKey, d.nowFunc())
	if err != nil {
		return false, err
	}

	if !Allows(scopes, action, repo) {
		return false, ForbiddenRefusal(action, repo)
	}

	return true, nil
}
