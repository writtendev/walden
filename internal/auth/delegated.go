package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
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
	if p.ExpiresAt == "" {
		return "", refusal.RefuseWithCause(
			"invalid capability",
			"missing 'expires_at' timestamp",
			"delegated capabilities must specify a finite expiration time",
			ErrInvalidToken,
		)
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

	var payloadBytes []byte
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

		decodedPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, nil, refusal.RefuseWithCause(
				"invalid capability",
				"invalid base64url payload encoding",
				"provide a valid v1 capability token",
				ErrInvalidToken,
			)
		}
		payloadBytes = decodedPayload

		sigStr := parts[2]
		if strings.HasPrefix(sigStr, journal.SignaturePrefix) {
			parsedSig, err := journal.ParseSignature(sigStr)
			if err != nil {
				return nil, nil, refusal.RefuseWithCause(
					"invalid capability",
					"invalid hex signature format",
					"ensure signature matches ed25519:<128-hex>",
					ErrInvalidSignature,
				)
			}
			sigBytes = parsedSig
		} else {
			decodedSig, err := base64.RawURLEncoding.DecodeString(sigStr)
			if err != nil {
				return nil, nil, refusal.RefuseWithCause(
					"invalid capability",
					"invalid base64url signature encoding",
					"provide a valid v1 capability token",
					ErrInvalidSignature,
				)
			}
			sigBytes = decodedSig
		}
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
		marshaled, err := json.Marshal(env.Payload)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal envelope payload: %w", err)
		}
		payloadBytes = marshaled

		parsedSig, err := journal.ParseSignature(env.Signature)
		if err != nil {
			// Try base64url decoding if hex prefix not present
			decodedSig, b64err := base64.RawURLEncoding.DecodeString(env.Signature)
			if b64err != nil {
				return nil, nil, refusal.RefuseWithCause(
					"invalid capability",
					"invalid signature in JSON envelope",
					"signature must be ed25519:<128-hex> or base64url encoded",
					ErrInvalidSignature,
				)
			}
			sigBytes = decodedSig
		} else {
			sigBytes = parsedSig
		}
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

	var payload CapabilityPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, nil, refusal.RefuseWithCause(
			"invalid capability",
			"failed to parse capability payload JSON",
			"provide a valid v1 JSON capability payload",
			ErrInvalidToken,
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
	if !utcNow.Before(expTime.UTC()) {
		return nil, nil, refusal.RefuseWithCause(
			"capability expired",
			fmt.Sprintf("token expired at %s (current time %s)", payload.ExpiresAt, utcNow.Format(time.RFC3339)),
			"request a fresh token from the issuer",
			ErrExpired,
		)
	}

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
		if utcNow.Before(nbTime.UTC()) {
			return nil, nil, refusal.RefuseWithCause(
				"capability not yet valid",
				fmt.Sprintf("token is not valid until %s (current time %s)", payload.NotBefore, utcNow.Format(time.RFC3339)),
				"wait until token activation time",
				ErrNotYetValid,
			)
		}
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

// Authorize validates the capability token against the trusted public key and checks permissions.
func (d *DelegatedAuthorizer) Authorize(ctx context.Context, token string, action Action, repo string) (bool, error) {
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
