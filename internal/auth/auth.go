// Package auth defines walden's authorization and token validation primitives.
// Per ARCHITECTURE.md: "may this token read, write, or create this repo?"
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
)

var (
	ErrUnauthorized     = errors.New("unauthorized")
	ErrForbidden        = errors.New("forbidden")
	ErrInvalidRepo      = errors.New("invalid repository identifier")
	ErrInvalidScope     = errors.New("invalid scope")
	ErrInvalidToken     = errors.New("invalid token")
	ErrExpired          = errors.New("capability expired")
	ErrNotYetValid      = errors.New("capability not yet valid")
	ErrInvalidSignature = errors.New("invalid signature")
)

// Authorizer determines if a token is authorized to perform an action on a repository.
type Authorizer interface {
	// Authorize checks whether the given token permits the action on the repository.
	Authorize(ctx context.Context, token string, action Action, repo string) (bool, error)
}

// NewAuthorizer creates the single Authorizer for this server's configuration.
//
// The two modes are mutually exclusive, per ARCHITECTURE.md's auth section: a
// non-empty trustKey selects delegated capability verification against that
// Ed25519 public key, an empty one selects built-in tokens against store, and
// the mode not selected is never consulted. In particular a capability token
// that fails to verify does not fall back to the built-in store. A server that
// could answer yes from either source would be a third mode wearing the other
// two as a disguise, and would double the surface on which an authorization
// mistake is worst.
//
// store is still accepted under a trust key, and is deliberately not dropped
// from the signature there: exclusivity governs who can grant, not who can
// revoke, so `walden token list` and `walden token revoke` keep working in
// delegated mode. It is simply never wired to the returned Authorizer.
//
// TestExclusiveModes pins the behaviour rather than the branch.
func NewAuthorizer(trustKey string, store TokenStore) (Authorizer, error) {
	if strings.TrimSpace(trustKey) != "" {
		pubKey, err := journal.ParsePublicKey(trustKey)
		if err != nil {
			return nil, refusal.RefuseWithCause(
				"invalid auth-trust configuration",
				err.Error(),
				"provide a valid Ed25519 public key formatted as ed25519:<64-hex>",
				err,
			)
		}
		return NewDelegatedAuthorizer(pubKey), nil
	}
	if store == nil {
		store = NewMemoryTokenStore()
	}
	return NewBuiltinAuthorizer(store), nil
}

// CheckRepoAndToken is a shared helper to validate repo identifier and ensure token is present.
func CheckRepoAndToken(token, repo string) error {
	if err := ValidateRepo(repo); err != nil {
		return err
	}
	if strings.TrimSpace(token) == "" {
		return refusal.RefuseWithCause(
			"unauthorized",
			"missing authentication token",
			"provide token via Bearer header or HTTP Basic auth",
			ErrUnauthorized,
		)
	}
	return nil
}

// ForbiddenRefusal creates a single-line refusal when a token lacks sufficient scope.
func ForbiddenRefusal(action Action, repo string) error {
	return refusal.RefuseWithCause(
		"forbidden",
		fmt.Sprintf("token does not grant action %q on repository %q", action, repo),
		fmt.Sprintf("request scope '%s:%s' from administrator or issuer", action, repo),
		ErrForbidden,
	)
}
