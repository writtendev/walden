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

	// ErrTokenExists marks a TokenStore.CreateToken refusal: a record already exists with the
	// given TokenID or TokenHash. CreateToken never overwrites, so a create is always a
	// create -- never an upsert a caller must infer from success alone.
	ErrTokenExists = errors.New("token already exists")
	// ErrTokenNotFound marks a TokenStore refusal (RevokeToken, GetTokenByID) naming a token
	// ID no record carries.
	ErrTokenNotFound = errors.New("token not found")
	// ErrTokenAlreadyRevoked marks a TokenStore.RevokeToken refusal: the named token is
	// already revoked. Per PHILOSOPHY.md's "detect it, say so plainly, and stop", a second
	// revoke refuses rather than succeeding as a no-op -- a silent no-op would tell an
	// operator their action had an effect it did not have. A caller that wants
	// retry-friendly behavior matches this sentinel with errors.Is and treats it as
	// already-satisfied; that is the caller's decision to make, not the store's to make for
	// it.
	ErrTokenAlreadyRevoked = errors.New("token already revoked")
	// ErrStoreUnavailable marks an operator-fault TokenStore refusal: the token file could
	// not be read or written, or exists but is not valid JSON in the expected shape. A
	// corrupt or malformed tokens.json is refused loudly under this sentinel rather than
	// silently treated as an empty table, which would invalidate every token without saying
	// so.
	ErrStoreUnavailable = errors.New("token store unavailable")
)

// Authorizer is walden's single authorization decision point: may this token perform this
// set of actions on this repository? Both auth modes implement it, and every caller asks
// the whole question at once — a push that may create a repository requests
// Actions{Write: true, Create: true} in one call, rather than composing two answers itself
// and re-implementing spec/auth/v1 §3.4's rule outside this package.
type Authorizer interface {
	// Authorize reports whether token grants every action in required on repo. nil means
	// yes; any non-nil error is a single-line refusal carrying one of this package's Err
	// sentinels (suitable for errors.Is). required must not be empty — that is a caller
	// mistake, not something any scope could grant, and is refused rather than guessed at.
	Authorize(ctx context.Context, token string, required Actions, repo string) error
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

// checkRequired refuses an empty required action set. Both Authorize implementations call
// this before resolving a token: asking to authorize nothing is a caller's programming
// error, not a question any scope could answer yes to, so it is refused rather than treated
// as a trivially granted request.
func checkRequired(required Actions) error {
	if required.IsEmpty() {
		return refusal.RefuseWithCause(
			"invalid scope",
			"required action set is empty",
			"pass at least one of Actions{Read: true}, {Write: true}, {Create: true}",
			ErrInvalidScope,
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
