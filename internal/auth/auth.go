// Package auth defines walden's authorization and token validation primitives.
// Per ARCHITECTURE.md: "may this token read, write, or create this repo?"
package auth

import (
	"context"
	"errors"
)

// Action represents an authorized operation against a repository.
type Action string

const (
	ActionRead   Action = "r"
	ActionWrite  Action = "w"
	ActionCreate Action = "c"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
)

// Authorizer determines if a token is authorized to perform an action on a repository.
type Authorizer interface {
	// Authorize checks whether the given token permits the action on the repository.
	Authorize(ctx context.Context, token string, action Action, repo string) (bool, error)
}
