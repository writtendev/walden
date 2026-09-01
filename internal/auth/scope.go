package auth

import (
	"fmt"
	"strings"

	"github.com/writtendev/walden/internal/refusal"
)

// Action represents an authorized operation against a repository.
type Action string

const (
	ActionRead   Action = "r"
	ActionWrite  Action = "w"
	ActionCreate Action = "c"
)

// Actions represents a set of authorized actions (r, w, c).
type Actions struct {
	Read   bool
	Write  bool
	Create bool
}

// NewActions returns an Actions set with the given booleans.
func NewActions(read, write, create bool) Actions {
	return Actions{Read: read, Write: write, Create: create}
}

// Has reports whether the set contains the given action.
func (a Actions) Has(action Action) bool {
	switch action {
	case ActionRead:
		return a.Read
	case ActionWrite:
		return a.Write
	case ActionCreate:
		return a.Create
	default:
		return false
	}
}

// IsEmpty reports whether the action set is empty.
func (a Actions) IsEmpty() bool {
	return !a.Read && !a.Write && !a.Create
}

// String returns the canonical representation of the action set (e.g. "rwc", "rw", "r").
func (a Actions) String() string {
	var sb strings.Builder
	if a.Read {
		sb.WriteByte('r')
	}
	if a.Write {
		sb.WriteByte('w')
	}
	if a.Create {
		sb.WriteByte('c')
	}
	return sb.String()
}

// ParseActions parses an action string containing a permutation of 'r', 'w', 'c'.
func ParseActions(s string) (Actions, error) {
	if s == "" {
		return Actions{}, refusal.RefuseWithCause(
			"invalid scope",
			"actions component cannot be empty",
			"specify one or more actions from [r, w, c] (e.g. 'rw', 'rwc')",
			ErrInvalidScope,
		)
	}

	var a Actions
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case 'r':
			if a.Read {
				return Actions{}, refusal.RefuseWithCause(
					"invalid scope",
					"duplicate action 'r'",
					"each action [r, w, c] may appear at most once in a scope",
					ErrInvalidScope,
				)
			}
			a.Read = true
		case 'w':
			if a.Write {
				return Actions{}, refusal.RefuseWithCause(
					"invalid scope",
					"duplicate action 'w'",
					"each action [r, w, c] may appear at most once in a scope",
					ErrInvalidScope,
				)
			}
			a.Write = true
		case 'c':
			if a.Create {
				return Actions{}, refusal.RefuseWithCause(
					"invalid scope",
					"duplicate action 'c'",
					"each action [r, w, c] may appear at most once in a scope",
					ErrInvalidScope,
				)
			}
			a.Create = true
		default:
			return Actions{}, refusal.RefuseWithCause(
				"invalid scope",
				fmt.Sprintf("unknown action '%c'", s[i]),
				"allowed actions are 'r' (read), 'w' (write), 'c' (create)",
				ErrInvalidScope,
			)
		}
	}

	if a.IsEmpty() {
		return Actions{}, refusal.RefuseWithCause(
			"invalid scope",
			"actions component cannot be empty",
			"specify one or more actions from [r, w, c]",
			ErrInvalidScope,
		)
	}

	return a, nil
}

// Scope represents an authorization rule granting a set of actions on repositories matching a pattern.
type Scope struct {
	Actions Actions
	Pattern string
}

// String returns the formatted scope string "<actions>:<pattern>".
func (s Scope) String() string {
	return fmt.Sprintf("%s:%s", s.Actions.String(), s.Pattern)
}

// Allows checks whether this scope permits the given action on the specified repository.
func (s Scope) Allows(action Action, repo string) bool {
	if !s.Actions.Has(action) {
		return false
	}
	return MatchGlob(s.Pattern, repo)
}

// ParseScope parses a scope string formatted as "<actions>:<pattern>".
func ParseScope(s string) (Scope, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Scope{}, refusal.RefuseWithCause(
			"invalid scope",
			"scope cannot be empty",
			"use format <actions>:<pattern> with actions from [r,w,c]",
			ErrInvalidScope,
		)
	}

	idx := strings.IndexByte(s, ':')
	if idx == -1 {
		return Scope{}, refusal.RefuseWithCause(
			"invalid scope",
			fmt.Sprintf("missing colon separator in scope %q", s),
			"use format <actions>:<pattern> (e.g. 'rwc:*', 'rw:blog-*')",
			ErrInvalidScope,
		)
	}

	actionsPart := s[:idx]
	patternPart := s[idx+1:]

	actions, err := ParseActions(actionsPart)
	if err != nil {
		return Scope{}, err
	}

	if patternPart == "" {
		return Scope{}, refusal.RefuseWithCause(
			"invalid scope",
			"pattern component cannot be empty",
			"specify a repository name or glob pattern (e.g. '*', 'blog-*')",
			ErrInvalidScope,
		)
	}

	if err := validateGlobPattern(patternPart); err != nil {
		return Scope{}, err
	}

	return Scope{
		Actions: actions,
		Pattern: patternPart,
	}, nil
}

// validateGlobPattern ensures pattern only contains allowed characters [a-zA-Z0-9._-*].
func validateGlobPattern(pattern string) error {
	if strings.Contains(pattern, "/") || strings.Contains(pattern, "\\") {
		return refusal.RefuseWithCause(
			"invalid scope",
			"slashes are not allowed in glob pattern",
			"walden repositories use a flat namespace without hierarchy",
			ErrInvalidScope,
		)
	}

	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-' || c == '*' {
			continue
		}
		return refusal.RefuseWithCause(
			"invalid scope",
			fmt.Sprintf("pattern contains invalid character '%c'", c),
			"allowed pattern characters are [a-zA-Z0-9._-*]",
			ErrInvalidScope,
		)
	}

	return nil
}

// ParseScopes parses a slice of scope strings into a slice of Scope structures.
func ParseScopes(scopeStrs []string) ([]Scope, error) {
	if len(scopeStrs) == 0 {
		return nil, refusal.RefuseWithCause(
			"invalid scope",
			"scopes list cannot be empty",
			"provide at least one scope (e.g. 'rwc:*')",
			ErrInvalidScope,
		)
	}

	scopes := make([]Scope, 0, len(scopeStrs))
	for _, str := range scopeStrs {
		s, err := ParseScope(str)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, s)
	}
	return scopes, nil
}

// MatchGlob evaluates whether a repo identifier matches a glob pattern.
// Supports universal wildcard "*", exact match, prefix "pre-*", suffix "*-suf", and infix "a-*-b".
func MatchGlob(pattern, repo string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == repo
	}

	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return parts[0] == repo
	}

	// First part must match prefix
	if !strings.HasPrefix(repo, parts[0]) {
		return false
	}
	repo = repo[len(parts[0]):]

	// Last part must match suffix
	last := parts[len(parts)-1]
	if !strings.HasSuffix(repo, last) {
		return false
	}
	repo = repo[:len(repo)-len(last)]

	// Middle parts must appear sequentially
	for i := 1; i < len(parts)-1; i++ {
		part := parts[i]
		if part == "" {
			continue
		}
		idx := strings.Index(repo, part)
		if idx == -1 {
			return false
		}
		repo = repo[idx+len(part):]
	}

	return true
}

// Allows checks if any scope in the slice permits the action on the repository.
func Allows(scopes []Scope, action Action, repo string) bool {
	for _, s := range scopes {
		if s.Allows(action, repo) {
			return true
		}
	}
	return false
}
