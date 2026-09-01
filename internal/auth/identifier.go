package auth

import (
	"fmt"
	"strings"

	"github.com/writtendev/walden/internal/refusal"
)

// MaxRepoIDLength is the maximum allowed length of a repository identifier.
const MaxRepoIDLength = 100

// ReservedMetaRepo is the reserved journal stream name for server metadata.
const ReservedMetaRepo = "_meta"

// ValidateRepo validates that a repository identifier satisfies Walden format v1 rules.
// Flat namespace, caller-chosen string, allowed characters [a-zA-Z0-9._-], length 1..100,
// no leading/trailing dots or dashes, no path traversal ('..'), and no slashes.
func ValidateRepo(repo string) error {
	if repo == "" {
		return refusal.RefuseWithCause(
			"invalid repository identifier",
			"identifier cannot be empty",
			"provide a valid repository identifier matching [a-zA-Z0-9._-]",
			ErrInvalidRepo,
		)
	}

	if len(repo) > MaxRepoIDLength {
		return refusal.RefuseWithCause(
			"invalid repository identifier",
			fmt.Sprintf("length %d exceeds maximum of %d characters", len(repo), MaxRepoIDLength),
			fmt.Sprintf("use a repository identifier between 1 and %d characters", MaxRepoIDLength),
			ErrInvalidRepo,
		)
	}

	if repo == ReservedMetaRepo {
		return refusal.RefuseWithCause(
			"invalid repository identifier",
			"'_meta' is a reserved journal stream name",
			"choose a different repository identifier",
			ErrInvalidRepo,
		)
	}

	if strings.Contains(repo, "/") || strings.Contains(repo, "\\") {
		return refusal.RefuseWithCause(
			"invalid repository identifier",
			"slashes are not allowed",
			"walden repositories use a flat namespace without hierarchy",
			ErrInvalidRepo,
		)
	}

	if strings.Contains(repo, "..") {
		return refusal.RefuseWithCause(
			"invalid repository identifier",
			"path traversal '..' is not allowed",
			"walden repositories use a flat namespace without directory traversal",
			ErrInvalidRepo,
		)
	}

	first := repo[0]
	last := repo[len(repo)-1]
	if first == '.' || first == '-' || last == '.' || last == '-' {
		return refusal.RefuseWithCause(
			"invalid repository identifier",
			"identifier cannot start or end with '.' or '-'",
			"ensure repository identifier starts and ends with [a-zA-Z0-9_]",
			ErrInvalidRepo,
		)
	}

	for i := 0; i < len(repo); i++ {
		c := repo[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-' {
			continue
		}
		if c <= 0x20 || c == 0x7F {
			return refusal.RefuseWithCause(
				"invalid repository identifier",
				"whitespace and control characters are not allowed",
				"allowed characters are [a-zA-Z0-9._-]",
				ErrInvalidRepo,
			)
		}
		return refusal.RefuseWithCause(
			"invalid repository identifier",
			fmt.Sprintf("contains invalid character '%c'", c),
			"allowed characters are [a-zA-Z0-9._-]",
			ErrInvalidRepo,
		)
	}

	return nil
}
