// Package githttp implements git's smart HTTP protocol endpoints.
package githttp

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// MinGitVersion defines the minimum supported git binary version floor (2.40.0).
const MinGitVersion = "2.40.0"

// ErrGitNotFound indicates that the git executable is not available in PATH.
var ErrGitNotFound = errors.New("git binary not found")

// DetectGitVersion executes `git version` using the default PATH and returns the parsed version string.
func DetectGitVersion(ctx context.Context) (string, error) {
	return DetectGitVersionPath(ctx, "git")
}

// DetectGitVersionPath executes the git binary at the specified path and returns the parsed version string.
func DetectGitVersionPath(ctx context.Context, gitPath string) (string, error) {
	path, err := exec.LookPath(gitPath)
	if err != nil {
		return "", fmt.Errorf("%w: %s not found in PATH", ErrGitNotFound, gitPath)
	}

	cmd := exec.CommandContext(ctx, path, "version")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to execute %s: %w", path, err)
	}

	return ParseGitVersionOutput(string(out))
}

// ParseGitVersionOutput extracts the semantic version substring from `git version` command output.
// Example outputs handled:
// - "git version 2.47.2"
// - "git version 2.50.1 (Apple Git-155)"
// - "git version 2.40.0.windows.1"
// - "git version 2.40.0-rc1"
func ParseGitVersionOutput(output string) (string, error) {
	trimmed := strings.TrimSpace(output)
	if !strings.HasPrefix(trimmed, "git version") {
		return "", fmt.Errorf("unexpected git version output format: %q", trimmed)
	}

	raw := strings.TrimSpace(strings.TrimPrefix(trimmed, "git version"))
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return "", fmt.Errorf("empty version string in git output: %q", trimmed)
	}

	verStr := fields[0]

	// Normalize version components: extract numeric parts separated by dots/hyphens
	parts := strings.Split(verStr, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid git version format: %q", verStr)
	}

	// Validate leading major and minor numbers
	if _, err := strconv.Atoi(parts[0]); err != nil {
		return "", fmt.Errorf("invalid major version in %q: %w", verStr, err)
	}
	if _, err := strconv.Atoi(parts[1]); err != nil {
		return "", fmt.Errorf("invalid minor version in %q: %w", verStr, err)
	}

	return verStr, nil
}

// CompareVersions compares two semantic version strings (e.g. "2.47.2" vs "2.40.0").
// Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2.
func CompareVersions(v1, v2 string) (int, error) {
	parse := func(v string) ([]int, error) {
		// Strip any build/metadata suffixes after '-' or extra '.'
		clean := strings.TrimSpace(v)
		if idx := strings.Index(clean, "-"); idx != -1 {
			clean = clean[:idx]
		}
		parts := strings.Split(clean, ".")
		nums := make([]int, 0, len(parts))
		for _, p := range parts {
			// Extract leading integer
			numStr := ""
			for _, r := range p {
				if r >= '0' && r <= '9' {
					numStr += string(r)
				} else {
					break
				}
			}
			if numStr == "" {
				break
			}
			n, err := strconv.Atoi(numStr)
			if err != nil {
				return nil, fmt.Errorf("invalid version component %q in %q: %w", p, v, err)
			}
			nums = append(nums, n)
		}
		if len(nums) == 0 {
			return nil, fmt.Errorf("invalid version string: %q", v)
		}
		// Ensure at least 3 components (major, minor, patch)
		for len(nums) < 3 {
			nums = append(nums, 0)
		}
		return nums, nil
	}

	p1, err := parse(v1)
	if err != nil {
		return 0, err
	}
	p2, err := parse(v2)
	if err != nil {
		return 0, err
	}

	maxLen := len(p1)
	if len(p2) > maxLen {
		maxLen = len(p2)
	}

	for i := 0; i < maxLen; i++ {
		n1, n2 := 0, 0
		if i < len(p1) {
			n1 = p1[i]
		}
		if i < len(p2) {
			n2 = p2[i]
		}
		if n1 < n2 {
			return -1, nil
		}
		if n1 > n2 {
			return 1, nil
		}
	}

	return 0, nil
}

// AssertGitFloor verifies that the git binary is available in PATH and its version is at or above the floor.
// On failure, it returns a clear, single-line error naming what was refused and what floor is required.
func AssertGitFloor(ctx context.Context, floor string) (string, error) {
	return AssertGitFloorPath(ctx, "git", floor)
}

// AssertGitFloorPath verifies that the git binary at gitPath is at or above the specified floor version.
func AssertGitFloorPath(ctx context.Context, gitPath, floor string) (string, error) {
	ver, err := DetectGitVersionPath(ctx, gitPath)
	if err != nil {
		if errors.Is(err, ErrGitNotFound) {
			return "", fmt.Errorf("git not found in PATH (walden requires git >= %s)", floor)
		}
		return "", fmt.Errorf("git detection failed: %w", err)
	}

	cmp, err := CompareVersions(ver, floor)
	if err != nil {
		return "", fmt.Errorf("failed to parse git version %q: %w", ver, err)
	}

	if cmp < 0 {
		return "", fmt.Errorf("git version %s is below supported floor %s (walden requires git >= %s)", ver, floor, floor)
	}

	return ver, nil
}
