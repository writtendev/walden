package auth_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/auth"
)

func TestValidateRepoValid(t *testing.T) {
	valid := []string{
		"repo-alpha",
		"blog_backend",
		"my.cool.project",
		"r_8f3a2b1c90de",
		"a",
		"12345",
		strings.Repeat("a", 100),
		"repo-1.2_3",
	}

	for _, repo := range valid {
		if err := auth.ValidateRepo(repo); err != nil {
			t.Errorf("expected valid repo %q, got error: %v", repo, err)
		}
	}
}

func TestValidateRepoInvalid(t *testing.T) {
	tests := []struct {
		repo        string
		containsMsg string
	}{
		{"", "identifier cannot be empty"},
		{strings.Repeat("a", 101), "exceeds maximum of 100 characters"},
		{"_meta", "'_meta' is a reserved journal stream name"},
		{"-leading-dash", "identifier cannot start or end with '.' or '-'"},
		{"trailing-dash-", "identifier cannot start or end with '.' or '-'"},
		{".leading-dot", "identifier cannot start or end with '.' or '-'"},
		{"trailing-dot.", "identifier cannot start or end with '.' or '-'"},
		{"repo/sub", "slashes are not allowed"},
		{"repo\\sub", "slashes are not allowed"},
		{"repo..name", "path traversal '..' is not allowed"},
		{"repo name", "whitespace and control characters are not allowed"},
		{"repo:name", "contains invalid character ':'"},
		{"repo@name", "contains invalid character '@'"},
		{"repo\nname", "whitespace and control characters are not allowed"},
		{"repo\tname", "whitespace and control characters are not allowed"},
	}

	for _, tc := range tests {
		err := auth.ValidateRepo(tc.repo)
		if err == nil {
			t.Errorf("expected error for repo %q, got nil", tc.repo)
			continue
		}
		if !errors.Is(err, auth.ErrInvalidRepo) {
			t.Errorf("expected ErrInvalidRepo for %q, got %v", tc.repo, err)
		}
		if !strings.Contains(err.Error(), tc.containsMsg) {
			t.Errorf("expected error for %q to contain %q, got %q", tc.repo, tc.containsMsg, err.Error())
		}
		// Refusal single-line requirement: check no embedded newlines
		if strings.Contains(err.Error(), "\n") {
			t.Errorf("refusal for %q contains newline: %q", tc.repo, err.Error())
		}
	}
}
