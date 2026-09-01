package auth_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/auth"
)

func TestParseActions(t *testing.T) {
	tests := []struct {
		input     string
		wantRead  bool
		wantWrite bool
		wantCreat bool
		wantCanon string
	}{
		{"r", true, false, false, "r"},
		{"w", false, true, false, "w"},
		{"c", false, false, true, "c"},
		{"rw", true, true, false, "rw"},
		{"wr", true, true, false, "rw"},
		{"rc", true, false, true, "rc"},
		{"cr", true, false, true, "rc"},
		{"wc", false, true, true, "wc"},
		{"cw", false, true, true, "wc"},
		{"rwc", true, true, true, "rwc"},
		{"crw", true, true, true, "rwc"},
		{"wcr", true, true, true, "rwc"},
	}

	for _, tc := range tests {
		actions, err := auth.ParseActions(tc.input)
		if err != nil {
			t.Fatalf("ParseActions(%q) unexpected error: %v", tc.input, err)
		}
		if actions.Read != tc.wantRead || actions.Write != tc.wantWrite || actions.Create != tc.wantCreat {
			t.Errorf("ParseActions(%q) got %+v, want r:%v w:%v c:%v", tc.input, actions, tc.wantRead, tc.wantWrite, tc.wantCreat)
		}
		if canon := actions.String(); canon != tc.wantCanon {
			t.Errorf("actions.String() for %q = %q, want canonical %q", tc.input, canon, tc.wantCanon)
		}
	}
}

func TestParseActionsInvalid(t *testing.T) {
	invalid := []string{
		"",
		"x",
		"rx",
		"r w",
		"r-w",
		"123",
	}

	for _, in := range invalid {
		_, err := auth.ParseActions(in)
		if err == nil {
			t.Errorf("expected ParseActions(%q) to fail, got nil", in)
		}
		if !errors.Is(err, auth.ErrInvalidScope) {
			t.Errorf("expected ErrInvalidScope for %q, got %v", in, err)
		}
	}
}

func TestParseScope(t *testing.T) {
	tests := []struct {
		input       string
		wantPattern string
		wantCanon   string
	}{
		{"rwc:*", "*", "rwc:*"},
		{"rw:blog-*", "blog-*", "rw:blog-*"},
		{"wr:blog-*", "blog-*", "rw:blog-*"},
		{"r:docs", "docs", "r:docs"},
		{"c:sandbox-*", "sandbox-*", "c:sandbox-*"},
		{"wc:*-svc", "*-svc", "wc:*-svc"},
		{"rc:proj-*-test", "proj-*-test", "rc:proj-*-test"},
	}

	for _, tc := range tests {
		s, err := auth.ParseScope(tc.input)
		if err != nil {
			t.Fatalf("ParseScope(%q) unexpected error: %v", tc.input, err)
		}
		if s.Pattern != tc.wantPattern {
			t.Errorf("ParseScope(%q).Pattern = %q, want %q", tc.input, s.Pattern, tc.wantPattern)
		}
		if canon := s.String(); canon != tc.wantCanon {
			t.Errorf("ParseScope(%q).String() = %q, want %q", tc.input, canon, tc.wantCanon)
		}
	}
}

func TestParseScopeInvalid(t *testing.T) {
	invalid := []string{
		"",
		"rwc",
		":*",
		"rw:",
		"rx:*",
		"r w:*",
		"rw:repo/sub",
		"rw:repo\\sub",
		"rw:repo@name",
	}

	for _, in := range invalid {
		_, err := auth.ParseScope(in)
		if err == nil {
			t.Errorf("expected ParseScope(%q) to fail, got nil", in)
		}
		if !errors.Is(err, auth.ErrInvalidScope) {
			t.Errorf("expected ErrInvalidScope for %q, got %v", in, err)
		}
	}
}

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern string
		repo    string
		match   bool
	}{
		// Universal
		{"*", "repo-alpha", true},
		{"*", "any_name.123", true},

		// Exact
		{"repo-alpha", "repo-alpha", true},
		{"repo-alpha", "repo-alphax", false},
		{"repo-alpha", "xrepo-alpha", false},
		{"repo-alpha", "repo-beta", false},

		// Prefix
		{"blog-*", "blog-posts", true},
		{"blog-*", "blog-", true},
		{"blog-*", "blog-backend-v2", true},
		{"blog-*", "my-blog-posts", false},
		{"blog-*", "blog", false},

		// Suffix
		{"*-service", "auth-service", true},
		{"*-service", "-service", true},
		{"*-service", "auth-service-v2", false},
		{"*-service", "service", false},

		// Infix
		{"proj-*-backend", "proj-core-backend", true},
		{"proj-*-backend", "proj--backend", true},
		{"proj-*-backend", "proj-core-backend-api", false},
		{"proj-*-backend", "my-proj-core-backend", false},

		// Multi-wildcard
		{"a-*-b-*-c", "a-1-b-2-c", true},
		{"a-*-b-*-c", "a-b-c", false}, // first * matches "", second * matches "" -> "a--b--c"? wait: "a--b--c" would match, "a-b-c" does not have "-b-"
		{"a-*-b-*-c", "a--b--c", true},
		{"a-*-b-*-c", "a-1-b-2-d", false},
	}

	for _, tc := range tests {
		got := auth.MatchGlob(tc.pattern, tc.repo)
		if got != tc.match {
			t.Errorf("MatchGlob(%q, %q) = %v, want %v", tc.pattern, tc.repo, got, tc.match)
		}
	}
}

func TestScopeAllows(t *testing.T) {
	scope, err := auth.ParseScope("rw:blog-*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !scope.Allows(auth.ActionRead, "blog-posts") {
		t.Errorf("expected rw:blog-* to allow read on blog-posts")
	}
	if !scope.Allows(auth.ActionWrite, "blog-posts") {
		t.Errorf("expected rw:blog-* to allow write on blog-posts")
	}
	if scope.Allows(auth.ActionCreate, "blog-posts") {
		t.Errorf("expected rw:blog-* to deny create on blog-posts")
	}
	if scope.Allows(auth.ActionRead, "other-repo") {
		t.Errorf("expected rw:blog-* to deny read on other-repo")
	}
}

func TestAllowsMultiScope(t *testing.T) {
	scopes, err := auth.ParseScopes([]string{"r:*", "w:staging-*", "rwc:sandbox-*"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !auth.Allows(scopes, auth.ActionRead, "prod") {
		t.Errorf("expected read on prod to be allowed via r:*")
	}
	if auth.Allows(scopes, auth.ActionWrite, "prod") {
		t.Errorf("expected write on prod to be denied")
	}
	if !auth.Allows(scopes, auth.ActionWrite, "staging-api") {
		t.Errorf("expected write on staging-api to be allowed via w:staging-*")
	}
	if auth.Allows(scopes, auth.ActionCreate, "staging-api") {
		t.Errorf("expected create on staging-api to be denied")
	}
	if !auth.Allows(scopes, auth.ActionCreate, "sandbox-demo") {
		t.Errorf("expected create on sandbox-demo to be allowed via rwc:sandbox-*")
	}
}

func TestParseScopesEmpty(t *testing.T) {
	_, err := auth.ParseScopes(nil)
	if err == nil {
		t.Errorf("expected error for nil scopes")
	}
	if !strings.Contains(err.Error(), "cannot be empty") {
		t.Errorf("expected empty error message, got %q", err.Error())
	}
}

func TestCheckRepoAndToken(t *testing.T) {
	// Valid
	if err := auth.CheckRepoAndToken("token123", "repo-alpha"); err != nil {
		t.Errorf("expected CheckRepoAndToken to succeed, got %v", err)
	}

	// Empty token
	err := auth.CheckRepoAndToken("", "repo-alpha")
	if err == nil || !errors.Is(err, auth.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized for empty token, got %v", err)
	}
	if strings.Contains(err.Error(), "\n") {
		t.Errorf("refusal contains newline: %q", err.Error())
	}

	// Invalid repo
	err = auth.CheckRepoAndToken("token123", "repo/sub")
	if err == nil || !errors.Is(err, auth.ErrInvalidRepo) {
		t.Errorf("expected ErrInvalidRepo for invalid repo, got %v", err)
	}
}

func TestForbiddenRefusal(t *testing.T) {
	err := auth.ForbiddenRefusal(auth.ActionWrite, "repo-alpha")
	if err == nil || !errors.Is(err, auth.ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
	if strings.Contains(err.Error(), "\n") {
		t.Errorf("refusal contains newline: %q", err.Error())
	}
	expected := "forbidden: token does not grant action \"w\" on repository \"repo-alpha\" (request scope 'w:repo-alpha' from administrator or issuer)"
	if err.Error() != expected {
		t.Errorf("got %q, want %q", err.Error(), expected)
	}
}
