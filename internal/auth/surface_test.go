package auth_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// authImportPath is the import path this guard watches for. A file is only inspected for
// auth.X references once it is confirmed to import this path — matched here, not by the
// literal identifier "auth", precisely so an alias on the import doesn't change what is
// found.
const authImportPath = "github.com/writtendev/walden/internal/auth"

// authSurfaceAllowlist is every auth.X identifier a non-test file outside internal/auth may
// reference: the Authorizer contract itself, the vocabulary needed to build a request
// (Action, Actions, and their constants), the two ways to obtain an Authorizer, the store
// interface and file-backed constructor a caller wires in (TokenStore, NewFileTokenStore), the
// first-boot admin token primitives (AdminTokenID, EnsureAdminToken), the token CLI primitives
// (GenerateToken, TokenRecord, ParseScope, ParseScopes), the repo-identifier validator WALD-37
// reuses, and the sentinel errors a caller matches against with errors.Is (including
// ErrStoreUnavailable, ErrTokenExists, ErrTokenNotFound, ErrTokenAlreadyRevoked). Everything
// else — Scope, Allows, Missing, MatchGlob, HashToken, ParseAndVerifyCapability, and so on —
// is an authorization detail, reachable only from inside this package.
var authSurfaceAllowlist = map[string]bool{
	"Authorizer":    true,
	"NewAuthorizer": true,
	"Action":        true,
	"ActionRead":    true,
	"ActionWrite":   true,
	"ActionCreate":  true,
	"Actions":       true,
	"TokenStore":    true,
	"ValidateRepo":  true,

	"AdminTokenID":      true,
	"EnsureAdminToken":  true,
	"NewFileTokenStore": true,

	"GenerateToken": true,
	"TokenRecord":   true,
	"ParseScope":    true,
	"ParseScopes":   true,

	"ErrUnauthorized":        true,
	"ErrForbidden":           true,
	"ErrInvalidRepo":         true,
	"ErrInvalidScope":        true,
	"ErrInvalidToken":        true,
	"ErrExpired":             true,
	"ErrNotYetValid":         true,
	"ErrInvalidSignature":    true,
	"ErrCreateForbidden":     true,
	"ErrStoreUnavailable":    true,
	"ErrTokenExists":         true,
	"ErrTokenNotFound":       true,
	"ErrTokenAlreadyRevoked": true,
}

// checkAuthSurface inspects one already-parsed file for references to internal/auth
// identifiers outside authSurfaceAllowlist. It resolves every local name bound to the
// authImportPath import from the file's own import declarations — rather than matching the
// literal identifier "auth" — so an aliased import (`wauth "…/internal/auth"`) is resolved to
// the real package and checked exactly like an unaliased one. Go allows importing the same
// path more than once under different names in one file, so every matching import spec's name
// is collected rather than just the last one seen. A file that never imports authImportPath is
// left alone, which also removes a converse false positive: an unrelated local variable or
// field named "auth" in a file that doesn't import this package at all.
//
// A dot-import (`. "…/internal/auth"`) binds the package's exported identifiers directly into
// the file's scope, indistinguishable at the AST level from any other bare identifier without
// full type information this guard does not have. Rather than silently miss that case the way
// the alias bug did, a dot-import is reported on sight as its own violation.
func checkAuthSurface(file *ast.File) []string {
	localNames := map[string]bool{}
	dotImported := false
	imported := false

	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != authImportPath {
			continue
		}
		imported = true
		switch {
		case imp.Name == nil:
			localNames["auth"] = true // the package's own declared name
		case imp.Name.Name == "_":
			// blank import: no identifier is ever bound, nothing to check
		case imp.Name.Name == ".":
			dotImported = true
		default:
			localNames[imp.Name.Name] = true
		}
	}

	if !imported {
		return nil
	}

	var violations []string
	if dotImported {
		violations = append(violations, fmt.Sprintf(
			"dot-imports %s: this guard cannot resolve which bare identifiers it introduces; use a named import (aliased or not) instead",
			authImportPath))
	}
	if len(localNames) == 0 {
		return violations
	}

	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if !ok || !localNames[pkgIdent.Name] {
			return true
		}
		if !authSurfaceAllowlist[sel.Sel.Name] {
			violations = append(violations, fmt.Sprintf(
				"references %s.%s, which is outside the authorization surface a handler may reach (see authSurfaceAllowlist in surface_test.go)",
				pkgIdent.Name, sel.Sel.Name))
		}
		return true
	})
	return violations
}

// TestNoHandlerReachesAuthorizationDetail is a source-level guard, stdlib only, pinning
// WALD-50's other half of "one function": not just that Authorizer carries a single
// method (see TestSingleDecisionMethod), but that nothing outside internal/auth reaches
// past it to an authorization detail — a scope, a token hash, the glob matcher — directly.
// A route is meant to ask the question and act on the answer, not weigh the answer itself.
//
// It walks every non-test .go file in the module outside internal/auth, parses it, and hands
// it to checkAuthSurface, which resolves the file's own import of internal/auth (under
// whatever local name or alias it was given) before looking for identifiers outside
// authSurfaceAllowlist below.
//
// ValidateRepo is allowed on purpose: WALD-37 makes store.RepoPath call it, and that is the
// published validator being used, not an authorization detail being reached around.
// AdminTokenID, EnsureAdminToken, NewFileTokenStore, and ErrStoreUnavailable are allowed
// so cmd/walden can initialize the store and ensure the first-boot admin token on startup
// in built-in auth mode without violating the authorization detail boundary guard.
//
// Like the dependency-guard allowlist in .github/workflows/ci.yml, authSurfaceAllowlist is
// edited deliberately, in the commit that needs the new entry — not expanded on the way to
// making a test pass.
//
// What this cannot see: a method call through an interface value (for example, a
// githttp.Handler holding its authorizer as a plain auth.Authorizer) is a method call on an
// interface, not an `auth.X` selector, and is invisible to this walk by construction of
// go/ast. It also cannot see reflection or string-built identifiers. An aliased import
// (`wauth "…/internal/auth"`) is resolved through the file's own import declarations rather
// than matched by the literal name "auth", so it is still caught; a dot-import is flagged on
// sight instead, since resolving which bare identifiers it introduces would need full type
// information this guard does not have. It only pins the one avoidance this ticket is about:
// reaching for auth's internals by name from outside auth.
//
// Test files are exempt everywhere in the module, including outside internal/auth: WALD-52's
// handler tests mint a token to drive a route, and a guard that forbade that would be worked
// around rather than obeyed.
func TestNoHandlerReachesAuthorizationDetail(t *testing.T) {
	root := moduleRoot(t)

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if path != root && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if rel == "internal/auth" || strings.HasPrefix(rel, "internal/auth/") {
			return nil
		}

		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}

		for _, violation := range checkAuthSurface(file) {
			t.Errorf("%s: %s", rel, violation)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk %s: %v", root, err)
	}
}

// TestAuthSurfaceGuardResolvesImportAlias re-verifies, directly against checkAuthSurface
// rather than by hand-editing a file under internal/githttp and reverting it, that the guard
// fires on an auth.X reference regardless of the local name the importing file gave the
// package — the bug the round-1 review caught: the guard used to match the literal identifier
// "auth", which an alias walks straight past.
func TestAuthSurfaceGuardResolvesImportAlias(t *testing.T) {
	tests := []struct {
		name          string
		src           string
		wantViolation bool
	}{
		{
			name: "unaliased import reaching a detail",
			src: `package p
import "github.com/writtendev/walden/internal/auth"
var _ = auth.HashToken
`,
			wantViolation: true,
		},
		{
			name: "aliased import reaching a detail",
			src: `package p
import wauth "github.com/writtendev/walden/internal/auth"
var _ = wauth.HashToken
`,
			wantViolation: true,
		},
		{
			name: "aliased import staying within the allowlist",
			src: `package p
import wauth "github.com/writtendev/walden/internal/auth"
var _ wauth.Authorizer
`,
			wantViolation: false,
		},
		{
			name: "unaliased import staying within the allowlist",
			src: `package p
import "github.com/writtendev/walden/internal/auth"
var _ auth.Authorizer
`,
			wantViolation: false,
		},
		{
			name: "a local identifier named auth is not the package when it isn't imported",
			src: `package p
type helper struct{ auth string }
func f(auth string) string { return auth }
`,
			wantViolation: false,
		},
		{
			name: "dot import is flagged on sight",
			src: `package p
import . "github.com/writtendev/walden/internal/auth"
var _ = HashToken
`,
			wantViolation: true,
		},
		{
			name: "same path imported twice under two names catches a reference through either",
			src: `package p
import (
	auth "github.com/writtendev/walden/internal/auth"
	wauth "github.com/writtendev/walden/internal/auth"
)
var _ = auth.HashToken
var _ wauth.Authorizer
`,
			wantViolation: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "probe.go", tc.src, 0)
			if err != nil {
				t.Fatalf("ParseFile: %v", err)
			}
			got := checkAuthSurface(file)
			if tc.wantViolation && len(got) == 0 {
				t.Fatalf("checkAuthSurface found no violation, want one")
			}
			if !tc.wantViolation && len(got) != 0 {
				t.Fatalf("checkAuthSurface found violation(s) %v, want none", got)
			}
		})
	}
}

// moduleRoot walks up from the current package directory — where `go test` runs this
// package from — until it finds the go.mod that marks the module root.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("failed to find the module root (no go.mod found walking up from the test directory)")
		}
		dir = parent
	}
}
