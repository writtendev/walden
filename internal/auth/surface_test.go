package auth_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// authSurfaceAllowlist is every auth.X identifier a non-test file outside internal/auth may
// reference: the Authorizer contract itself, the vocabulary needed to build a request
// (Action, Actions, and their constants), the two ways to obtain an Authorizer, the store
// interface a caller wires in, the repo-identifier validator WALD-37 reuses, and the
// sentinel errors a caller matches against with errors.Is. Everything else — ParseScope,
// Scope, Allows, Missing, MatchGlob, HashToken, TokenRecord, ParseAndVerifyCapability, and
// so on — is an authorization detail, reachable only from inside this package.
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

	"ErrUnauthorized":     true,
	"ErrForbidden":        true,
	"ErrInvalidRepo":      true,
	"ErrInvalidScope":     true,
	"ErrInvalidToken":     true,
	"ErrExpired":          true,
	"ErrNotYetValid":      true,
	"ErrInvalidSignature": true,
}

// TestNoHandlerReachesAuthorizationDetail is a source-level guard, stdlib only, pinning
// WALD-50's other half of "one function": not just that Authorizer carries a single
// method (see TestSingleDecisionMethod), but that nothing outside internal/auth reaches
// past it to an authorization detail — a scope, a token hash, the glob matcher — directly.
// A route is meant to ask the question and act on the answer, not weigh the answer itself.
//
// It walks every non-test .go file in the module outside internal/auth, collects each
// `auth.X` selector it references, and fails on any X outside authSurfaceAllowlist below.
// ValidateRepo is allowed on purpose: WALD-37 makes store.RepoPath call it, and that is the
// published validator being used, not an authorization detail being reached around.
//
// Like the dependency-guard allowlist in .github/workflows/ci.yml, authSurfaceAllowlist is
// edited deliberately, in the commit that needs the new entry — not expanded on the way to
// making a test pass.
//
// What this cannot see: a method call through an interface value (for example, a
// githttp.Handler holding its authorizer as a plain auth.Authorizer) is a method call on an
// interface, not an `auth.X` selector, and is invisible to this walk by construction of
// go/ast. It also cannot see reflection, string-built identifiers, or a second import path
// for this package under another module name. It only pins the one avoidance this ticket is
// about: reaching for auth's internals by name from outside auth.
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

		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkgIdent, ok := sel.X.(*ast.Ident)
			if !ok || pkgIdent.Name != "auth" {
				return true
			}
			if !authSurfaceAllowlist[sel.Sel.Name] {
				t.Errorf("%s: references auth.%s, which is outside the authorization surface a handler may reach (see authSurfaceAllowlist in surface_test.go)", rel, sel.Sel.Name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk %s: %v", root, err)
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
