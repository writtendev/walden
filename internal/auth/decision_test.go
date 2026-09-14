package auth_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/journal"
)

// TestSingleDecisionMethod pins "one function": Authorizer is the single authorization
// decision point, so it carries exactly one method. A second one — a way to ask the
// question that does not go through Authorize — would let a caller route around the shared
// evaluation this ticket centralizes, and would fail to compile only if something noticed;
// this makes it fail a test instead.
func TestSingleDecisionMethod(t *testing.T) {
	typ := reflect.TypeOf((*auth.Authorizer)(nil)).Elem()
	if got := typ.NumMethod(); got != 1 {
		t.Fatalf("auth.Authorizer carries %d methods, want exactly 1 (Authorize)", got)
	}
	if typ.Method(0).Name != "Authorize" {
		t.Fatalf("auth.Authorizer's one method is %q, want %q", typ.Method(0).Name, "Authorize")
	}
}

// TestAuthorizeVerdicts runs the same required-action table against both providers — a
// built-in token and a signed capability, each carrying the same scopes — and asserts they
// reach the same verdicts. Same inputs, same answers, whichever provider is mounted: that
// is the property "one question, one pluggable answer" promises, and it is checked here
// rather than assumed from each provider's own tests agreeing with themselves.
//
// The create case ({Write, Create}) is what keeps creation from being bolted on elsewhere:
// spec/auth/v1 §3.4 says an implicit-create push needs both, and a provider that checked
// them one at a time could not tell "denied create" from "denied write" apart from this
// table's own refusal message.
func TestAuthorizeVerdicts(t *testing.T) {
	ctx := context.Background()
	const repo = "repo-alpha"

	priv, pub, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	// mount builds both providers for the same scope string, each holding a credential
	// that carries exactly those scopes, so the table below asks the identical question of
	// both.
	mount := func(t *testing.T, scope string) map[string]struct {
		authorizer auth.Authorizer
		token      string
	} {
		t.Helper()

		scopes, err := auth.ParseScopes([]string{scope})
		if err != nil {
			t.Fatalf("ParseScopes(%q): %v", scope, err)
		}

		const builtinToken = "walden_decision_token"
		store := auth.NewMemoryTokenStore()
		if err := store.SaveToken(ctx, &auth.TokenRecord{
			TokenID:   "tok_decision",
			TokenHash: auth.HashToken(builtinToken),
			Scopes:    scopes,
		}); err != nil {
			t.Fatalf("SaveToken: %v", err)
		}

		now := time.Now().UTC()
		capToken, err := auth.SignCapability(priv, &auth.CapabilityPayload{
			Version:   "v1",
			ID:        "cap_decision_" + scope,
			Scopes:    []string{scope},
			IssuedAt:  now.Format(time.RFC3339),
			ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
		})
		if err != nil {
			t.Fatalf("SignCapability: %v", err)
		}

		return map[string]struct {
			authorizer auth.Authorizer
			token      string
		}{
			"built-in":  {auth.NewBuiltinAuthorizer(store), builtinToken},
			"delegated": {auth.NewDelegatedAuthorizer(pub), capToken},
		}
	}

	requiredCases := []auth.Actions{
		{Read: true},
		{Write: true},
		{Create: true},
		{Write: true, Create: true},
	}

	for _, tc := range []struct {
		scope   string
		granted bool // whether every requiredCases entry above must be granted under scope
	}{
		{"rwc:*", true},
		{"rw:*", false},
	} {
		providers := mount(t, tc.scope)
		for name, p := range providers {
			for _, required := range requiredCases {
				err := p.authorizer.Authorize(ctx, p.token, required, repo)
				if tc.granted {
					if err != nil {
						t.Errorf("%s provider, scope %q, required %q: got %v, want granted", name, tc.scope, required, err)
					}
					continue
				}
				// rw:* denies exactly 'c': granted for {Read} and {Write}, refused for
				// {Create} and {Write, Create}, naming 'c' in both refused cases.
				if !required.Create {
					if err != nil {
						t.Errorf("%s provider, scope %q, required %q: got %v, want granted", name, tc.scope, required, err)
					}
					continue
				}
				if !errors.Is(err, auth.ErrForbidden) {
					t.Errorf("%s provider, scope %q, required %q: got %v, want ErrForbidden", name, tc.scope, required, err)
				}
				if err != nil {
					if !strings.Contains(err.Error(), `"c"`) {
						t.Errorf("%s provider, scope %q, required %q: refusal %q does not name 'c'", name, tc.scope, required, err.Error())
					}
					if strings.ContainsAny(err.Error(), "\n\r") {
						t.Errorf("%s provider, scope %q, required %q: refusal is not a single line: %q", name, tc.scope, required, err.Error())
					}
				}
			}
		}
	}
}

// TestAuthorizeRefusesEmptyRequired pins the one fail-open the plan calls out by name: asking
// to authorize nothing must never be answered as a trivial grant. Without this test, nothing
// in the suite ever calls Authorize with auth.Actions{} — so if a later refactor dropped or
// reordered checkRequired (inlining it, moving it below the token lookup, hoisting the
// evaluation into a shared helper), Missing would be handed a zero-value Actions, its loop
// body would never run since nothing is required, it would report nothing missing, and
// Authorize would return nil — a full grant — with every other test in the package still
// green, because every one of them passes a non-empty set.
//
// The token and capability here carry every scope ("rwc:*"), so a refusal can only be
// explained by the empty-required guard itself, never by an ordinary missing-scope denial —
// which is what makes this test able to catch the regression described above instead of
// passing either way.
func TestAuthorizeRefusesEmptyRequired(t *testing.T) {
	ctx := context.Background()
	const repo = "repo-alpha"

	priv, pub, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	scopes, err := auth.ParseScopes([]string{"rwc:*"})
	if err != nil {
		t.Fatalf("ParseScopes: %v", err)
	}

	const builtinToken = "walden_empty_required_token"
	store := auth.NewMemoryTokenStore()
	if err := store.SaveToken(ctx, &auth.TokenRecord{
		TokenID:   "tok_empty_required",
		TokenHash: auth.HashToken(builtinToken),
		Scopes:    scopes,
	}); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	now := time.Now().UTC()
	capToken, err := auth.SignCapability(priv, &auth.CapabilityPayload{
		Version:   "v1",
		ID:        "cap_empty_required",
		Scopes:    []string{"rwc:*"},
		IssuedAt:  now.Format(time.RFC3339),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("SignCapability: %v", err)
	}

	providers := map[string]struct {
		authorizer auth.Authorizer
		token      string
	}{
		"built-in":  {auth.NewBuiltinAuthorizer(store), builtinToken},
		"delegated": {auth.NewDelegatedAuthorizer(pub), capToken},
	}

	for name, p := range providers {
		err := p.authorizer.Authorize(ctx, p.token, auth.Actions{}, repo)
		if err == nil {
			t.Fatalf("%s provider: Authorize(ctx, token, Actions{}, repo) = nil, want a refusal", name)
		}
		if !errors.Is(err, auth.ErrInvalidScope) {
			t.Errorf("%s provider: Authorize(ctx, token, Actions{}, repo) = %v, want ErrInvalidScope", name, err)
		}
		if strings.ContainsAny(err.Error(), "\n\r") {
			t.Errorf("%s provider: refusal is not a single line: %q", name, err.Error())
		}
	}
}
