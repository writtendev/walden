package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/store"
	"github.com/writtendev/walden/internal/store/storetest"
)

func TestTokenCreateSuccess(t *testing.T) {
	dataDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	args := []string{"walden", "token", "create", "--data-dir", dataDir, "--allow", "rw:blog-*", "--id", "test_tok_1"}
	if err := run(context.Background(), args, &stdout, &stderr); err != nil {
		t.Fatalf("run token create failed: %v", err)
	}

	rawToken := strings.TrimSpace(stdout.String())
	if !strings.HasPrefix(rawToken, "walden_") {
		t.Errorf("expected token with prefix walden_, got %q", rawToken)
	}
	if strings.Contains(rawToken, "\n") {
		t.Errorf("expected single token string without embedded newlines, got %q", rawToken)
	}

	// Verify token on disk
	tokensFile := filepath.Join(dataDir, "tokens.json")
	data, err := os.ReadFile(tokensFile)
	if err != nil {
		t.Fatalf("cannot read tokens.json: %v", err)
	}

	var table struct {
		Version string `json:"version"`
		Tokens  []struct {
			TokenID   string   `json:"token_id"`
			TokenHash string   `json:"token_hash"`
			Scopes    []string `json:"scopes"`
			Revoked   bool     `json:"revoked"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(data, &table); err != nil {
		t.Fatalf("cannot parse tokens.json: %v", err)
	}
	if len(table.Tokens) != 1 {
		t.Fatalf("expected 1 token in file, got %d", len(table.Tokens))
	}
	tok := table.Tokens[0]
	if tok.TokenID != "test_tok_1" {
		t.Errorf("expected token_id test_tok_1, got %q", tok.TokenID)
	}
	if len(tok.Scopes) != 1 || tok.Scopes[0] != "rw:blog-*" {
		t.Errorf("expected scope rw:blog-*, got %v", tok.Scopes)
	}
	if tok.Revoked {
		t.Errorf("expected token to be active, got revoked")
	}

	// Verify the minted token authenticates via BuiltinAuthorizer
	store := auth.NewFileTokenStore(dataDir)
	authorizer := auth.NewBuiltinAuthorizer(store)
	ctx := context.Background()

	// Read on blog-foo should succeed
	if err := authorizer.Authorize(ctx, rawToken, auth.Actions{Read: true}, "blog-foo"); err != nil {
		t.Errorf("Authorize read on blog-foo failed: %v", err)
	}
	// Write on blog-bar should succeed
	if err := authorizer.Authorize(ctx, rawToken, auth.Actions{Write: true}, "blog-bar"); err != nil {
		t.Errorf("Authorize write on blog-bar failed: %v", err)
	}
	// Create on blog-baz should be forbidden (missing 'c')
	if err := authorizer.Authorize(ctx, rawToken, auth.Actions{Create: true}, "blog-baz"); err == nil {
		t.Errorf("expected Authorize create on blog-baz to fail, but it succeeded")
	}
	// Read on docs should be forbidden (pattern does not match)
	if err := authorizer.Authorize(ctx, rawToken, auth.Actions{Read: true}, "docs"); err == nil {
		t.Errorf("expected Authorize read on docs to fail, but it succeeded")
	}
}

func TestTokenCreateDefaultScope(t *testing.T) {
	dataDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	args := []string{"walden", "token", "create", "--data-dir", dataDir}
	if err := run(context.Background(), args, &stdout, &stderr); err != nil {
		t.Fatalf("run token create without --allow failed: %v", err)
	}

	rawToken := strings.TrimSpace(stdout.String())
	store := auth.NewFileTokenStore(dataDir)
	tokens, err := store.ListTokens(context.Background())
	if err != nil {
		t.Fatalf("ListTokens failed: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}
	if len(tokens[0].Scopes) != 1 || tokens[0].Scopes[0].String() != "rwc:*" {
		t.Errorf("expected default scope rwc:*, got %v", tokens[0].Scopes)
	}
	if !strings.HasPrefix(tokens[0].TokenID, "tok_") {
		t.Errorf("expected auto-generated token ID starting with tok_, got %q", tokens[0].TokenID)
	}
	if len(tokens[0].TokenID) != 20 {
		t.Errorf("expected auto-generated token ID length 20 (tok_ + 16 hex), got %d (%q)", len(tokens[0].TokenID), tokens[0].TokenID)
	}

	// Verify it grants full rwc:*
	authorizer := auth.NewBuiltinAuthorizer(store)
	ctx := context.Background()
	if err := authorizer.Authorize(ctx, rawToken, auth.Actions{Read: true, Write: true, Create: true}, "any-repo"); err != nil {
		t.Errorf("Authorize rwc on any-repo failed: %v", err)
	}
}

func TestTokenCreateMultipleAndCommaSeparatedScopes(t *testing.T) {
	dataDir := t.TempDir()

	// Repeated --allow and comma-separated
	var stdout, stderr bytes.Buffer
	args := []string{
		"walden", "token", "create",
		"--data-dir", dataDir,
		"--allow", "rw:blog-*,r:docs",
		"--allow", "c:new-*",
		"--id", "multi_scope",
	}
	if err := run(context.Background(), args, &stdout, &stderr); err != nil {
		t.Fatalf("run token create with multiple scopes failed: %v", err)
	}

	store := auth.NewFileTokenStore(dataDir)
	rec, err := store.GetTokenByID(context.Background(), "multi_scope")
	if err != nil {
		t.Fatalf("GetTokenByID failed: %v", err)
	}
	if len(rec.Scopes) != 3 {
		t.Fatalf("expected 3 scopes, got %d: %v", len(rec.Scopes), rec.Scopes)
	}
	expected := []string{"rw:blog-*", "r:docs", "c:new-*"}
	for i, exp := range expected {
		if rec.Scopes[i].String() != exp {
			t.Errorf("scope[%d] = %q, want %q", i, rec.Scopes[i].String(), exp)
		}
	}
}

func TestTokenCreateInvalidScopesRefusal(t *testing.T) {
	tests := []struct {
		name       string
		allowArg   string
		wantErrSub string
	}{
		{
			name:       "missing-colon",
			allowArg:   "rw",
			wantErrSub: `invalid scope: missing colon separator in scope "rw" (use format <actions>:<pattern> (e.g. 'rwc:*', 'rw:blog-*'))`,
		},
		{
			name:       "unknown-action",
			allowArg:   "x:*",
			wantErrSub: "invalid scope: unknown action 'x' (allowed actions are 'r' (read), 'w' (write), 'c' (create))",
		},
		{
			name:       "slash-in-pattern",
			allowArg:   "rw:repo/sub",
			wantErrSub: "invalid scope: slashes are not allowed in glob pattern (walden repositories use a flat namespace without hierarchy)",
		},
		{
			name:       "invalid-character-in-pattern",
			allowArg:   "rw:repo@name",
			wantErrSub: "invalid scope: pattern contains invalid character '@' (allowed pattern characters are [a-zA-Z0-9._-*])",
		},
		{
			name:       "empty-pattern",
			allowArg:   "rw:",
			wantErrSub: "invalid scope: pattern component cannot be empty (specify a repository name or glob pattern (e.g. '*', 'blog-*'))",
		},
		{
			name:       "empty-scope",
			allowArg:   "",
			wantErrSub: "invalid scope: scope cannot be empty (use format <actions>:<pattern> with actions from [r,w,c])",
		},
		{
			name:       "duplicate-action",
			allowArg:   "rr:*",
			wantErrSub: "invalid scope: duplicate action 'r' (each action [r, w, c] may appear at most once in a scope)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataDir := t.TempDir()
			var stdout, stderr bytes.Buffer
			args := []string{"walden", "token", "create", "--data-dir", dataDir, "--allow", tt.allowArg}
			err := run(context.Background(), args, &stdout, &stderr)
			if err == nil {
				t.Fatalf("expected error for invalid scope %q, got nil", tt.allowArg)
			}
			if !strings.Contains(err.Error(), tt.wantErrSub) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErrSub)
			}

			// Ensure no tokens file was written or no tokens created
			store := auth.NewFileTokenStore(dataDir)
			tokens, _ := store.ListTokens(context.Background())
			if len(tokens) != 0 {
				t.Errorf("expected 0 tokens created after refusal, found %d", len(tokens))
			}
		})
	}
}

func TestTokenCreateDuplicateScopeRefusal(t *testing.T) {
	dataDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	args := []string{"walden", "token", "create", "--data-dir", dataDir, "--allow", "r:foo", "--allow", "r:foo"}
	err := run(context.Background(), args, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected refusal for duplicate scope, got nil")
	}
	if !strings.Contains(err.Error(), `duplicate scope "r:foo"`) {
		t.Errorf("error = %q, want substring duplicate scope", err.Error())
	}
}

func TestTokenCreateInvalidTokenID(t *testing.T) {
	dataDir := t.TempDir()

	// Spaces in ID
	var stdout, stderr bytes.Buffer
	args := []string{"walden", "token", "create", "--data-dir", dataDir, "--id", "bad id"}
	err := run(context.Background(), args, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for invalid token ID, got nil")
	}
	if !errors.Is(err, journal.ErrInvalidTokenID) {
		t.Errorf("expected error to wrap journal.ErrInvalidTokenID, got %v", err)
	}

	// Empty ID flag
	stdout.Reset()
	stderr.Reset()
	args = []string{"walden", "token", "create", "--data-dir", dataDir, "--id", ""}
	err = run(context.Background(), args, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for empty token ID, got nil")
	}
	if !strings.Contains(err.Error(), "invalid token id: cannot be empty") {
		t.Errorf("expected cannot be empty refusal, got %v", err)
	}
}

func TestTokenCreateDuplicateIDRefusal(t *testing.T) {
	dataDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	args := []string{"walden", "token", "create", "--data-dir", dataDir, "--id", "tok_dup"}
	if err := run(context.Background(), args, &stdout, &stderr); err != nil {
		t.Fatalf("first token create failed: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	err := run(context.Background(), args, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for duplicate token ID, got nil")
	}
	if !errors.Is(err, auth.ErrTokenExists) {
		t.Errorf("expected error to wrap auth.ErrTokenExists, got %v", err)
	}
	if !strings.Contains(err.Error(), `token id "tok_dup" already exists`) {
		t.Errorf("expected duplicate token id refusal, got %v", err)
	}
}

func TestTokenDelegatedModeExclusivity(t *testing.T) {
	dataDir := t.TempDir()

	// 1. Create a token in built-in mode first
	var stdout, stderr bytes.Buffer
	args := []string{"walden", "token", "create", "--data-dir", dataDir, "--id", "tok_pre"}
	if err := run(context.Background(), args, &stdout, &stderr); err != nil {
		t.Fatalf("run token create failed: %v", err)
	}

	// 2. Set WALDEN_AUTH_TRUST: create must refuse
	t.Setenv("WALDEN_AUTH_TRUST", "ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	wantRefusal := "token create refused: cannot create built-in token when delegated auth is configured (auth-trust key is set) (built-in tokens cannot authenticate while delegated mode is active; unset WALDEN_AUTH_TRUST to use built-in auth)"

	stdout.Reset()
	stderr.Reset()
	args = []string{"walden", "token", "create", "--data-dir", dataDir}
	err := run(context.Background(), args, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected token create to refuse when WALDEN_AUTH_TRUST is set, got nil")
	}
	if err.Error() != wantRefusal {
		t.Errorf("got refusal %q, want %q", err.Error(), wantRefusal)
	}

	// 3. Passing --auth-trust flag explicitly also refuses
	t.Setenv("WALDEN_AUTH_TRUST", "")
	stdout.Reset()
	stderr.Reset()
	args = []string{"walden", "token", "create", "--data-dir", dataDir, "--auth-trust", "some-trust-key"}
	err = run(context.Background(), args, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected token create to refuse with --auth-trust flag, got nil")
	}
	if err.Error() != wantRefusal {
		t.Errorf("got refusal %q, want %q", err.Error(), wantRefusal)
	}

	// 4. List and revoke must continue to function while WALDEN_AUTH_TRUST is set
	t.Setenv("WALDEN_AUTH_TRUST", "ed25519:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	stdout.Reset()
	stderr.Reset()
	args = []string{"walden", "token", "list", "--data-dir", dataDir}
	if err := run(context.Background(), args, &stdout, &stderr); err != nil {
		t.Fatalf("token list failed under delegated mode: %v", err)
	}
	if !strings.Contains(stdout.String(), "tok_pre") {
		t.Errorf("token list output missing tok_pre: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	args = []string{"walden", "token", "revoke", "--data-dir", dataDir, "tok_pre"}
	if err := run(context.Background(), args, &stdout, &stderr); err != nil {
		t.Fatalf("token revoke failed under delegated mode: %v", err)
	}
	if !strings.Contains(stdout.String(), "revoked token tok_pre") {
		t.Errorf("expected revoke confirmation, got %s", stdout.String())
	}
}

func TestTokenListNeverLeaksSecrets(t *testing.T) {
	dataDir := t.TempDir()

	// Create 3 tokens
	var tokens []string
	for _, id := range []string{"tok_a", "tok_b", "tok_c"} {
		var stdout, stderr bytes.Buffer
		args := []string{"walden", "token", "create", "--data-dir", dataDir, "--id", id, "--allow", "r:*"}
		if err := run(context.Background(), args, &stdout, &stderr); err != nil {
			t.Fatalf("create %s failed: %v", id, err)
		}
		raw := strings.TrimSpace(stdout.String())
		tokens = append(tokens, raw)
	}

	// Run list
	var stdout, stderr bytes.Buffer
	args := []string{"walden", "token", "list", "--data-dir", dataDir}
	if err := run(context.Background(), args, &stdout, &stderr); err != nil {
		t.Fatalf("token list failed: %v", err)
	}

	out := stdout.String()

	// Assert header columns
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 4 {
		t.Fatalf("expected header + 3 rows, got %d lines: %s", len(lines), out)
	}
	header := lines[0]
	for _, col := range []string{"ID", "SCOPES", "STATUS", "CREATED"} {
		if !strings.Contains(header, col) {
			t.Errorf("header missing column %q: %q", col, header)
		}
	}

	// Assert zero raw token secrets or sha256 hashes leak
	for _, raw := range tokens {
		if strings.Contains(out, raw) {
			t.Errorf("SECRET LEAK: token list output contains raw bearer token %q", raw)
		}
	}
	if strings.Contains(out, "sha256:") {
		t.Errorf("SECRET LEAK: token list output contains token storage hash prefix sha256:")
	}
}

func TestTokenRevocationImmediate(t *testing.T) {
	dataDir := t.TempDir()

	// Create token
	var stdout, stderr bytes.Buffer
	args := []string{"walden", "token", "create", "--data-dir", dataDir, "--id", "tok_active", "--allow", "rw:*"}
	if err := run(context.Background(), args, &stdout, &stderr); err != nil {
		t.Fatalf("token create failed: %v", err)
	}
	rawToken := strings.TrimSpace(stdout.String())

	// BuiltinAuthorizer probe succeeds
	store := auth.NewFileTokenStore(dataDir)
	authorizer := auth.NewBuiltinAuthorizer(store)
	ctx := context.Background()

	if err := authorizer.Authorize(ctx, rawToken, auth.Actions{Read: true}, "test-repo"); err != nil {
		t.Fatalf("initial Authorize failed: %v", err)
	}

	// Revoke token via CLI
	stdout.Reset()
	stderr.Reset()
	args = []string{"walden", "token", "revoke", "--data-dir", dataDir, "tok_active"}
	if err := run(context.Background(), args, &stdout, &stderr); err != nil {
		t.Fatalf("token revoke failed: %v", err)
	}
	if strings.TrimSpace(stdout.String()) != "revoked token tok_active" {
		t.Errorf("expected 'revoked token tok_active', got %q", stdout.String())
	}

	// The very next Authorize probe must fail immediately with ErrUnauthorized
	err := authorizer.Authorize(ctx, rawToken, auth.Actions{Read: true}, "test-repo")
	if err == nil {
		t.Fatal("expected Authorize to fail immediately after revoke, but it succeeded")
	}
	if !errors.Is(err, auth.ErrUnauthorized) {
		t.Errorf("expected error to wrap auth.ErrUnauthorized, got %v", err)
	}

	// List tokens shows status revoked
	stdout.Reset()
	stderr.Reset()
	args = []string{"walden", "token", "list", "--data-dir", dataDir}
	if err := run(context.Background(), args, &stdout, &stderr); err != nil {
		t.Fatalf("token list failed: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "tok_active") || !strings.Contains(out, "revoked") {
		t.Errorf("expected tok_active to be listed as revoked, got: %s", out)
	}
}

func TestTokenRevokeRefusals(t *testing.T) {
	dataDir := t.TempDir()

	// 1. Missing token ID positional argument
	var stdout, stderr bytes.Buffer
	args := []string{"walden", "token", "revoke", "--data-dir", dataDir}
	err := run(context.Background(), args, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for missing token ID, got nil")
	}
	wantMissing := "missing token id: no token id specified (provide token id to revoke (e.g. 'walden token revoke <token-id>'))"
	if err.Error() != wantMissing {
		t.Errorf("got %q, want %q", err.Error(), wantMissing)
	}

	// 2. Extra positional arguments
	stdout.Reset()
	stderr.Reset()
	args = []string{"walden", "token", "revoke", "--data-dir", dataDir, "tok_1", "tok_2"}
	err = run(context.Background(), args, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for extra positional argument, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected argument") {
		t.Errorf("expected unexpected argument error, got %v", err)
	}

	// 3. Unknown token ID
	stdout.Reset()
	stderr.Reset()
	args = []string{"walden", "token", "revoke", "--data-dir", dataDir, "tok_nonexistent"}
	err = run(context.Background(), args, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for unknown token ID, got nil")
	}
	if !errors.Is(err, auth.ErrTokenNotFound) {
		t.Errorf("expected error to wrap auth.ErrTokenNotFound, got %v", err)
	}
	if !strings.Contains(err.Error(), `no token with id "tok_nonexistent" exists`) {
		t.Errorf("expected unknown token refusal, got %v", err)
	}

	// Create and revoke a real token
	stdout.Reset()
	stderr.Reset()
	args = []string{"walden", "token", "create", "--data-dir", dataDir, "--id", "tok_to_revoke"}
	if err := run(context.Background(), args, &stdout, &stderr); err != nil {
		t.Fatalf("token create failed: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	args = []string{"walden", "token", "revoke", "--data-dir", dataDir, "tok_to_revoke"}
	if err := run(context.Background(), args, &stdout, &stderr); err != nil {
		t.Fatalf("first revoke failed: %v", err)
	}

	// 4. Revoking already-revoked token ID
	stdout.Reset()
	stderr.Reset()
	err = run(context.Background(), args, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for already-revoked token ID, got nil")
	}
	if !errors.Is(err, auth.ErrTokenAlreadyRevoked) {
		t.Errorf("expected error to wrap auth.ErrTokenAlreadyRevoked, got %v", err)
	}
	if !strings.Contains(err.Error(), `token id "tok_to_revoke" is already revoked`) {
		t.Errorf("expected already revoked refusal, got %v", err)
	}
}

func TestTokenInvalidDataDir(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{"walden", "token", "create", "--data-dir", ""}
	err := run(context.Background(), args, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for empty --data-dir, got nil")
	}
	if !strings.Contains(err.Error(), "invalid data-dir: cannot be empty") {
		t.Errorf("expected cannot be empty refusal, got %v", err)
	}
}

func TestTokenUnexpectedArguments(t *testing.T) {
	dataDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	args := []string{"walden", "token", "create", "--data-dir", dataDir, "extra-arg"}
	err := run(context.Background(), args, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for unexpected argument on create, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected argument: extra-arg") {
		t.Errorf("expected unexpected argument refusal, got %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	args = []string{"walden", "token", "list", "--data-dir", dataDir, "extra-arg"}
	err = run(context.Background(), args, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for unexpected argument on list, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected argument: extra-arg") {
		t.Errorf("expected unexpected argument refusal, got %v", err)
	}
}

// bootJournal boots a fresh signing identity for dataDir against a fake
// journal (mirroring rotate_test.go's own pattern) and returns the
// --journal URL every test below passes straight through to `walden
// token create`/`walden token revoke`.
func bootJournal(t *testing.T, dataDir string) string {
	t.Helper()
	setJournalCreds(t)
	fake := storetest.New(t)
	journalURL := journalTestJournalURL(fake)

	var stdout, stderr bytes.Buffer
	if err := runServe(cancelledContext(), []string{
		"--data-dir", dataDir,
		"--listen", "127.0.0.1:0",
		"--journal", journalURL,
	}, &stdout, &stderr); err != nil {
		t.Fatalf("runServe (mint) failed: %v", err)
	}
	return journalURL
}

// replayJournalTable replays the journal at journalURL and returns its
// rebuilt token table, for assertions independent of the CLI's own
// output.
func replayJournalTable(t *testing.T, journalURL string) (*journal.SigningChain, *journal.TokenTable) {
	t.Helper()
	j, err := store.ResolveJournal(journalURL, os.LookupEnv)
	if err != nil {
		t.Fatalf("ResolveJournal: %v", err)
	}
	c := store.NewClient(j)
	chain, table, err := c.ReplayMetaTable(context.Background())
	if err != nil {
		t.Fatalf("ReplayMetaTable: %v", err)
	}
	return chain, table
}

// TestTokenCreateWithJournalWritesMetaRecordAndDisk covers WALD-33's "how
// to know it worked" item 8: `walden token create` against a fake journal
// writes both the _meta record and tokens.json, and prints the raw token
// only on full success.
func TestTokenCreateWithJournalWritesMetaRecordAndDisk(t *testing.T) {
	dataDir := t.TempDir()
	journalURL := bootJournal(t, dataDir)

	var stdout, stderr bytes.Buffer
	args := []string{"walden", "token", "create", "--data-dir", dataDir, "--journal", journalURL, "--allow", "rw:blog-*", "--id", "tok_journaled"}
	if err := run(context.Background(), args, &stdout, &stderr); err != nil {
		t.Fatalf("run token create failed: %v", err)
	}
	rawToken := strings.TrimSpace(stdout.String())
	if !strings.HasPrefix(rawToken, "walden_") {
		t.Fatalf("expected token with prefix walden_, got %q", rawToken)
	}

	_, table := replayJournalTable(t, journalURL)
	row, ok := table.Row("tok_journaled")
	if !ok {
		t.Fatal("the journal's rebuilt token table does not hold tok_journaled")
	}
	if row.TokenHash != auth.HashToken(rawToken) {
		t.Errorf("journaled hash %q != HashToken(printed token) = %q", row.TokenHash, auth.HashToken(rawToken))
	}
	if got, want := strings.Join(row.Scopes, ","), "rw:blog-*"; got != want {
		t.Errorf("journaled scopes = %q, want %q", got, want)
	}

	store := auth.NewFileTokenStore(dataDir)
	rec, err := store.GetTokenByID(context.Background(), "tok_journaled")
	if err != nil {
		t.Fatalf("GetTokenByID: %v", err)
	}
	if rec.TokenHash != auth.HashToken(rawToken) {
		t.Errorf("tokens.json hash %q != HashToken(printed token) = %q", rec.TokenHash, auth.HashToken(rawToken))
	}
}

// TestTokenCreateWithJournalReusedIDRefusesBeforeAnyPut covers the
// uniqueness pre-check: a create whose id the journal already holds
// refuses in one line before any PUT, and tokens.json gains no row for
// it.
func TestTokenCreateWithJournalReusedIDRefusesBeforeAnyPut(t *testing.T) {
	dataDir := t.TempDir()
	journalURL := bootJournal(t, dataDir)

	var stdout, stderr bytes.Buffer
	first := []string{"walden", "token", "create", "--data-dir", dataDir, "--journal", journalURL, "--id", "tok_dup"}
	if err := run(context.Background(), first, &stdout, &stderr); err != nil {
		t.Fatalf("first run token create failed: %v", err)
	}

	chainBefore, _ := replayJournalTable(t, journalURL)
	seqBefore := chainBefore.LastMetaSeq()

	stdout.Reset()
	stderr.Reset()
	second := []string{"walden", "token", "create", "--data-dir", dataDir, "--journal", journalURL, "--id", "tok_dup"}
	err := run(context.Background(), second, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected the second create with a reused id to refuse")
	}
	if !errors.Is(err, auth.ErrTokenExists) {
		t.Errorf("errors.Is(_, auth.ErrTokenExists) = false, err = %v", err)
	}
	if strings.Count(err.Error(), "\n") != 0 {
		t.Errorf("refusal is not one line: %q", err.Error())
	}
	if stdout.String() != "" {
		t.Errorf("expected no token printed on a refused create, got %q", stdout.String())
	}

	chainAfter, _ := replayJournalTable(t, journalURL)
	if chainAfter.LastMetaSeq() != seqBefore {
		t.Errorf("LastMetaSeq() = %d after the refused create, want unchanged %d (no PUT should have happened)", chainAfter.LastMetaSeq(), seqBefore)
	}

	// tokens.json must not have gained a second row either.
	store := auth.NewFileTokenStore(dataDir)
	tokens, err := store.ListTokens(context.Background())
	if err != nil {
		t.Fatalf("ListTokens: %v", err)
	}
	count := 0
	for _, tok := range tokens {
		if tok.TokenID == "tok_dup" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("tokens.json holds %d rows named tok_dup, want 1", count)
	}
}

// TestTokenRevokeWithJournalJournalsThenMutates covers the revoke half of
// "how to know it worked" item 8: `walden token revoke` journals then
// mutates tokens.json.
func TestTokenRevokeWithJournalJournalsThenMutates(t *testing.T) {
	dataDir := t.TempDir()
	journalURL := bootJournal(t, dataDir)

	var stdout, stderr bytes.Buffer
	create := []string{"walden", "token", "create", "--data-dir", dataDir, "--journal", journalURL, "--id", "tok_to_revoke"}
	if err := run(context.Background(), create, &stdout, &stderr); err != nil {
		t.Fatalf("run token create failed: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	revoke := []string{"walden", "token", "revoke", "--data-dir", dataDir, "--journal", journalURL, "tok_to_revoke"}
	if err := run(context.Background(), revoke, &stdout, &stderr); err != nil {
		t.Fatalf("run token revoke failed: %v", err)
	}
	if !strings.Contains(stdout.String(), "revoked token tok_to_revoke") {
		t.Errorf("expected confirmation line, got %q", stdout.String())
	}

	_, table := replayJournalTable(t, journalURL)
	row, ok := table.Row("tok_to_revoke")
	if !ok {
		t.Fatal("the journal's rebuilt token table lost tok_to_revoke")
	}
	if !row.Revoked {
		t.Error("the journal's rebuilt table shows tok_to_revoke as live, want revoked")
	}

	store := auth.NewFileTokenStore(dataDir)
	rec, err := store.GetTokenByID(context.Background(), "tok_to_revoke")
	if err != nil {
		t.Fatalf("GetTokenByID: %v", err)
	}
	if !rec.Revoked {
		t.Error("tokens.json still shows tok_to_revoke as live")
	}
}

// TestTokenRevokeWithJournalUnknownOrAlreadyRevokedRefusesWithoutAppending
// covers the same "without appending" guarantee create's uniqueness
// check gives, on the revoke side: an unknown id and an already-revoked
// id both refuse before any further _meta record lands.
func TestTokenRevokeWithJournalUnknownOrAlreadyRevokedRefusesWithoutAppending(t *testing.T) {
	dataDir := t.TempDir()
	journalURL := bootJournal(t, dataDir)

	var stdout, stderr bytes.Buffer
	create := []string{"walden", "token", "create", "--data-dir", dataDir, "--journal", journalURL, "--id", "tok_live"}
	if err := run(context.Background(), create, &stdout, &stderr); err != nil {
		t.Fatalf("run token create failed: %v", err)
	}

	t.Run("unknown id", func(t *testing.T) {
		chainBefore, _ := replayJournalTable(t, journalURL)

		var out, errOut bytes.Buffer
		args := []string{"walden", "token", "revoke", "--data-dir", dataDir, "--journal", journalURL, "tok_ghost"}
		err := run(context.Background(), args, &out, &errOut)
		if err == nil {
			t.Fatal("expected revoking an unknown id to refuse")
		}
		if !errors.Is(err, auth.ErrTokenNotFound) {
			t.Errorf("errors.Is(_, auth.ErrTokenNotFound) = false, err = %v", err)
		}
		if strings.Count(err.Error(), "\n") != 0 {
			t.Errorf("refusal is not one line: %q", err.Error())
		}

		chainAfter, _ := replayJournalTable(t, journalURL)
		if chainAfter.LastMetaSeq() != chainBefore.LastMetaSeq() {
			t.Errorf("LastMetaSeq() changed from %d to %d; an unknown id must not append", chainBefore.LastMetaSeq(), chainAfter.LastMetaSeq())
		}
	})

	t.Run("already revoked", func(t *testing.T) {
		var out, errOut bytes.Buffer
		firstRevoke := []string{"walden", "token", "revoke", "--data-dir", dataDir, "--journal", journalURL, "tok_live"}
		if err := run(context.Background(), firstRevoke, &out, &errOut); err != nil {
			t.Fatalf("first revoke failed: %v", err)
		}

		chainBefore, _ := replayJournalTable(t, journalURL)

		out.Reset()
		errOut.Reset()
		secondRevoke := []string{"walden", "token", "revoke", "--data-dir", dataDir, "--journal", journalURL, "tok_live"}
		err := run(context.Background(), secondRevoke, &out, &errOut)
		if err == nil {
			t.Fatal("expected revoking an already-revoked id to refuse")
		}
		if !errors.Is(err, auth.ErrTokenAlreadyRevoked) {
			t.Errorf("errors.Is(_, auth.ErrTokenAlreadyRevoked) = false, err = %v", err)
		}
		if strings.Count(err.Error(), "\n") != 0 {
			t.Errorf("refusal is not one line: %q", err.Error())
		}

		chainAfter, _ := replayJournalTable(t, journalURL)
		if chainAfter.LastMetaSeq() != chainBefore.LastMetaSeq() {
			t.Errorf("LastMetaSeq() changed from %d to %d; an already-revoked id must not append", chainBefore.LastMetaSeq(), chainAfter.LastMetaSeq())
		}
	})
}

// TestTokenCreateNoJournalBehavesAsBefore pins that omitting --journal (and
// leaving WALDEN_JOURNAL unset) behaves exactly as it did before this
// ticket: no network access, disk-only.
func TestTokenCreateNoJournalBehavesAsBefore(t *testing.T) {
	dataDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	args := []string{"walden", "token", "create", "--data-dir", dataDir, "--id", "tok_no_journal"}
	if err := run(context.Background(), args, &stdout, &stderr); err != nil {
		t.Fatalf("run token create failed: %v", err)
	}
	rawToken := strings.TrimSpace(stdout.String())
	if !strings.HasPrefix(rawToken, "walden_") {
		t.Fatalf("expected token with prefix walden_, got %q", rawToken)
	}

	store := auth.NewFileTokenStore(dataDir)
	rec, err := store.GetTokenByID(context.Background(), "tok_no_journal")
	if err != nil {
		t.Fatalf("GetTokenByID: %v", err)
	}
	if rec.TokenHash != auth.HashToken(rawToken) {
		t.Errorf("tokens.json hash %q != HashToken(printed token) = %q", rec.TokenHash, auth.HashToken(rawToken))
	}
}
