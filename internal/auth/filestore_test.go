package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/auth"
)

// TestFileTokenStoreFixtureRoundTrip loads the published builtin_tokens.json into a
// FileTokenStore over t.TempDir(), opens a second store over the same directory, hands it to
// NewBuiltinAuthorizer, and runs the same probe matrix TestBuiltinTokensFixture runs against
// MemoryTokenStore. Same verdicts and the same refusal sentinels, or the disk format has lost
// something between one store instance and the next.
func TestFileTokenStoreFixtureRoundTrip(t *testing.T) {
	var fixture struct {
		Version     string `json:"version"`
		Description string `json:"description"`
		Tokens      []struct {
			TokenID   string   `json:"token_id"`
			RawToken  string   `json:"raw_token"`
			TokenHash string   `json:"token_hash"`
			Scopes    []string `json:"scopes"`
			Revoked   bool     `json:"revoked"`
		} `json:"tokens"`
	}
	readFixture(t, "builtin_tokens.json", &fixture)

	ctx := context.Background()
	dir := t.TempDir()
	writer := auth.NewFileTokenStore(dir)

	for _, tok := range fixture.Tokens {
		scopes, err := auth.ParseScopes(tok.Scopes)
		if err != nil {
			t.Fatalf("ParseScopes(%v): %v", tok.Scopes, err)
		}
		if err := writer.CreateToken(ctx, &auth.TokenRecord{
			TokenID:   tok.TokenID,
			TokenHash: tok.TokenHash,
			Scopes:    scopes,
			CreatedAt: time.Date(2026, 8, 31, 0, 1, 0, 0, time.UTC),
			Revoked:   tok.Revoked,
		}); err != nil {
			t.Fatalf("CreateToken(%s): %v", tok.TokenID, err)
		}
	}

	// A second store instance over the same directory: this proves the format round-trips
	// across a process boundary rather than merely surviving in one store's memory.
	reader := auth.NewFileTokenStore(dir)
	authorizer := auth.NewBuiltinAuthorizer(reader)

	for _, want := range builtinTokenExpectations {
		if len(want.grants) != len(probeRepos) {
			t.Fatalf("token %s pins %d probe answers, want one per probe repository (%d)", want.tokenID, len(want.grants), len(probeRepos))
		}
		for i, repo := range probeRepos {
			for _, action := range probeActions {
				err := authorizer.Authorize(ctx, want.rawToken, onlyAction(action), repo)
				switch {
				case strings.Contains(want.grants[i], string(action)):
					if err != nil {
						t.Errorf("token %s, action %q on %q: got err=%v, want allowed", want.tokenID, action, repo, err)
					}
				case want.revoked:
					if !errors.Is(err, auth.ErrUnauthorized) {
						t.Errorf("revoked token %s, action %q on %q: got err=%v, want unauthorized", want.tokenID, action, repo, err)
					}
				default:
					if !errors.Is(err, auth.ErrForbidden) {
						t.Errorf("token %s, action %q on %q: got err=%v, want forbidden", want.tokenID, action, repo, err)
					}
				}
			}
		}
	}
}

// TestFileTokenStoreNoRawTokenOnDisk creates and then revokes a token with a known raw
// string, then reads every byte under the data directory and asserts the raw string never
// appears while the sha256: hash form does. This is the property the plan calls out by name:
// raw tokens never touch disk.
func TestFileTokenStoreNoRawTokenOnDisk(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store := auth.NewFileTokenStore(dir)

	rawToken, hash, err := auth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	scopes, err := auth.ParseScopes([]string{"rwc:*"})
	if err != nil {
		t.Fatalf("ParseScopes: %v", err)
	}
	if err := store.CreateToken(ctx, &auth.TokenRecord{
		TokenID:   "tok_raw_probe",
		TokenHash: hash,
		Scopes:    scopes,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if err := store.RevokeToken(ctx, "tok_raw_probe", time.Now().UTC()); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	sawHash := false
	err = filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(data), rawToken) {
			t.Errorf("%s contains the raw token", path)
		}
		if strings.Contains(string(data), "sha256:") {
			sawHash = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}
	if !sawHash {
		t.Error("no file under the data directory carries the sha256: hash form")
	}
}

// TestFileTokenStoreScopesArePublishedStrings unmarshals tokens.json into a bare map and
// asserts that "scopes" is exactly the published "<actions>:<pattern>" strings, in order —
// not TokenRecord's Go-side nested {Actions,Pattern} object.
func TestFileTokenStoreScopesArePublishedStrings(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store := auth.NewFileTokenStore(dir)

	scopes, err := auth.ParseScopes([]string{"rw:blog-*", "r:docs"})
	if err != nil {
		t.Fatalf("ParseScopes: %v", err)
	}
	if err := store.CreateToken(ctx, &auth.TokenRecord{
		TokenID:   "tok_writer_02",
		TokenHash: auth.HashToken("walden_sec_writer_0123456789abcdef"),
		Scopes:    scopes,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "tokens.json"))
	if err != nil {
		t.Fatalf("reading tokens.json: %v", err)
	}
	var raw struct {
		Tokens []map[string]any `json:"tokens"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(raw.Tokens) != 1 {
		t.Fatalf("tokens.json carries %d tokens, want 1", len(raw.Tokens))
	}
	gotScopes, ok := raw.Tokens[0]["scopes"].([]any)
	if !ok {
		t.Fatalf("scopes field is %T, want a JSON array", raw.Tokens[0]["scopes"])
	}
	want := []string{"rw:blog-*", "r:docs"}
	if len(gotScopes) != len(want) {
		t.Fatalf("scopes = %v, want %v", gotScopes, want)
	}
	for i, s := range gotScopes {
		str, ok := s.(string)
		if !ok {
			t.Fatalf("scopes[%d] is %T, not a published scope string", i, s)
		}
		if str != want[i] {
			t.Errorf("scopes[%d] = %q, want %q", i, str, want[i])
		}
	}
}

// TestFileTokenStoreAtomicAndPermissioned checks that a mutation leaves no tokens.json.tmp
// behind and that tokens.json is mode 0600.
func TestFileTokenStoreAtomicAndPermissioned(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store := auth.NewFileTokenStore(dir)

	scopes, err := auth.ParseScopes([]string{"rwc:*"})
	if err != nil {
		t.Fatalf("ParseScopes: %v", err)
	}
	if err := store.CreateToken(ctx, &auth.TokenRecord{
		TokenID:   "tok_atomic",
		TokenHash: auth.HashToken("walden_atomic_probe"),
		Scopes:    scopes,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tokens.json.tmp")); !os.IsNotExist(err) {
		t.Errorf("tokens.json.tmp leftover after CreateToken (stat err=%v)", err)
	}
	info, err := os.Stat(filepath.Join(dir, "tokens.json"))
	if err != nil {
		t.Fatalf("Stat tokens.json: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Errorf("tokens.json mode = %o, want 0600", got)
	}

	if err := store.RevokeToken(ctx, "tok_atomic", time.Now().UTC()); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tokens.json.tmp")); !os.IsNotExist(err) {
		t.Errorf("tokens.json.tmp leftover after RevokeToken (stat err=%v)", err)
	}
	info, err = os.Stat(filepath.Join(dir, "tokens.json"))
	if err != nil {
		t.Fatalf("Stat tokens.json: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Errorf("tokens.json mode after revoke = %o, want 0600", got)
	}
}

// TestFileTokenStoreSecondProcessSeesRevoke proves there is no stale cache: store A revokes,
// and a second FileTokenStore instance's next GetTokenByHash sees the revocation without
// either instance being told about the other.
func TestFileTokenStoreSecondProcessSeesRevoke(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	storeA := auth.NewFileTokenStore(dir)
	storeB := auth.NewFileTokenStore(dir)

	scopes, err := auth.ParseScopes([]string{"rwc:*"})
	if err != nil {
		t.Fatalf("ParseScopes: %v", err)
	}
	hash := auth.HashToken("walden_cross_process")
	if err := storeA.CreateToken(ctx, &auth.TokenRecord{
		TokenID:   "tok_cross_process",
		TokenHash: hash,
		Scopes:    scopes,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	if err := storeA.RevokeToken(ctx, "tok_cross_process", time.Now().UTC()); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	rec, err := storeB.GetTokenByHash(ctx, hash)
	if err != nil {
		t.Fatalf("GetTokenByHash: %v", err)
	}
	if rec == nil {
		t.Fatal("storeB: token not found")
	}
	if !rec.Revoked {
		t.Errorf("storeB observed a stale, unrevoked record: %+v", rec)
	}
}

// checkSingleLineRefusal asserts err is a refusal matching want via errors.Is, is exactly one
// line, and never echoes what looks like a raw bearer token.
func checkSingleLineRefusal(t *testing.T, err error, want error) {
	t.Helper()
	if err == nil {
		t.Fatal("got nil error, want a refusal")
	}
	if !errors.Is(err, want) {
		t.Errorf("errors.Is(err, %v) = false for err=%v", want, err)
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
	if strings.Contains(err.Error(), auth.TokenPrefix) {
		t.Errorf("refusal echoes what looks like a raw token: %q", err.Error())
	}
}

// TestFileTokenStoreRefusals covers every refusal the plan calls out by name: a duplicate
// CreateToken (by id, and separately by hash), RevokeToken on an unknown id, RevokeToken on
// an already-revoked token, and a truncated tokens.json — each pinned to its sentinel via
// errors.Is, and the truncated file proven not to be read as an empty table.
func TestFileTokenStoreRefusals(t *testing.T) {
	ctx := context.Background()

	t.Run("duplicate token id", func(t *testing.T) {
		dir := t.TempDir()
		store := auth.NewFileTokenStore(dir)
		scopes, _ := auth.ParseScopes([]string{"rwc:*"})
		if err := store.CreateToken(ctx, &auth.TokenRecord{
			TokenID:   "tok_dup",
			TokenHash: auth.HashToken("walden_dup_a"),
			Scopes:    scopes,
			CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("CreateToken: %v", err)
		}
		err := store.CreateToken(ctx, &auth.TokenRecord{
			TokenID:   "tok_dup",
			TokenHash: auth.HashToken("walden_dup_b"),
			Scopes:    scopes,
			CreatedAt: time.Now().UTC(),
		})
		checkSingleLineRefusal(t, err, auth.ErrTokenExists)
	})

	t.Run("duplicate token hash", func(t *testing.T) {
		dir := t.TempDir()
		store := auth.NewFileTokenStore(dir)
		scopes, _ := auth.ParseScopes([]string{"rwc:*"})
		hash := auth.HashToken("walden_dup_hash")
		if err := store.CreateToken(ctx, &auth.TokenRecord{
			TokenID:   "tok_dup_hash_a",
			TokenHash: hash,
			Scopes:    scopes,
			CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("CreateToken: %v", err)
		}
		err := store.CreateToken(ctx, &auth.TokenRecord{
			TokenID:   "tok_dup_hash_b",
			TokenHash: hash,
			Scopes:    scopes,
			CreatedAt: time.Now().UTC(),
		})
		checkSingleLineRefusal(t, err, auth.ErrTokenExists)
		if strings.Contains(err.Error(), hash) {
			t.Errorf("refusal echoes the token hash: %q", err.Error())
		}
	})

	t.Run("revoke unknown token", func(t *testing.T) {
		dir := t.TempDir()
		store := auth.NewFileTokenStore(dir)
		err := store.RevokeToken(ctx, "tok_missing", time.Now().UTC())
		checkSingleLineRefusal(t, err, auth.ErrTokenNotFound)
	})

	t.Run("revoke already-revoked token", func(t *testing.T) {
		dir := t.TempDir()
		store := auth.NewFileTokenStore(dir)
		scopes, _ := auth.ParseScopes([]string{"rwc:*"})
		if err := store.CreateToken(ctx, &auth.TokenRecord{
			TokenID:   "tok_double_revoke",
			TokenHash: auth.HashToken("walden_double_revoke"),
			Scopes:    scopes,
			CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("CreateToken: %v", err)
		}
		if err := store.RevokeToken(ctx, "tok_double_revoke", time.Now().UTC()); err != nil {
			t.Fatalf("first RevokeToken: %v", err)
		}
		err := store.RevokeToken(ctx, "tok_double_revoke", time.Now().UTC())
		checkSingleLineRefusal(t, err, auth.ErrTokenAlreadyRevoked)
	})

	t.Run("truncated tokens.json is not read as empty", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "tokens.json"), []byte(`{"version":"v1","tokens":[{"token_id":`), 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		store := auth.NewFileTokenStore(dir)

		_, err := store.ListTokens(ctx)
		checkSingleLineRefusal(t, err, auth.ErrStoreUnavailable)

		if _, err := store.GetTokenByHash(ctx, "sha256:0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
			t.Error("GetTokenByHash over a truncated file returned nil error, want a refusal")
		}

		// The decisive check: a truncated table must never be treated as an empty one, which
		// would silently invalidate every token. CreateToken over the same directory must
		// refuse rather than happily append to what it believes is an empty table.
		scopes, _ := auth.ParseScopes([]string{"rwc:*"})
		err = store.CreateToken(ctx, &auth.TokenRecord{
			TokenID:   "tok_after_corruption",
			TokenHash: auth.HashToken("walden_after_corruption"),
			Scopes:    scopes,
			CreatedAt: time.Now().UTC(),
		})
		checkSingleLineRefusal(t, err, auth.ErrStoreUnavailable)
	})
}

// TestFileTokenStoreConcurrent mirrors TestMemoryTokenStoreConcurrent against the file store,
// run under -race, and separately proves that N concurrent writers through distinct store
// instances over one directory all land: no lost update.
func TestFileTokenStoreConcurrent(t *testing.T) {
	ctx := context.Background()

	t.Run("mixed reads and writes through one store", func(t *testing.T) {
		dir := t.TempDir()
		store := auth.NewFileTokenStore(dir)
		authorizer := auth.NewBuiltinAuthorizer(store)

		const numWorkers = 8
		const iterations = 10

		var wg sync.WaitGroup
		wg.Add(numWorkers)
		for w := 0; w < numWorkers; w++ {
			workerID := w
			go func() {
				defer wg.Done()
				tokenID := fmt.Sprintf("tok_conc_%d", workerID)
				rawToken := fmt.Sprintf("walden_conc_%d", workerID)
				hash := auth.HashToken(rawToken)
				scopes, _ := auth.ParseScopes([]string{"rwc:*"})

				if err := store.CreateToken(ctx, &auth.TokenRecord{
					TokenID:   tokenID,
					TokenHash: hash,
					Scopes:    scopes,
					CreatedAt: time.Now().UTC(),
				}); err != nil {
					t.Errorf("CreateToken(%s): %v", tokenID, err)
					return
				}

				for i := 0; i < iterations; i++ {
					_, _ = store.GetTokenByHash(ctx, hash)
					_, _ = store.ListTokens(ctx)
					_ = authorizer.Authorize(ctx, rawToken, auth.Actions{Read: true}, "repo-alpha")
				}

				if err := store.RevokeToken(ctx, tokenID, time.Now().UTC()); err != nil {
					t.Errorf("RevokeToken(%s): %v", tokenID, err)
				}
			}()
		}
		wg.Wait()
	})

	t.Run("distinct store instances over one directory all land", func(t *testing.T) {
		dir := t.TempDir()
		const numWriters = 16

		var wg sync.WaitGroup
		wg.Add(numWriters)
		for w := 0; w < numWriters; w++ {
			workerID := w
			go func() {
				defer wg.Done()
				store := auth.NewFileTokenStore(dir)
				scopes, _ := auth.ParseScopes([]string{"rwc:*"})
				tokenID := fmt.Sprintf("tok_writer_%d", workerID)
				if err := store.CreateToken(ctx, &auth.TokenRecord{
					TokenID:   tokenID,
					TokenHash: auth.HashToken(fmt.Sprintf("walden_writer_%d", workerID)),
					Scopes:    scopes,
					CreatedAt: time.Now().UTC(),
				}); err != nil {
					t.Errorf("CreateToken(%s): %v", tokenID, err)
				}
			}()
		}
		wg.Wait()

		verify := auth.NewFileTokenStore(dir)
		tokens, err := verify.ListTokens(ctx)
		if err != nil {
			t.Fatalf("ListTokens: %v", err)
		}
		if len(tokens) != numWriters {
			t.Fatalf("ListTokens returned %d tokens, want %d (a concurrent writer lost its update)", len(tokens), numWriters)
		}
	})
}
