package auth_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/auth"
)

func TestHashToken(t *testing.T) {
	token := "walden_sec_admin_0123456789abcdef"
	hash := auth.HashToken(token)

	expected := "sha256:b807af8cbdd0849e534474c93408ecdc1593e7e3de172261bd717e6484425ceb"
	if hash != expected {
		t.Errorf("HashToken(%q) = %q, want %q", token, hash, expected)
	}
}

func TestGenerateToken(t *testing.T) {
	raw, hash, err := auth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	if !strings.HasPrefix(raw, "walden_") {
		t.Errorf("expected token to start with 'walden_', got %q", raw)
	}
	if !strings.HasPrefix(hash, "sha256:") {
		t.Errorf("expected hash to start with 'sha256:', got %q", hash)
	}

	// Verify hash is consistent
	if computed := auth.HashToken(raw); computed != hash {
		t.Errorf("computed hash %q does not match returned hash %q", computed, hash)
	}
}

func TestMemoryTokenStore(t *testing.T) {
	ctx := context.Background()
	store := auth.NewMemoryTokenStore()

	scopes, _ := auth.ParseScopes([]string{"rwc:*"})
	rec := &auth.TokenRecord{
		TokenID:   "tok_01",
		TokenHash: auth.HashToken("walden_test_token"),
		Scopes:    scopes,
		CreatedAt: time.Now().UTC(),
	}

	if err := store.CreateToken(ctx, rec); err != nil {
		t.Fatalf("CreateToken failed: %v", err)
	}

	got, err := store.GetTokenByHash(ctx, rec.TokenHash)
	if err != nil {
		t.Fatalf("GetTokenByHash failed: %v", err)
	}
	if got == nil || got.TokenID != "tok_01" {
		t.Errorf("GetTokenByHash got %+v, expected tok_01", got)
	}

	list, err := store.ListTokens(ctx)
	if err != nil || len(list) != 1 {
		t.Errorf("ListTokens got %d items, err %v", len(list), err)
	}

	if err := store.RevokeToken(ctx, "tok_01", time.Now().UTC()); err != nil {
		t.Fatalf("RevokeToken failed: %v", err)
	}

	revoked, err := store.GetTokenByHash(ctx, rec.TokenHash)
	if err != nil || !revoked.Revoked {
		t.Errorf("expected token to be revoked, got %+v", revoked)
	}

	err = store.RevokeToken(ctx, "nonexistent", time.Now().UTC())
	if err == nil {
		t.Errorf("expected error revoking nonexistent token")
	}
}

func TestBuiltinAuthorizer(t *testing.T) {
	ctx := context.Background()
	store := auth.NewMemoryTokenStore()
	authorizer := auth.NewBuiltinAuthorizer(store)

	adminScopes, _ := auth.ParseScopes([]string{"rwc:*"})
	store.CreateToken(ctx, &auth.TokenRecord{
		TokenID:   "tok_admin",
		TokenHash: auth.HashToken("walden_admin"),
		Scopes:    adminScopes,
	})

	readerScopes, _ := auth.ParseScopes([]string{"r:blog-*"})
	store.CreateToken(ctx, &auth.TokenRecord{
		TokenID:   "tok_reader",
		TokenHash: auth.HashToken("walden_reader"),
		Scopes:    readerScopes,
	})

	revokedScopes, _ := auth.ParseScopes([]string{"rwc:*"})
	store.CreateToken(ctx, &auth.TokenRecord{
		TokenID:   "tok_revoked",
		TokenHash: auth.HashToken("walden_revoked"),
		Scopes:    revokedScopes,
		Revoked:   true,
	})

	// Admin token
	err := authorizer.Authorize(ctx, "walden_admin", auth.Actions{Read: true}, "my-repo")
	if err != nil {
		t.Errorf("expected admin read to succeed, got err=%v", err)
	}
	err = authorizer.Authorize(ctx, "walden_admin", auth.Actions{Write: true}, "my-repo")
	if err != nil {
		t.Errorf("expected admin write to succeed, got err=%v", err)
	}
	err = authorizer.Authorize(ctx, "walden_admin", auth.Actions{Create: true}, "my-repo")
	if err != nil {
		t.Errorf("expected admin create to succeed, got err=%v", err)
	}

	// Reader token
	err = authorizer.Authorize(ctx, "walden_reader", auth.Actions{Read: true}, "blog-posts")
	if err != nil {
		t.Errorf("expected reader read on blog-posts to succeed, got err=%v", err)
	}
	err = authorizer.Authorize(ctx, "walden_reader", auth.Actions{Write: true}, "blog-posts")
	if !errors.Is(err, auth.ErrForbidden) {
		t.Errorf("expected forbidden for reader write, got err=%v", err)
	}
	err = authorizer.Authorize(ctx, "walden_reader", auth.Actions{Read: true}, "other-repo")
	if !errors.Is(err, auth.ErrForbidden) {
		t.Errorf("expected forbidden for reader on other-repo, got err=%v", err)
	}

	// Revoked token
	err = authorizer.Authorize(ctx, "walden_revoked", auth.Actions{Read: true}, "my-repo")
	if !errors.Is(err, auth.ErrUnauthorized) {
		t.Errorf("expected unauthorized for revoked token, got err=%v", err)
	}

	// Nonexistent token
	err = authorizer.Authorize(ctx, "walden_unknown", auth.Actions{Read: true}, "my-repo")
	if !errors.Is(err, auth.ErrUnauthorized) {
		t.Errorf("expected unauthorized for unknown token, got err=%v", err)
	}

	// Empty token
	err = authorizer.Authorize(ctx, "", auth.Actions{Read: true}, "my-repo")
	if !errors.Is(err, auth.ErrUnauthorized) {
		t.Errorf("expected unauthorized for empty token, got err=%v", err)
	}

	// Invalid repo ID
	err = authorizer.Authorize(ctx, "walden_admin", auth.Actions{Read: true}, "repo/with/slash")
	if !errors.Is(err, auth.ErrInvalidRepo) {
		t.Errorf("expected invalid repo error, got err=%v", err)
	}
}

func TestMemoryTokenStoreConcurrent(t *testing.T) {
	ctx := context.Background()
	store := auth.NewMemoryTokenStore()
	authorizer := auth.NewBuiltinAuthorizer(store)

	const numWorkers = 16
	const iterations = 50

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	for w := 0; w < numWorkers; w++ {
		workerID := w
		go func() {
			defer wg.Done()
			tokenID := fmt.Sprintf("tok_worker_%d", workerID)
			rawToken := fmt.Sprintf("walden_token_worker_%d", workerID)
			tokenHash := auth.HashToken(rawToken)
			scopes, _ := auth.ParseScopes([]string{"rwc:*"})

			for i := 0; i < iterations; i++ {
				// Create (a duplicate after the first iteration, which CreateToken refuses;
				// the point here is exercising concurrent access, not the create itself)
				_ = store.CreateToken(ctx, &auth.TokenRecord{
					TokenID:   tokenID,
					TokenHash: tokenHash,
					Scopes:    scopes,
					CreatedAt: time.Now().UTC(),
				})

				// Read & Authorize
				rec, _ := store.GetTokenByHash(ctx, tokenHash)
				if rec != nil && len(rec.Scopes) > 0 {
					// Mutating local slice must not affect store
					rec.Scopes[0].Pattern = "mutated"
				}

				_ = authorizer.Authorize(ctx, rawToken, auth.Actions{Read: true}, "repo-alpha")

				// List
				_, _ = store.ListTokens(ctx)

				// Revoke
				if i%2 == 0 {
					_ = store.RevokeToken(ctx, tokenID, time.Now().UTC())
				}
			}
		}()
	}

	wg.Wait()
}

func TestBuiltinAuthorizerNilStore(t *testing.T) {
	ctx := context.Background()
	authorizer := auth.NewBuiltinAuthorizer(nil)

	// NewBuiltinAuthorizer(nil) initializes an empty MemoryTokenStore
	err := authorizer.Authorize(ctx, "walden_nonexistent", auth.Actions{Read: true}, "repo-alpha")
	if !errors.Is(err, auth.ErrUnauthorized) {
		t.Errorf("expected unauthorized for nonexistent token with default store, got err=%v", err)
	}
}

// TestGetTokenByIDNotFound proves both TokenStore implementations refuse an unknown token ID
// under ErrTokenNotFound rather than returning (nil, nil). ErrTokenNotFound's doc comment
// names GetTokenByID as a path that returns it, and WALD-53's CLI is the caller about to
// build an errors.Is branch on that promise — a (nil, nil) return would make that branch
// unreachable and the next line a nil dereference.
func TestGetTokenByIDNotFound(t *testing.T) {
	ctx := context.Background()

	t.Run("MemoryTokenStore", func(t *testing.T) {
		store := auth.NewMemoryTokenStore()

		rec, err := store.GetTokenByID(ctx, "tok_missing")
		checkSingleLineRefusal(t, err, auth.ErrTokenNotFound)
		if rec != nil {
			t.Errorf("GetTokenByID(unknown) = %+v, want nil", rec)
		}

		scopes, _ := auth.ParseScopes([]string{"rwc:*"})
		if err := store.CreateToken(ctx, &auth.TokenRecord{
			TokenID:   "tok_known",
			TokenHash: auth.HashToken("walden_get_by_id_known"),
			Scopes:    scopes,
			CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("CreateToken: %v", err)
		}
		got, err := store.GetTokenByID(ctx, "tok_known")
		if err != nil {
			t.Fatalf("GetTokenByID(known): %v", err)
		}
		if got == nil || got.TokenID != "tok_known" {
			t.Errorf("GetTokenByID(known) = %+v, want tok_known", got)
		}
	})

	t.Run("FileTokenStore", func(t *testing.T) {
		dir := t.TempDir()
		store := auth.NewFileTokenStore(dir)

		rec, err := store.GetTokenByID(ctx, "tok_missing")
		checkSingleLineRefusal(t, err, auth.ErrTokenNotFound)
		if rec != nil {
			t.Errorf("GetTokenByID(unknown) = %+v, want nil", rec)
		}

		scopes, _ := auth.ParseScopes([]string{"rwc:*"})
		if err := store.CreateToken(ctx, &auth.TokenRecord{
			TokenID:   "tok_known",
			TokenHash: auth.HashToken("walden_get_by_id_known_file"),
			Scopes:    scopes,
			CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("CreateToken: %v", err)
		}
		got, err := store.GetTokenByID(ctx, "tok_known")
		if err != nil {
			t.Fatalf("GetTokenByID(known): %v", err)
		}
		if got == nil || got.TokenID != "tok_known" {
			t.Errorf("GetTokenByID(known) = %+v, want tok_known", got)
		}
	})
}

func TestEnsureAdminToken(t *testing.T) {
	ctx := context.Background()

	t.Run("nil store returns refusal with ErrStoreUnavailable", func(t *testing.T) {
		token, err := auth.EnsureAdminToken(ctx, nil, nil)
		if token != "" {
			t.Errorf("expected empty token for nil store, got %q", token)
		}
		checkSingleLineRefusal(t, err, auth.ErrStoreUnavailable)
	})

	t.Run("empty memory store mints admin token and grants rwc", func(t *testing.T) {
		store := auth.NewMemoryTokenStore()
		token, err := auth.EnsureAdminToken(ctx, store, nil)
		if err != nil {
			t.Fatalf("EnsureAdminToken failed: %v", err)
		}
		if !strings.HasPrefix(token, auth.TokenPrefix) {
			t.Fatalf("expected token prefix %q, got %q", auth.TokenPrefix, token)
		}

		rec, err := store.GetTokenByID(ctx, auth.AdminTokenID)
		if err != nil {
			t.Fatalf("GetTokenByID(%q) failed: %v", auth.AdminTokenID, err)
		}
		if rec == nil {
			t.Fatalf("expected admin token record, got nil")
		}
		if rec.TokenID != auth.AdminTokenID {
			t.Errorf("token ID = %q, want %q", rec.TokenID, auth.AdminTokenID)
		}
		if rec.TokenHash != auth.HashToken(token) {
			t.Errorf("token hash %q does not match hash of %q", rec.TokenHash, token)
		}
		if rec.Revoked {
			t.Errorf("admin token should not be revoked")
		}
		if len(rec.Scopes) != 1 || rec.Scopes[0].String() != "rwc:*" {
			t.Errorf("admin token scopes = %v, want [rwc:*]", rec.Scopes)
		}

		// Verify that the minted token grants Read, Write, and Create on arbitrary repos
		authorizer := auth.NewBuiltinAuthorizer(store)
		repos := []string{"repo-1", "org-repo", "any.git"}
		for _, repo := range repos {
			if err := authorizer.Authorize(ctx, token, auth.Actions{Read: true}, repo); err != nil {
				t.Errorf("expected read on %q to be authorized, got %v", repo, err)
			}
			if err := authorizer.Authorize(ctx, token, auth.Actions{Write: true}, repo); err != nil {
				t.Errorf("expected write on %q to be authorized, got %v", repo, err)
			}
			if err := authorizer.Authorize(ctx, token, auth.Actions{Create: true}, repo); err != nil {
				t.Errorf("expected create on %q to be authorized, got %v", repo, err)
			}
			if err := authorizer.Authorize(ctx, token, auth.Actions{Read: true, Write: true, Create: true}, repo); err != nil {
				t.Errorf("expected rwc on %q to be authorized, got %v", repo, err)
			}
		}

		// Second call on the same store returns "" and adds no tokens
		token2, err := auth.EnsureAdminToken(ctx, store, nil)
		if err != nil {
			t.Fatalf("second EnsureAdminToken call failed: %v", err)
		}
		if token2 != "" {
			t.Errorf("second call returned token %q, want empty", token2)
		}
		tokens, err := store.ListTokens(ctx)
		if err != nil {
			t.Fatalf("ListTokens failed: %v", err)
		}
		if len(tokens) != 1 {
			t.Errorf("expected 1 token in store after second call, got %d", len(tokens))
		}
	})

	t.Run("empty file store mints admin token and second call is no-op", func(t *testing.T) {
		dir := t.TempDir()
		store := auth.NewFileTokenStore(dir)
		token, err := auth.EnsureAdminToken(ctx, store, nil)
		if err != nil {
			t.Fatalf("EnsureAdminToken on file store failed: %v", err)
		}
		if !strings.HasPrefix(token, auth.TokenPrefix) {
			t.Fatalf("expected token prefix %q, got %q", auth.TokenPrefix, token)
		}

		rec, err := store.GetTokenByID(ctx, auth.AdminTokenID)
		if err != nil {
			t.Fatalf("GetTokenByID(%q) failed: %v", auth.AdminTokenID, err)
		}
		if rec.TokenHash != auth.HashToken(token) {
			t.Errorf("token hash %q does not match hash of %q", rec.TokenHash, token)
		}

		// Second call returns ""
		token2, err := auth.EnsureAdminToken(ctx, store, nil)
		if err != nil {
			t.Fatalf("second EnsureAdminToken call failed: %v", err)
		}
		if token2 != "" {
			t.Errorf("second call returned %q, want empty", token2)
		}
	})

	t.Run("store with existing active token does not mint admin token", func(t *testing.T) {
		store := auth.NewMemoryTokenStore()
		scopes, _ := auth.ParseScopes([]string{"rw:*"})
		_ = store.CreateToken(ctx, &auth.TokenRecord{
			TokenID:   "custom_token",
			TokenHash: auth.HashToken("walden_custom"),
			Scopes:    scopes,
			CreatedAt: time.Now().UTC(),
		})

		token, err := auth.EnsureAdminToken(ctx, store, nil)
		if err != nil {
			t.Fatalf("EnsureAdminToken failed: %v", err)
		}
		if token != "" {
			t.Errorf("expected empty token when tokens already exist, got %q", token)
		}
		_, err = store.GetTokenByID(ctx, auth.AdminTokenID)
		if !errors.Is(err, auth.ErrTokenNotFound) {
			t.Errorf("expected ErrTokenNotFound for admin token, got %v", err)
		}
	})

	t.Run("store with existing revoked token does not mint admin token", func(t *testing.T) {
		store := auth.NewMemoryTokenStore()
		scopes, _ := auth.ParseScopes([]string{"rw:*"})
		_ = store.CreateToken(ctx, &auth.TokenRecord{
			TokenID:   "revoked_token",
			TokenHash: auth.HashToken("walden_revoked"),
			Scopes:    scopes,
			CreatedAt: time.Now().UTC(),
		})
		_ = store.RevokeToken(ctx, "revoked_token", time.Now().UTC())

		token, err := auth.EnsureAdminToken(ctx, store, nil)
		if err != nil {
			t.Fatalf("EnsureAdminToken failed: %v", err)
		}
		if token != "" {
			t.Errorf("expected empty token when revoked token exists, got %q", token)
		}
		_, err = store.GetTokenByID(ctx, auth.AdminTokenID)
		if !errors.Is(err, auth.ErrTokenNotFound) {
			t.Errorf("expected ErrTokenNotFound for admin token, got %v", err)
		}
	})

	t.Run("lost race ErrTokenExists returns empty token without error", func(t *testing.T) {
		store := &raceMockStore{MemoryTokenStore: auth.NewMemoryTokenStore()}
		token, err := auth.EnsureAdminToken(ctx, store, nil)
		if err != nil {
			t.Fatalf("EnsureAdminToken failed on lost race: %v", err)
		}
		if token != "" {
			t.Errorf("expected empty token on lost race, got %q", token)
		}
	})

	t.Run("journalFn is called before store.CreateToken, with the built record", func(t *testing.T) {
		store := auth.NewMemoryTokenStore()
		var journaled *auth.TokenRecord
		journalFn := func(_ context.Context, rec *auth.TokenRecord) error {
			journaled = rec
			// The record must not be on disk yet when journalFn runs: journal
			// first, disk second (WALD-33).
			if _, err := store.GetTokenByID(ctx, auth.AdminTokenID); !errors.Is(err, auth.ErrTokenNotFound) {
				t.Errorf("store already holds the admin token when journalFn ran: err = %v", err)
			}
			return nil
		}

		token, err := auth.EnsureAdminToken(ctx, store, journalFn)
		if err != nil {
			t.Fatalf("EnsureAdminToken failed: %v", err)
		}
		if token == "" {
			t.Fatal("expected a minted token")
		}
		if journaled == nil {
			t.Fatal("journalFn was never called")
		}
		if journaled.TokenID != auth.AdminTokenID {
			t.Errorf("journaled record token id = %q, want %q", journaled.TokenID, auth.AdminTokenID)
		}
		if journaled.TokenHash != auth.HashToken(token) {
			t.Errorf("journaled record hash %q does not match hash of minted token %q", journaled.TokenHash, token)
		}

		rec, err := store.GetTokenByID(ctx, auth.AdminTokenID)
		if err != nil {
			t.Fatalf("GetTokenByID after EnsureAdminToken failed: %v", err)
		}
		if rec.TokenHash != journaled.TokenHash {
			t.Errorf("disk record hash %q does not match journaled hash %q", rec.TokenHash, journaled.TokenHash)
		}
	})

	t.Run("journalFn error is returned unchanged and nothing is persisted", func(t *testing.T) {
		store := auth.NewMemoryTokenStore()
		journalErr := errors.New("journal append refused")
		journalFn := func(context.Context, *auth.TokenRecord) error {
			return journalErr
		}

		token, err := auth.EnsureAdminToken(ctx, store, journalFn)
		if token != "" {
			t.Errorf("expected empty token when journalFn fails, got %q", token)
		}
		if !errors.Is(err, journalErr) {
			t.Errorf("expected journalFn's error to be returned unchanged, got %v", err)
		}
		tokens, listErr := store.ListTokens(ctx)
		if listErr != nil {
			t.Fatalf("ListTokens failed: %v", listErr)
		}
		if len(tokens) != 0 {
			t.Errorf("expected no tokens persisted after journalFn failure, got %d", len(tokens))
		}
	})

	// TestEnsureAdminToken/journalFn_ErrTokenExists_is_swallowed... covers
	// round 1 finding 1 on WALD-33 at the auth-layer unit: a journalFn
	// that reports the journal already carries AdminTokenID (the shape
	// cmd/walden/main.go's own journalFn now returns when its
	// ReplayMetaTable pre-check finds the row) must not be treated as a
	// boot failure. Before the fix, EnsureAdminToken returned every
	// journalFn error unchanged, including this one — which, reproduced
	// end to end in cmd/walden's TestServeSecondBootWithLostTokensJSON...,
	// is exactly the sequence that let a lost tokens.json between two
	// boots append a second token_create for the constant id "admin" and
	// poison every future replay. This test pins the fix at the
	// package's own boundary, independent of any store or journal
	// client: store.CreateToken must never be reached.
	t.Run("journalFn ErrTokenExists is swallowed like a lost race, and store is never touched", func(t *testing.T) {
		store := &createSpyStore{MemoryTokenStore: auth.NewMemoryTokenStore()}
		journalFn := func(context.Context, *auth.TokenRecord) error {
			return fmt.Errorf("token id %q already exists in the journal: %w", auth.AdminTokenID, auth.ErrTokenExists)
		}

		token, err := auth.EnsureAdminToken(ctx, store, journalFn)
		if err != nil {
			t.Fatalf("expected journalFn's ErrTokenExists to be swallowed, got err = %v", err)
		}
		if token != "" {
			t.Errorf("expected empty token when journalFn reports ErrTokenExists, got %q", token)
		}
		if store.createCalls != 0 {
			t.Errorf("store.CreateToken was called %d times; want 0 (journal already holds this id, so disk must not gain a row the journal cannot agree with)", store.createCalls)
		}
	})
}

// createSpyStore counts CreateToken calls, so a test can prove
// EnsureAdminToken never reaches disk once journalFn has already refused.
type createSpyStore struct {
	*auth.MemoryTokenStore
	createCalls int
}

func (s *createSpyStore) CreateToken(ctx context.Context, record *auth.TokenRecord) error {
	s.createCalls++
	return s.MemoryTokenStore.CreateToken(ctx, record)
}

type raceMockStore struct {
	*auth.MemoryTokenStore
}

func (r *raceMockStore) CreateToken(ctx context.Context, record *auth.TokenRecord) error {
	return auth.ErrTokenExists
}
