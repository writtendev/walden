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

	if err := store.SaveToken(ctx, rec); err != nil {
		t.Fatalf("SaveToken failed: %v", err)
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

	if err := store.RevokeToken(ctx, "tok_01"); err != nil {
		t.Fatalf("RevokeToken failed: %v", err)
	}

	revoked, err := store.GetTokenByHash(ctx, rec.TokenHash)
	if err != nil || !revoked.Revoked {
		t.Errorf("expected token to be revoked, got %+v", revoked)
	}

	err = store.RevokeToken(ctx, "nonexistent")
	if err == nil {
		t.Errorf("expected error revoking nonexistent token")
	}
}

func TestBuiltinAuthorizer(t *testing.T) {
	ctx := context.Background()
	store := auth.NewMemoryTokenStore()
	authorizer := auth.NewBuiltinAuthorizer(store)

	adminScopes, _ := auth.ParseScopes([]string{"rwc:*"})
	store.SaveToken(ctx, &auth.TokenRecord{
		TokenID:   "tok_admin",
		TokenHash: auth.HashToken("walden_admin"),
		Scopes:    adminScopes,
	})

	readerScopes, _ := auth.ParseScopes([]string{"r:blog-*"})
	store.SaveToken(ctx, &auth.TokenRecord{
		TokenID:   "tok_reader",
		TokenHash: auth.HashToken("walden_reader"),
		Scopes:    readerScopes,
	})

	revokedScopes, _ := auth.ParseScopes([]string{"rwc:*"})
	store.SaveToken(ctx, &auth.TokenRecord{
		TokenID:   "tok_revoked",
		TokenHash: auth.HashToken("walden_revoked"),
		Scopes:    revokedScopes,
		Revoked:   true,
	})

	// Admin token
	ok, err := authorizer.Authorize(ctx, "walden_admin", auth.ActionRead, "my-repo")
	if !ok || err != nil {
		t.Errorf("expected admin read to succeed, got ok=%v, err=%v", ok, err)
	}
	ok, err = authorizer.Authorize(ctx, "walden_admin", auth.ActionWrite, "my-repo")
	if !ok || err != nil {
		t.Errorf("expected admin write to succeed, got ok=%v, err=%v", ok, err)
	}
	ok, err = authorizer.Authorize(ctx, "walden_admin", auth.ActionCreate, "my-repo")
	if !ok || err != nil {
		t.Errorf("expected admin create to succeed, got ok=%v, err=%v", ok, err)
	}

	// Reader token
	ok, err = authorizer.Authorize(ctx, "walden_reader", auth.ActionRead, "blog-posts")
	if !ok || err != nil {
		t.Errorf("expected reader read on blog-posts to succeed, got ok=%v, err=%v", ok, err)
	}
	ok, err = authorizer.Authorize(ctx, "walden_reader", auth.ActionWrite, "blog-posts")
	if ok || !errors.Is(err, auth.ErrForbidden) {
		t.Errorf("expected forbidden for reader write, got ok=%v, err=%v", ok, err)
	}
	ok, err = authorizer.Authorize(ctx, "walden_reader", auth.ActionRead, "other-repo")
	if ok || !errors.Is(err, auth.ErrForbidden) {
		t.Errorf("expected forbidden for reader on other-repo, got ok=%v, err=%v", ok, err)
	}

	// Revoked token
	ok, err = authorizer.Authorize(ctx, "walden_revoked", auth.ActionRead, "my-repo")
	if ok || !errors.Is(err, auth.ErrUnauthorized) {
		t.Errorf("expected unauthorized for revoked token, got ok=%v, err=%v", ok, err)
	}

	// Nonexistent token
	ok, err = authorizer.Authorize(ctx, "walden_unknown", auth.ActionRead, "my-repo")
	if ok || !errors.Is(err, auth.ErrUnauthorized) {
		t.Errorf("expected unauthorized for unknown token, got ok=%v, err=%v", ok, err)
	}

	// Empty token
	ok, err = authorizer.Authorize(ctx, "", auth.ActionRead, "my-repo")
	if ok || !errors.Is(err, auth.ErrUnauthorized) {
		t.Errorf("expected unauthorized for empty token, got ok=%v, err=%v", ok, err)
	}

	// Invalid repo ID
	ok, err = authorizer.Authorize(ctx, "walden_admin", auth.ActionRead, "repo/with/slash")
	if ok || !errors.Is(err, auth.ErrInvalidRepo) {
		t.Errorf("expected invalid repo error, got ok=%v, err=%v", ok, err)
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
				// Save
				_ = store.SaveToken(ctx, &auth.TokenRecord{
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

				_, _ = authorizer.Authorize(ctx, rawToken, auth.ActionRead, "repo-alpha")

				// List
				_, _ = store.ListTokens(ctx)

				// Revoke
				if i%2 == 0 {
					_ = store.RevokeToken(ctx, tokenID)
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
	ok, err := authorizer.Authorize(ctx, "walden_nonexistent", auth.ActionRead, "repo-alpha")
	if ok || !errors.Is(err, auth.ErrUnauthorized) {
		t.Errorf("expected unauthorized for nonexistent token with default store, got ok=%v, err=%v", ok, err)
	}
}
