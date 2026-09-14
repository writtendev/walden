package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/writtendev/walden/internal/refusal"
)

const (
	// TokenPrefix is the standard prefix for Walden built-in bearer tokens.
	TokenPrefix = "walden_"

	// HashPrefix is the prefix for SHA-256 token storage hashes.
	HashPrefix = "sha256:"
)

// TokenRecord represents a built-in token's stored metadata and permissions.
//
// It carries no json tags of its own. A FileTokenStore's on-disk encoding is written out
// explicitly as its own unexported type in filestore.go, so there is exactly one place a
// token record is turned into bytes, rather than this struct's tags and a store's encoding
// silently needing to agree.
type TokenRecord struct {
	TokenID   string
	TokenHash string
	Scopes    []Scope
	CreatedAt time.Time
	Revoked   bool
	RevokedAt *time.Time
}

// HashToken computes the deterministic storage hash for a raw bearer token: "sha256:<64-hex>".
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return HashPrefix + hex.EncodeToString(h[:])
}

// GenerateToken generates a cryptographically secure random bearer token and its SHA-256 storage hash.
func GenerateToken() (rawToken, tokenHash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("failed to generate random token bytes: %w", err)
	}
	rawToken = TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	tokenHash = HashToken(rawToken)
	return rawToken, tokenHash, nil
}

// TokenStore defines the storage interface for built-in token records. Its mutation
// vocabulary is one-to-one with the meta stream's token_create and token_revoke records
// (internal/journal/token.go), so a later journaling layer (WALD-33) can append the matching
// record and then call the matching mutation without either being rebuilt or re-read:
//
//   - CreateToken and RevokeToken are the only two mutations, and there is no upsert. A
//     create is always a create; a revoke only ever narrows. A journaling layer never has to
//     classify what just happened.
//   - Both take their timestamp as an input (CreateToken persists record.CreatedAt as given;
//     RevokeToken takes at) rather than reading the clock, so the journal record and the
//     disk record can carry the same instant.
//   - GetTokenByID makes a revoke addressable before it happens: a token_revoke record names
//     the token by id and hash, so a writer can build that record before mutating disk.
type TokenStore interface {
	GetTokenByHash(ctx context.Context, hash string) (*TokenRecord, error)
	GetTokenByID(ctx context.Context, tokenID string) (*TokenRecord, error)
	ListTokens(ctx context.Context) ([]*TokenRecord, error)
	// CreateToken adds a new token record, refusing (ErrTokenExists) rather than overwriting
	// when a record already exists with the same TokenID or TokenHash.
	CreateToken(ctx context.Context, record *TokenRecord) error
	// RevokeToken marks the token identified by tokenID as revoked at the given instant.
	// It refuses an unknown tokenID (ErrTokenNotFound) and an already-revoked one
	// (ErrTokenAlreadyRevoked) rather than treating either as a no-op.
	RevokeToken(ctx context.Context, tokenID string, at time.Time) error
}

// MemoryTokenStore is a thread-safe in-memory implementation of TokenStore.
type MemoryTokenStore struct {
	mu     sync.RWMutex
	byHash map[string]*TokenRecord
	byID   map[string]*TokenRecord
}

// NewMemoryTokenStore creates a new empty MemoryTokenStore.
func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{
		byHash: make(map[string]*TokenRecord),
		byID:   make(map[string]*TokenRecord),
	}
}

// GetTokenByHash retrieves a token record by its SHA-256 hash.
func (m *MemoryTokenStore) GetTokenByHash(ctx context.Context, hash string) (*TokenRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.byHash[hash]
	if !ok || rec == nil {
		return nil, nil
	}
	cp := *rec
	if rec.Scopes != nil {
		cp.Scopes = make([]Scope, len(rec.Scopes))
		copy(cp.Scopes, rec.Scopes)
	}
	return &cp, nil
}

// GetTokenByID retrieves a token record by its token ID, refusing under ErrTokenNotFound if
// no record carries it — see that sentinel's doc comment in auth.go.
func (m *MemoryTokenStore) GetTokenByID(ctx context.Context, tokenID string) (*TokenRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.byID[tokenID]
	if !ok || rec == nil {
		return nil, refusal.RefuseWithCause(
			"token lookup refused",
			fmt.Sprintf("no token with id %q exists", tokenID),
			"verify the token id with 'walden token list'",
			ErrTokenNotFound,
		)
	}
	cp := *rec
	if rec.Scopes != nil {
		cp.Scopes = make([]Scope, len(rec.Scopes))
		copy(cp.Scopes, rec.Scopes)
	}
	return &cp, nil
}

// CreateToken adds a new token record. It refuses rather than overwrites when a record
// already exists with the same TokenID or TokenHash, so a create is always a create — never
// an upsert a caller must infer from success alone. record.CreatedAt is persisted as given;
// CreateToken never calls time.Now.
func (m *MemoryTokenStore) CreateToken(ctx context.Context, record *TokenRecord) error {
	if record == nil {
		return refusal.Refuse("token create refused", "record is nil", "pass a non-nil token record")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.byID[record.TokenID]; exists {
		return refusal.RefuseWithCause(
			"token create refused",
			fmt.Sprintf("token id %q already exists", record.TokenID),
			"choose a different token id",
			ErrTokenExists,
		)
	}
	if _, exists := m.byHash[record.TokenHash]; exists {
		return refusal.RefuseWithCause(
			"token create refused",
			"a token with this hash already exists",
			"generate a new token rather than reusing a hash",
			ErrTokenExists,
		)
	}
	cp := *record
	if record.Scopes != nil {
		cp.Scopes = make([]Scope, len(record.Scopes))
		copy(cp.Scopes, record.Scopes)
	}
	m.byHash[record.TokenHash] = &cp
	m.byID[record.TokenID] = &cp
	return nil
}

// RevokeToken marks a token as revoked by its token ID, at the given instant. Revoking an
// unknown token ID is refused (ErrTokenNotFound); revoking an already-revoked token is
// refused too (ErrTokenAlreadyRevoked) rather than treated as a no-op — see the sentinel's
// doc comment in auth.go. RevokeToken never calls time.Now; at is the caller's, for the same
// journaling reason CreateToken takes CreatedAt as given.
func (m *MemoryTokenStore) RevokeToken(ctx context.Context, tokenID string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.byID[tokenID]
	if !ok || rec == nil {
		return refusal.RefuseWithCause(
			"token revoke refused",
			fmt.Sprintf("no token with id %q exists", tokenID),
			"verify token id with 'walden token list'",
			ErrTokenNotFound,
		)
	}
	if rec.Revoked {
		return refusal.RefuseWithCause(
			"token revoke refused",
			fmt.Sprintf("token id %q is already revoked", tokenID),
			"no action needed; the token is already inactive",
			ErrTokenAlreadyRevoked,
		)
	}
	revokedAt := at.UTC()
	updated := *rec
	if rec.Scopes != nil {
		updated.Scopes = make([]Scope, len(rec.Scopes))
		copy(updated.Scopes, rec.Scopes)
	}
	updated.Revoked = true
	updated.RevokedAt = &revokedAt
	m.byID[tokenID] = &updated
	m.byHash[rec.TokenHash] = &updated
	return nil
}

// ListTokens returns all token records.
func (m *MemoryTokenStore) ListTokens(ctx context.Context) ([]*TokenRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := make([]*TokenRecord, 0, len(m.byID))
	for _, rec := range m.byID {
		if rec == nil {
			continue
		}
		cp := *rec
		if rec.Scopes != nil {
			cp.Scopes = make([]Scope, len(rec.Scopes))
			copy(cp.Scopes, rec.Scopes)
		}
		list = append(list, &cp)
	}
	return list, nil
}

// BuiltinAuthorizer evaluates access requests against built-in tokens in a TokenStore.
type BuiltinAuthorizer struct {
	store TokenStore
}

// NewBuiltinAuthorizer creates a new BuiltinAuthorizer.
func NewBuiltinAuthorizer(store TokenStore) *BuiltinAuthorizer {
	if store == nil {
		store = NewMemoryTokenStore()
	}
	return &BuiltinAuthorizer{store: store}
}

// Authorize checks whether the token grants every action in required on repo.
func (b *BuiltinAuthorizer) Authorize(ctx context.Context, token string, required Actions, repo string) error {
	if b == nil || b.store == nil {
		return refusal.RefuseWithCause(
			"unauthorized",
			"token store not available",
			"initialize token store before checking authorization",
			ErrUnauthorized,
		)
	}

	if err := checkRequired(required); err != nil {
		return err
	}

	if err := CheckRepoAndToken(token, repo); err != nil {
		return err
	}

	hash := HashToken(strings.TrimSpace(token))
	record, err := b.store.GetTokenByHash(ctx, hash)
	if err != nil {
		return err
	}

	if record == nil || record.Revoked {
		return refusal.RefuseWithCause(
			"unauthorized",
			"invalid or revoked token",
			"verify token credentials or mint a new token with 'walden token create'",
			ErrUnauthorized,
		)
	}

	if action, missing := Missing(record.Scopes, required, repo); missing {
		return ForbiddenRefusal(action, repo)
	}

	return nil
}
