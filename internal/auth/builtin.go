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
type TokenRecord struct {
	TokenID   string     `json:"token_id"`
	TokenHash string     `json:"token_hash"`
	Scopes    []Scope    `json:"scopes"`
	CreatedAt time.Time  `json:"created_at"`
	Revoked   bool       `json:"revoked"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
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

// TokenStore defines the storage interface for built-in token records.
type TokenStore interface {
	GetTokenByHash(ctx context.Context, hash string) (*TokenRecord, error)
	SaveToken(ctx context.Context, record *TokenRecord) error
	RevokeToken(ctx context.Context, tokenID string) error
	ListTokens(ctx context.Context) ([]*TokenRecord, error)
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
	if !ok {
		return nil, nil
	}
	return rec, nil
}

// SaveToken saves or updates a token record.
func (m *MemoryTokenStore) SaveToken(ctx context.Context, record *TokenRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byHash[record.TokenHash] = record
	m.byID[record.TokenID] = record
	return nil
}

// RevokeToken marks a token as revoked by its token ID.
func (m *MemoryTokenStore) RevokeToken(ctx context.Context, tokenID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.byID[tokenID]
	if !ok {
		return refusal.RefuseWithCause(
			"token not found",
			fmt.Sprintf("no token with ID %q exists", tokenID),
			"verify token ID with 'walden token list'",
			ErrUnauthorized,
		)
	}
	now := time.Now().UTC()
	rec.Revoked = true
	rec.RevokedAt = &now
	return nil
}

// ListTokens returns all token records.
func (m *MemoryTokenStore) ListTokens(ctx context.Context) ([]*TokenRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := make([]*TokenRecord, 0, len(m.byID))
	for _, rec := range m.byID {
		list = append(list, rec)
	}
	return list, nil
}

// BuiltinAuthorizer evaluates access requests against built-in tokens in a TokenStore.
type BuiltinAuthorizer struct {
	store TokenStore
}

// NewBuiltinAuthorizer creates a new BuiltinAuthorizer.
func NewBuiltinAuthorizer(store TokenStore) *BuiltinAuthorizer {
	return &BuiltinAuthorizer{store: store}
}

// Authorize checks whether the token grants action on repo.
func (b *BuiltinAuthorizer) Authorize(ctx context.Context, token string, action Action, repo string) (bool, error) {
	if err := CheckRepoAndToken(token, repo); err != nil {
		return false, err
	}

	hash := HashToken(strings.TrimSpace(token))
	record, err := b.store.GetTokenByHash(ctx, hash)
	if err != nil {
		return false, err
	}

	if record == nil || record.Revoked {
		return false, refusal.RefuseWithCause(
			"unauthorized",
			"invalid or revoked token",
			"verify token credentials or mint a new token with 'walden token create'",
			ErrUnauthorized,
		)
	}

	if !Allows(record.Scopes, action, repo) {
		return false, ForbiddenRefusal(action, repo)
	}

	return true, nil
}
