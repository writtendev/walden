package journal

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	// RecordTypeTokenCreate identifies a token creation record in the meta stream.
	RecordTypeTokenCreate = "token_create"

	// RecordTypeTokenRevoke identifies a token revocation record in the meta stream.
	RecordTypeTokenRevoke = "token_revoke"

	// TokenHashPrefix is the required prefix for the stored hash of a built-in token.
	TokenHashPrefix = "sha256:"
)

// ErrInvalidTokenRecord indicates a malformed token_create or token_revoke record.
var ErrInvalidTokenRecord = errors.New("invalid token record")

// ErrInvalidTokenID indicates a token identifier that is not a token identifier.
var ErrInvalidTokenID = errors.New("invalid token id")

// ErrInvalidTokenHash indicates a stored token hash that is not "sha256:<64-lowercase-hex>".
var ErrInvalidTokenHash = errors.New("invalid token hash")

var tokenIDRegexp = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

var tokenHashHexRegexp = regexp.MustCompile(`^[0-9a-f]{64}$`)

// TokenCreateRecord represents the creation of a built-in token on the _meta stream.
//
// It carries the hash the server stores and the scopes the token was minted with, because
// those two are the whole of a built-in token: a replay that has read this record can put
// the token back into the table it looks up on every request, which is what makes restoring
// from the journal restore the tokens too.
//
// It is deliberately not an identity record. There is no account here, no owner, no email
// and no expiry — a token id, a hash, and what the token may touch. The layer above walden
// may know who holds this token; walden does not, and this record is not where that changes.
//
// It carries no signature in v1, which spec/journal/v1 names as the one exception to the
// tamper-evidence of section 2.2: a party with bucket write access can append one of these
// and a replay rebuilds it as a live grant. Giving both token record types a canonical
// payload and a signature is WALD-104. The spec states the gap without the ticket id,
// because it is published for reimplementers who cannot resolve one.
type TokenCreateRecord struct {
	Version   string   `json:"version"`
	Stream    StreamID `json:"stream"`
	Seq       Seq      `json:"seq"`
	Type      string   `json:"type"`
	TokenID   string   `json:"token_id"`
	TokenHash string   `json:"token_hash"`
	Scopes    []string `json:"scopes"`
	Timestamp string   `json:"timestamp"`
}

// TokenRevokeRecord represents the revocation of a built-in token on the _meta stream.
//
// It names the token twice, by id and by hash. The id is what a replay matches on; the hash
// is the same value the creating record carried, repeated so that a revocation is legible
// against the table a server actually keys — which is the hash — and so that a revocation
// that has drifted from the record it revokes is visible rather than silently applied. A
// revocation carries no scopes: it withdraws a grant, it does not describe one.
//
// Like TokenCreateRecord it carries no signature in v1; see the note there and WALD-104.
type TokenRevokeRecord struct {
	Version   string   `json:"version"`
	Stream    StreamID `json:"stream"`
	Seq       Seq      `json:"seq"`
	Type      string   `json:"type"`
	TokenID   string   `json:"token_id"`
	TokenHash string   `json:"token_hash"`
	Timestamp string   `json:"timestamp"`
}

// ValidateTokenID validates a token identifier: the same character class a stream ID uses,
// so an identifier is safe in an object key, a log line, and a one-line refusal unescaped.
func ValidateTokenID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: cannot be empty", ErrInvalidTokenID)
	}
	if len(id) > 255 {
		return fmt.Errorf("%w: length %d exceeds maximum of 255 bytes", ErrInvalidTokenID, len(id))
	}
	if !tokenIDRegexp.MatchString(id) {
		return fmt.Errorf("%w: must contain only [a-zA-Z0-9._-], got %q", ErrInvalidTokenID, id)
	}
	return nil
}

// ValidateTokenHash validates a stored token hash: "sha256:" followed by 64 lowercase
// hexadecimal characters. Uppercase is refused rather than folded, because the hash is
// compared byte for byte against the one a request hashes to.
//
// Neither refusal here quotes the value it refused. The reason this check exists is that a
// writer may hand it a raw bearer token where the hash belongs, and a refusal that echoed it
// would put the secret on the operator's terminal, in the server log, and in whatever
// aggregates that log — the one place it must never reach is exactly where the refusal goes.
// The length and the failing rule are enough to find the bug. An identifier is not a secret
// and ValidateTokenID quotes it; a hash-shaped field may be a live credential and this does
// not.
func ValidateTokenHash(hash string) error {
	if !strings.HasPrefix(hash, TokenHashPrefix) {
		return fmt.Errorf("%w: missing prefix %q in a %d-byte value (value withheld: it may be a raw token)", ErrInvalidTokenHash, TokenHashPrefix, len(hash))
	}
	hexStr := strings.TrimPrefix(hash, TokenHashPrefix)
	if !tokenHashHexRegexp.MatchString(hexStr) {
		return fmt.Errorf("%w: must be 64 lowercase hexadecimal characters after %q, got %d bytes that are not (value withheld: it may be a raw token)", ErrInvalidTokenHash, TokenHashPrefix, len(hexStr))
	}
	return nil
}

// Validate validates that a TokenCreateRecord is well-formed.
func (r *TokenCreateRecord) Validate() error {
	if r == nil {
		return fmt.Errorf("%w: record cannot be nil", ErrInvalidTokenRecord)
	}
	if err := validateTokenHeader(r.Version, r.Stream, r.Seq, r.Type, RecordTypeTokenCreate); err != nil {
		return err
	}
	if err := ValidateTokenID(r.TokenID); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidTokenRecord, err)
	}
	if err := ValidateTokenHash(r.TokenHash); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidTokenRecord, err)
	}
	if len(r.Scopes) == 0 {
		return fmt.Errorf("%w: scopes must carry at least one scope", ErrInvalidTokenRecord)
	}
	seen := make(map[string]bool, len(r.Scopes))
	for i, scope := range r.Scopes {
		if scope == "" {
			return fmt.Errorf("%w: scopes[%d] cannot be empty", ErrInvalidTokenRecord, i)
		}
		if seen[scope] {
			return fmt.Errorf("%w: duplicate scope %q", ErrInvalidTokenRecord, scope)
		}
		seen[scope] = true
	}
	return validateTokenTimestamp(r.Timestamp)
}

// Validate validates that a TokenRevokeRecord is well-formed.
func (r *TokenRevokeRecord) Validate() error {
	if r == nil {
		return fmt.Errorf("%w: record cannot be nil", ErrInvalidTokenRecord)
	}
	if err := validateTokenHeader(r.Version, r.Stream, r.Seq, r.Type, RecordTypeTokenRevoke); err != nil {
		return err
	}
	if err := ValidateTokenID(r.TokenID); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidTokenRecord, err)
	}
	if err := ValidateTokenHash(r.TokenHash); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidTokenRecord, err)
	}
	return validateTokenTimestamp(r.Timestamp)
}

// validateTokenHeader checks the four fields both token records open with. Sequence zero
// belongs to genesis, so a token record cannot claim it.
func validateTokenHeader(version string, stream StreamID, seq Seq, gotType, wantType string) error {
	if version != VersionPrefix {
		return fmt.Errorf("%w: unsupported version %q (expected %q)", ErrInvalidTokenRecord, version, VersionPrefix)
	}
	if stream != MetaStreamID {
		return fmt.Errorf("%w: token records must be in meta stream %q, got %q", ErrInvalidTokenRecord, MetaStreamID, stream)
	}
	if seq == 0 {
		return fmt.Errorf("%w: sequence 0 is the genesis record, so a token record starts at 1", ErrInvalidTokenRecord)
	}
	if gotType != wantType {
		return fmt.Errorf("%w: expected type %q, got %q", ErrInvalidTokenRecord, wantType, gotType)
	}
	return nil
}

// validateTokenTimestamp checks an RFC 3339 UTC timestamp.
func validateTokenTimestamp(timestamp string) error {
	if timestamp == "" {
		return fmt.Errorf("%w: timestamp cannot be empty", ErrInvalidTokenRecord)
	}
	t, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return fmt.Errorf("%w: invalid timestamp %q (must be RFC 3339): %w", ErrInvalidTokenRecord, timestamp, err)
	}
	if !strings.HasSuffix(timestamp, "Z") && !strings.HasSuffix(timestamp, "+00:00") && !strings.HasSuffix(timestamp, "-00:00") {
		if t.Location() != time.UTC {
			return fmt.Errorf("%w: timestamp must be in UTC (got %q)", ErrInvalidTokenRecord, timestamp)
		}
	}
	return nil
}
