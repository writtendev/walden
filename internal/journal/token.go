package journal

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/writtendev/walden/internal/refusal"
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

// ErrInvalidTokenScope indicates a scope string that cannot appear in a token record because
// it could break the Canonical Token Creation Signing Payload's line-per-entry framing.
var ErrInvalidTokenScope = errors.New("invalid token scope")

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
// It carries a signature (WALD-104): an Ed25519 signature by the key active at this meta
// sequence, over CanonicalTokenCreatePayload. Unlike a ref-transaction record or a marker,
// it names no signing-key position of its own — see (*SigningChain).VerifyTokenCreate for
// why _meta's own contiguity makes that field unnecessary here.
type TokenCreateRecord struct {
	Version   string   `json:"version"`
	Stream    StreamID `json:"stream"`
	Seq       Seq      `json:"seq"`
	Type      string   `json:"type"`
	TokenID   string   `json:"token_id"`
	TokenHash string   `json:"token_hash"`
	Scopes    []string `json:"scopes"`
	Timestamp string   `json:"timestamp"`
	Signature string   `json:"signature"`
}

// TokenRevokeRecord represents the revocation of a built-in token on the _meta stream.
//
// It names the token twice, by id and by hash. The id is what a replay matches on; the hash
// is the same value the creating record carried, repeated so that a revocation is legible
// against the table a server actually keys — which is the hash — and so that a revocation
// that has drifted from the record it revokes is visible rather than silently applied. A
// revocation carries no scopes: it withdraws a grant, it does not describe one.
//
// Like TokenCreateRecord it carries a signature (WALD-104); see the note there and
// (*SigningChain).VerifyTokenRevoke.
type TokenRevokeRecord struct {
	Version   string   `json:"version"`
	Stream    StreamID `json:"stream"`
	Seq       Seq      `json:"seq"`
	Type      string   `json:"type"`
	TokenID   string   `json:"token_id"`
	TokenHash string   `json:"token_hash"`
	Timestamp string   `json:"timestamp"`
	Signature string   `json:"signature"`
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

// ValidateTokenScope validates a single entry of a TokenCreateRecord's scopes array: it must
// contain no ASCII control character (0x00-0x1F or 0x7F).
//
// The Canonical Token Creation Signing Payload (below) frames scopes one per line, each
// prefixed "scope:" and terminated by "\n" — the same idiom CanonicalRefUpdatePayload uses
// for ref names one "update:" line at a time. That idiom is safe there only because
// ValidateRefName refuses every control character, so a ref name can never smuggle in the
// "\n" the framing uses as its delimiter. Scopes had no equivalent: a scope string containing
// "\nscope:" could splice a second line into the payload, so a signature minted over one
// scope would verify unchanged for a record naming two, the second being whatever text
// followed the embedded delimiter. Banning control characters here closes that the same way
// ValidateRefName closes it for ref names — in the data, not in a caller.
func ValidateTokenScope(scope string) error {
	for i := 0; i < len(scope); i++ {
		if b := scope[i]; b <= 0x1F || b == 0x7F {
			return fmt.Errorf("%w: contains control character (byte 0x%02x): %q", ErrInvalidTokenScope, b, scope)
		}
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
		if err := ValidateTokenScope(scope); err != nil {
			return fmt.Errorf("%w: scopes[%d]: %w", ErrInvalidTokenRecord, i, err)
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

// CanonicalTokenCreatePayload returns the deterministic canonical byte payload to
// sign/verify for a TokenCreateRecord, styled on CanonicalMarkerPayload. Unlike
// CanonicalMarkerPayload and CanonicalRefUpdatePayload, token_hash is written verbatim,
// with no strings.ToLower: those two lowercase because ValidateOID accepts either case,
// which is exactly the signature malleability WALD-109 is filed against, and
// ValidateTokenHash already refuses a non-lowercase hash outright rather than folding it —
// lowercasing here would be a no-op that manufactures a second instance of the same defect.
// token_id, each scope string, and timestamp are likewise written verbatim.
//
// One "scope:" line is emitted per entry of scopes, so this framing is unambiguous only
// because ValidateTokenScope (enforced by TokenCreateRecord.Validate, which both
// SignTokenCreate and VerifyTokenCreate call before ever reaching this function) refuses a
// scope containing a control character — in particular the "\n" this framing delimits on.
// This function itself does not re-check that; it trusts its caller the same way
// CanonicalRefUpdatePayload trusts ValidateRefName to have already refused a ref name
// carrying the same character.
func CanonicalTokenCreatePayload(stream StreamID, seq Seq, tokenID, tokenHash string, scopes []string, timestamp string) []byte {
	var sb strings.Builder
	sb.WriteString("walden-token-create:v1\n")
	sb.WriteString("stream:")
	sb.WriteString(string(stream))
	sb.WriteByte('\n')
	sb.WriteString("seq:")
	sb.WriteString(seq.String())
	sb.WriteByte('\n')
	sb.WriteString("token_id:")
	sb.WriteString(tokenID)
	sb.WriteByte('\n')
	sb.WriteString("token_hash:")
	sb.WriteString(tokenHash)
	sb.WriteByte('\n')
	for _, scope := range scopes {
		sb.WriteString("scope:")
		sb.WriteString(scope)
		sb.WriteByte('\n')
	}
	sb.WriteString("timestamp:")
	sb.WriteString(timestamp)
	sb.WriteByte('\n')
	return []byte(sb.String())
}

// CanonicalTokenRevokePayload returns the deterministic canonical byte payload to
// sign/verify for a TokenRevokeRecord. See CanonicalTokenCreatePayload for why
// token_hash is written verbatim rather than lowercased.
func CanonicalTokenRevokePayload(stream StreamID, seq Seq, tokenID, tokenHash, timestamp string) []byte {
	var sb strings.Builder
	sb.WriteString("walden-token-revoke:v1\n")
	sb.WriteString("stream:")
	sb.WriteString(string(stream))
	sb.WriteByte('\n')
	sb.WriteString("seq:")
	sb.WriteString(seq.String())
	sb.WriteByte('\n')
	sb.WriteString("token_id:")
	sb.WriteString(tokenID)
	sb.WriteByte('\n')
	sb.WriteString("token_hash:")
	sb.WriteString(tokenHash)
	sb.WriteByte('\n')
	sb.WriteString("timestamp:")
	sb.WriteString(timestamp)
	sb.WriteByte('\n')
	return []byte(sb.String())
}

// SignTokenCreate signs a TokenCreateRecord using the server's Ed25519 private key.
func SignTokenCreate(priv ed25519.PrivateKey, r *TokenCreateRecord) error {
	if r == nil {
		return fmt.Errorf("%w: record cannot be nil", ErrInvalidTokenRecord)
	}
	if err := r.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidTokenRecord, err)
	}
	payload := CanonicalTokenCreatePayload(r.Stream, r.Seq, r.TokenID, r.TokenHash, r.Scopes, r.Timestamp)
	sig := ed25519.Sign(priv, payload)
	r.Signature = FormatSignature(sig)
	return nil
}

// SignTokenRevoke signs a TokenRevokeRecord using the server's Ed25519 private key.
func SignTokenRevoke(priv ed25519.PrivateKey, r *TokenRevokeRecord) error {
	if r == nil {
		return fmt.Errorf("%w: record cannot be nil", ErrInvalidTokenRecord)
	}
	if err := r.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidTokenRecord, err)
	}
	payload := CanonicalTokenRevokePayload(r.Stream, r.Seq, r.TokenID, r.TokenHash, r.Timestamp)
	sig := ed25519.Sign(priv, payload)
	r.Signature = FormatSignature(sig)
	return nil
}

// VerifyTokenCreate verifies that a TokenCreateRecord is well-formed and cryptographically
// valid against activePublicKey.
func VerifyTokenCreate(r *TokenCreateRecord, activePublicKey string) error {
	if r == nil {
		return fmt.Errorf("%w: record cannot be nil", ErrInvalidTokenRecord)
	}
	if err := r.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidTokenRecord, err)
	}
	if r.Signature == "" {
		return fmt.Errorf("%w: missing signature", ErrInvalidSignature)
	}
	pubKey, err := ParsePublicKey(activePublicKey)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	sigBytes, err := ParseSignature(r.Signature)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	payload := CanonicalTokenCreatePayload(r.Stream, r.Seq, r.TokenID, r.TokenHash, r.Scopes, r.Timestamp)
	if !ed25519.Verify(pubKey, payload, sigBytes) {
		return fmt.Errorf("%w: signature mismatch for token record at seq %d", ErrSignatureMismatch, r.Seq)
	}
	return nil
}

// VerifyTokenRevoke verifies that a TokenRevokeRecord is well-formed and cryptographically
// valid against activePublicKey.
func VerifyTokenRevoke(r *TokenRevokeRecord, activePublicKey string) error {
	if r == nil {
		return fmt.Errorf("%w: record cannot be nil", ErrInvalidTokenRecord)
	}
	if err := r.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidTokenRecord, err)
	}
	if r.Signature == "" {
		return fmt.Errorf("%w: missing signature", ErrInvalidSignature)
	}
	pubKey, err := ParsePublicKey(activePublicKey)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	sigBytes, err := ParseSignature(r.Signature)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	payload := CanonicalTokenRevokePayload(r.Stream, r.Seq, r.TokenID, r.TokenHash, r.Timestamp)
	if !ed25519.Verify(pubKey, payload, sigBytes) {
		return fmt.Errorf("%w: signature mismatch for token record at seq %d", ErrSignatureMismatch, r.Seq)
	}
	return nil
}

// VerifyTokenCreate verifies a token_create record against the key active at the meta
// sequence it was written to (c.ActiveKey()) — not against a signing-key position the
// record names itself, because a token record names none. _meta is the one stream that is
// never compacted: Marker.Validate refuses a meta-stream marker outright, and spec section
// 8 step 3 excludes _meta from the marker-bearing stream sweep by name, so it is always
// replayed contiguously from genesis. That makes a record's own sequence enough to fix the
// key that signed it — the key the most recent rotation this replay has applied activated
// — with no summarized history below it for a floor to protect, which is why this
// asymmetry against (*SigningChain).VerifyMarker and VerifyRefTx (both of which resolve a
// signing-key position the record names) is deliberate and not a gap to close. A signature
// that fails to verify against ActiveKey is refused with RefuseTokenSignatureMismatch (spec
// section 8.1 rule 19), not the raw package-level error. Callers still call AdvanceMetaSeq
// afterwards; this does not.
func (c *SigningChain) VerifyTokenCreate(r *TokenCreateRecord) error {
	if c == nil || !c.initialized {
		return fmt.Errorf("%w: cannot verify token record before genesis", ErrGenesisMissing)
	}
	if r == nil {
		return fmt.Errorf("%w: record cannot be nil", ErrInvalidTokenRecord)
	}
	if err := VerifyTokenCreate(r, c.ActiveKey()); err != nil {
		if errors.Is(err, ErrSignatureMismatch) {
			return RefuseTokenSignatureMismatch(r.Seq)
		}
		return err
	}
	return nil
}

// VerifyTokenRevoke verifies a token_revoke record against the key active at the meta
// sequence it was written to. See (*SigningChain).VerifyTokenCreate for why that is
// ActiveKey() rather than a signing-key position the record names itself, and why that is
// deliberate rather than a gap.
func (c *SigningChain) VerifyTokenRevoke(r *TokenRevokeRecord) error {
	if c == nil || !c.initialized {
		return fmt.Errorf("%w: cannot verify token record before genesis", ErrGenesisMissing)
	}
	if r == nil {
		return fmt.Errorf("%w: record cannot be nil", ErrInvalidTokenRecord)
	}
	if err := VerifyTokenRevoke(r, c.ActiveKey()); err != nil {
		if errors.Is(err, ErrSignatureMismatch) {
			return RefuseTokenSignatureMismatch(r.Seq)
		}
		return err
	}
	return nil
}

// RefuseTokenSignatureMismatch returns a single-line operator-facing refusal when a token
// record's signature does not verify against the key active at its meta sequence (spec
// section 8.1 rule 19).
func RefuseTokenSignatureMismatch(seq Seq) error {
	return refusal.RefuseWithCause(
		"refusal: replay failed",
		fmt.Sprintf("signature mismatch for token record at seq %d", seq),
		"",
		ErrSignatureMismatch,
	)
}

// tokenCreateShadow decodes a token_create record into pointer fields so that
// ParseTokenCreate can tell a field that is genuinely absent — signature above all, now
// that these records are signed — from one that decoded to its zero value, copying
// markerShadow's shape.
type tokenCreateShadow struct {
	Version   *string   `json:"version"`
	Stream    *StreamID `json:"stream"`
	Seq       *Seq      `json:"seq"`
	Type      *string   `json:"type"`
	TokenID   *string   `json:"token_id"`
	TokenHash *string   `json:"token_hash"`
	Scopes    *[]string `json:"scopes"`
	Timestamp *string   `json:"timestamp"`
	Signature *string   `json:"signature"`
}

// ParseTokenCreate parses and validates a token_create record's JSON bytes. A field that is
// genuinely absent — most importantly signature — is refused by name here, before Validate
// ever sees it and before it could decode to a zero value and pass silently.
func ParseTokenCreate(data []byte) (*TokenCreateRecord, error) {
	var shadow tokenCreateShadow
	if err := json.Unmarshal(data, &shadow); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTokenRecord, err)
	}
	missing := ""
	switch {
	case shadow.Version == nil:
		missing = "version"
	case shadow.Stream == nil:
		missing = "stream"
	case shadow.Seq == nil:
		missing = "seq"
	case shadow.Type == nil:
		missing = "type"
	case shadow.TokenID == nil:
		missing = "token_id"
	case shadow.TokenHash == nil:
		missing = "token_hash"
	case shadow.Scopes == nil:
		missing = "scopes"
	case shadow.Timestamp == nil:
		missing = "timestamp"
	case shadow.Signature == nil:
		missing = "signature"
	}
	if missing != "" {
		return nil, fmt.Errorf("%w: missing required field %q", ErrInvalidTokenRecord, missing)
	}
	r := &TokenCreateRecord{
		Version:   *shadow.Version,
		Stream:    *shadow.Stream,
		Seq:       *shadow.Seq,
		Type:      *shadow.Type,
		TokenID:   *shadow.TokenID,
		TokenHash: *shadow.TokenHash,
		Scopes:    *shadow.Scopes,
		Timestamp: *shadow.Timestamp,
		Signature: *shadow.Signature,
	}
	if err := r.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidTokenRecord, err)
	}
	return r, nil
}

// tokenRevokeShadow is tokenCreateShadow's counterpart for token_revoke records.
type tokenRevokeShadow struct {
	Version   *string   `json:"version"`
	Stream    *StreamID `json:"stream"`
	Seq       *Seq      `json:"seq"`
	Type      *string   `json:"type"`
	TokenID   *string   `json:"token_id"`
	TokenHash *string   `json:"token_hash"`
	Timestamp *string   `json:"timestamp"`
	Signature *string   `json:"signature"`
}

// ParseTokenRevoke parses and validates a token_revoke record's JSON bytes, under the same
// absent-field rule ParseTokenCreate applies.
func ParseTokenRevoke(data []byte) (*TokenRevokeRecord, error) {
	var shadow tokenRevokeShadow
	if err := json.Unmarshal(data, &shadow); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTokenRecord, err)
	}
	missing := ""
	switch {
	case shadow.Version == nil:
		missing = "version"
	case shadow.Stream == nil:
		missing = "stream"
	case shadow.Seq == nil:
		missing = "seq"
	case shadow.Type == nil:
		missing = "type"
	case shadow.TokenID == nil:
		missing = "token_id"
	case shadow.TokenHash == nil:
		missing = "token_hash"
	case shadow.Timestamp == nil:
		missing = "timestamp"
	case shadow.Signature == nil:
		missing = "signature"
	}
	if missing != "" {
		return nil, fmt.Errorf("%w: missing required field %q", ErrInvalidTokenRecord, missing)
	}
	r := &TokenRevokeRecord{
		Version:   *shadow.Version,
		Stream:    *shadow.Stream,
		Seq:       *shadow.Seq,
		Type:      *shadow.Type,
		TokenID:   *shadow.TokenID,
		TokenHash: *shadow.TokenHash,
		Timestamp: *shadow.Timestamp,
		Signature: *shadow.Signature,
	}
	if err := r.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidTokenRecord, err)
	}
	return r, nil
}
