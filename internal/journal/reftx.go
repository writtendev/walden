package journal

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	// RecordTypeRefUpdate identifies a ref transaction record.
	RecordTypeRefUpdate = "ref_update"
)

var (
	// ErrInvalidRefTx indicates an invalid ref transaction record structure.
	ErrInvalidRefTx = errors.New("invalid ref transaction record")

	// ErrInvalidRef indicates an invalid Git ref name.
	ErrInvalidRef = errors.New("invalid ref name")

	// ErrInvalidOID indicates an invalid Git object ID.
	ErrInvalidOID = errors.New("invalid object id")
)

var (
	oid40Regexp = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	oid64Regexp = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
)

// ZeroOID40 is the 40-hex zero object ID representing ref creation or deletion (SHA-1).
const ZeroOID40 = "0000000000000000000000000000000000000000"

// ZeroOID64 is the 64-hex zero object ID representing ref creation or deletion (SHA-256).
const ZeroOID64 = "0000000000000000000000000000000000000000000000000000000000000000"

// RefTransactionRecord represents a ref_update record on a stream carrying ref transitions and pack segments.
type RefTransactionRecord struct {
	Version   string      `json:"version"`
	Stream    StreamID    `json:"stream"`
	Seq       Seq         `json:"seq"`
	Type      string      `json:"type"`
	Segments  []string    `json:"segments"`
	Updates   []RefUpdate `json:"updates"`
	Timestamp string      `json:"timestamp"`
	Signature string      `json:"signature,omitempty"`
}

// ValidateOID validates that an object ID is a 40-hex (SHA-1) or 64-hex (SHA-256) string.
func ValidateOID(oid string) error {
	if len(oid) == 40 {
		if !oid40Regexp.MatchString(oid) {
			return fmt.Errorf("%w: sha1 oid must be 40 hexadecimal characters, got %q", ErrInvalidOID, oid)
		}
		return nil
	}
	if len(oid) == 64 {
		if !oid64Regexp.MatchString(oid) {
			return fmt.Errorf("%w: sha256 oid must be 64 hexadecimal characters, got %q", ErrInvalidOID, oid)
		}
		return nil
	}
	return fmt.Errorf("%w: oid must be 40 or 64 hex characters, got %d chars (%q)", ErrInvalidOID, len(oid), oid)
}

// ValidateRefName validates a Git ref name according to git-check-ref-format rules.
// Note: Git ref names are raw byte sequences. This validator enforces format invariants
// while preserving exact byte representation.
func ValidateRefName(ref string) error {
	if ref == "" {
		return fmt.Errorf("%w: cannot be empty", ErrInvalidRef)
	}
	if len(ref) > 4096 {
		return fmt.Errorf("%w: ref name exceeds 4096 bytes", ErrInvalidRef)
	}
	if ref == "@" {
		return fmt.Errorf("%w: ref name cannot be '@'", ErrInvalidRef)
	}
	if strings.HasPrefix(ref, "/") || strings.HasSuffix(ref, "/") {
		return fmt.Errorf("%w: leading or trailing slashes are not allowed: %q", ErrInvalidRef, ref)
	}
	if strings.Contains(ref, "//") {
		return fmt.Errorf("%w: consecutive slashes '//' are not allowed: %q", ErrInvalidRef, ref)
	}
	if strings.Contains(ref, "..") {
		return fmt.Errorf("%w: '..' sequences are not allowed: %q", ErrInvalidRef, ref)
	}
	if strings.Contains(ref, "@{") {
		return fmt.Errorf("%w: '@{' sequences are not allowed: %q", ErrInvalidRef, ref)
	}

	// Check components separated by '/'
	components := strings.Split(ref, "/")
	for _, comp := range components {
		if comp == "" {
			return fmt.Errorf("%w: empty component in ref: %q", ErrInvalidRef, ref)
		}
		if strings.HasPrefix(comp, ".") || strings.HasSuffix(comp, ".") {
			return fmt.Errorf("%w: component %q cannot begin or end with dot in ref %q", ErrInvalidRef, comp, ref)
		}
		if strings.HasSuffix(comp, ".lock") {
			return fmt.Errorf("%w: component %q cannot end with '.lock' in ref %q", ErrInvalidRef, comp, ref)
		}
	}

	// Check illegal characters: ASCII control characters (0x00-0x1F, 0x7F), space (0x20), ~, ^, :, ?, *, [, \
	for i := 0; i < len(ref); i++ {
		b := ref[i]
		if b <= 0x20 || b == 0x7F {
			return fmt.Errorf("%w: contains control character or whitespace (byte 0x%02x) in %q", ErrInvalidRef, b, ref)
		}
		switch b {
		case '~', '^', ':', '?', '*', '[', '\\':
			return fmt.Errorf("%w: contains illegal character %q in %q", ErrInvalidRef, string(b), ref)
		}
	}

	return nil
}

// ValidateRefUpdate validates a single ref update triple.
func ValidateRefUpdate(u RefUpdate) error {
	if err := ValidateRefName(u.Ref); err != nil {
		return err
	}
	if err := ValidateOID(u.OldOID); err != nil {
		return fmt.Errorf("invalid old_oid: %w", err)
	}
	if err := ValidateOID(u.NewOID); err != nil {
		return fmt.Errorf("invalid new_oid: %w", err)
	}
	if len(u.OldOID) != len(u.NewOID) {
		return fmt.Errorf("%w: old_oid and new_oid have mismatched lengths (%d vs %d)", ErrInvalidRefTx, len(u.OldOID), len(u.NewOID))
	}
	isOldZero := isZeroOID(u.OldOID)
	isNewZero := isZeroOID(u.NewOID)
	if isOldZero && isNewZero {
		return fmt.Errorf("%w: cannot transition from zero oid to zero oid", ErrInvalidRefTx)
	}
	if strings.EqualFold(u.OldOID, u.NewOID) {
		return fmt.Errorf("%w: no-op ref update (old_oid == new_oid: %q)", ErrInvalidRefTx, u.OldOID)
	}
	return nil
}

func isZeroOID(oid string) bool {
	for i := 0; i < len(oid); i++ {
		if oid[i] != '0' {
			return false
		}
	}
	return true
}

// Validate validates that a RefTransactionRecord is well-formed.
func (r *RefTransactionRecord) Validate() error {
	if r == nil {
		return fmt.Errorf("%w: record cannot be nil", ErrInvalidRefTx)
	}
	if r.Version != VersionPrefix {
		return fmt.Errorf("%w: unsupported version %q (expected %q)", ErrInvalidRefTx, r.Version, VersionPrefix)
	}
	if r.Stream == MetaStreamID {
		return fmt.Errorf("%w: ref transactions cannot be written to meta stream %q", ErrInvalidRefTx, MetaStreamID)
	}
	if err := ValidateStreamID(r.Stream); err != nil {
		return fmt.Errorf("%w: invalid stream: %w", ErrInvalidRefTx, err)
	}
	if r.Type != RecordTypeRefUpdate {
		return fmt.Errorf("%w: expected type %q, got %q", ErrInvalidRefTx, RecordTypeRefUpdate, r.Type)
	}
	if r.Segments == nil {
		r.Segments = []string{}
	}
	seenSegments := make(map[string]bool, len(r.Segments))
	for i, seg := range r.Segments {
		if err := ValidateHash(seg); err != nil {
			return fmt.Errorf("%w: segment[%d] %q invalid: %w", ErrInvalidRefTx, i, seg, err)
		}
		lowerSeg := strings.ToLower(seg)
		if seenSegments[lowerSeg] {
			return fmt.Errorf("%w: duplicate segment %q in transaction", ErrInvalidRefTx, seg)
		}
		seenSegments[lowerSeg] = true
	}
	if len(r.Updates) == 0 {
		return fmt.Errorf("%w: updates array must contain at least one ref update", ErrInvalidRefTx)
	}
	seenRefs := make(map[string]bool, len(r.Updates))
	var expectedOIDLen int
	for i, u := range r.Updates {
		if seenRefs[u.Ref] {
			return fmt.Errorf("%w: duplicate ref update for %q in single transaction", ErrInvalidRefTx, u.Ref)
		}
		seenRefs[u.Ref] = true
		if err := ValidateRefUpdate(u); err != nil {
			return fmt.Errorf("%w: update[%d] invalid: %w", ErrInvalidRefTx, i, err)
		}
		if i == 0 {
			expectedOIDLen = len(u.OldOID)
		} else if len(u.OldOID) != expectedOIDLen {
			return fmt.Errorf("%w: mixed oid algorithms in transaction (update[0] len %d vs update[%d] len %d)", ErrInvalidRefTx, expectedOIDLen, i, len(u.OldOID))
		}
	}
	if r.Timestamp == "" {
		return fmt.Errorf("%w: timestamp cannot be empty", ErrInvalidRefTx)
	}
	t, err := time.Parse(time.RFC3339, r.Timestamp)
	if err != nil {
		return fmt.Errorf("%w: invalid timestamp %q (must be RFC 3339): %w", ErrInvalidRefTx, r.Timestamp, err)
	}
	if !strings.HasSuffix(r.Timestamp, "Z") && !strings.HasSuffix(r.Timestamp, "+00:00") && !strings.HasSuffix(r.Timestamp, "-00:00") {
		if t.Location() != time.UTC {
			return fmt.Errorf("%w: timestamp must be in UTC (got %q)", ErrInvalidRefTx, r.Timestamp)
		}
	}
	return nil
}

// CanonicalRefUpdatePayload returns the deterministic canonical byte payload to sign/verify for a RefTransactionRecord.
// Ref names are embedded as exact byte sequences without Unicode normalization.
func CanonicalRefUpdatePayload(stream StreamID, seq Seq, timestamp string, segments []string, updates []RefUpdate) []byte {
	var sb strings.Builder
	sb.WriteString("walden-ref-update:v1\n")
	sb.WriteString("stream:")
	sb.WriteString(string(stream))
	sb.WriteByte('\n')
	sb.WriteString("seq:")
	sb.WriteString(seq.String())
	sb.WriteByte('\n')
	sb.WriteString("timestamp:")
	sb.WriteString(timestamp)
	sb.WriteByte('\n')
	for _, seg := range segments {
		sb.WriteString("segment:")
		sb.WriteString(strings.ToLower(seg))
		sb.WriteByte('\n')
	}
	for _, u := range updates {
		sb.WriteString("update:")
		sb.WriteString(u.Ref)
		sb.WriteByte(' ')
		sb.WriteString(strings.ToLower(u.OldOID))
		sb.WriteByte(' ')
		sb.WriteString(strings.ToLower(u.NewOID))
		sb.WriteByte('\n')
	}
	return []byte(sb.String())
}

// SignRefTx signs a RefTransactionRecord using the server's Ed25519 private key.
func SignRefTx(priv ed25519.PrivateKey, r *RefTransactionRecord) error {
	if r == nil {
		return fmt.Errorf("%w: record cannot be nil", ErrInvalidRefTx)
	}
	if err := r.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRefTx, err)
	}
	payload := CanonicalRefUpdatePayload(r.Stream, r.Seq, r.Timestamp, r.Segments, r.Updates)
	sig := ed25519.Sign(priv, payload)
	r.Signature = FormatSignature(sig)
	return nil
}

// VerifyRefTx verifies that a RefTransactionRecord is well-formed and cryptographically valid against activePublicKey.
func VerifyRefTx(r *RefTransactionRecord, activePublicKey string) error {
	if r == nil {
		return fmt.Errorf("%w: record cannot be nil", ErrInvalidRefTx)
	}
	if err := r.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRefTx, err)
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
	payload := CanonicalRefUpdatePayload(r.Stream, r.Seq, r.Timestamp, r.Segments, r.Updates)
	if !ed25519.Verify(pubKey, payload, sigBytes) {
		return fmt.Errorf("%w: signature mismatch for ref update on stream %q at seq %d", ErrSignatureMismatch, r.Stream, r.Seq)
	}
	return nil
}

// VerifyRefTx verifies a ref transaction record against the active signing key in the chain.
func (c *SigningChain) VerifyRefTx(r *RefTransactionRecord) error {
	if c == nil || !c.initialized {
		return fmt.Errorf("%w: cannot verify ref transaction before genesis", ErrGenesisMissing)
	}
	return VerifyRefTx(r, c.activeKey)
}
