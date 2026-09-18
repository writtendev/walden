package journal

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/writtendev/walden/internal/refusal"
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
	Version string   `json:"version"`
	Stream  StreamID `json:"stream"`
	Seq     Seq      `json:"seq"`
	Type    string   `json:"type"`

	// KeyEpoch names, as a hint rather than authority, the signing key that
	// signed this record: an index into the chain a reader has already
	// verified from genesis (WALD-96). It is part of the canonical signing
	// payload (CanonicalRefUpdatePayload), so it cannot be altered without
	// invalidating the signature.
	//
	// Validate does not range-check it against a chain — this type cannot see
	// one — so a record with no "key_epoch" at all decodes to epoch 0 and
	// passes Validate like any other. That is the same absent-vs-zero gap Seq
	// documents on its own UnmarshalJSON, left open here for the same reason.
	KeyEpoch Epoch `json:"key_epoch"`

	Segments  []string    `json:"segments"`
	Updates   []RefUpdate `json:"updates"`
	Timestamp string      `json:"timestamp"`
	Signature string      `json:"signature,omitempty"`
}

// NewRefTransactionRecord builds a RefTransactionRecord with the fixed
// fields spec/journal/v1 section 5.1 requires ("version": "v1", "type":
// "ref_update") set in one place, exactly as NewGenesisRecord does for
// section 3.1 (genesis.go) and as WALD-31's NewKeyRotationRecord will for
// section 4.1. timestamp is the caller's, not time.Now(), for the same
// determinism reason NewGenesisRecord gives: a caller (or a test) controls
// the clock, this constructor does not.
func NewRefTransactionRecord(stream StreamID, seq Seq, keyEpoch Epoch, timestamp string, segments []string, updates []RefUpdate) *RefTransactionRecord {
	return &RefTransactionRecord{
		Version:   VersionPrefix,
		Stream:    stream,
		Seq:       seq,
		Type:      RecordTypeRefUpdate,
		KeyEpoch:  keyEpoch,
		Segments:  segments,
		Updates:   updates,
		Timestamp: timestamp,
	}
}

// MarshalRefTx serializes a RefTransactionRecord to indented JSON with a
// trailing newline, mirroring MarshalMarker (marker.go): refuse nil,
// Validate() first, then json.MarshalIndent with a two-space indent and an
// appended trailing newline byte. That is byte-for-byte what the fixture
// generator's writeJSON produces, and RefTransactionRecord's field order
// already matches section 5.1, so the published golden records become
// reproducible by production code rather than only by a test helper.
//
// Three checks beyond Validate:
//
//   - r must already carry a non-empty signature ParseSignature accepts —
//     section 5.1 lists signature as required, and an unsigned record can
//     never be verified on replay, so it is refused here rather than
//     written.
//   - Every update's Ref must be valid UTF-8. Section 5.2 requires ref
//     names to round-trip as exact, opaque byte sequences, and
//     CanonicalRefUpdatePayload (section 5.3) honors that: it is a raw
//     byte stream, not JSON, so SignRefTx and VerifyRefTx preserve any
//     byte sequence git itself accepts, including one that is not valid
//     UTF-8. v1's on-disk record format cannot make the same promise: it
//     is JSON (section 5.1), and encoding/json silently replaces an
//     invalid UTF-8 byte sequence with U+FFFD instead of erroring, which
//     would write a record whose bytes no longer match the ones the
//     signature above was computed over — permanently unverifiable, and
//     spec section 8.1 rule 3 aborts replay of the whole stream on
//     exactly that. There is no v1 escape convention for raw bytes in
//     JSON (section 5.4 forbids inventing one unilaterally as an unknown
//     field), so this is refused rather than written.
//   - Segments and every update's OIDs are lowercased in a copy before
//     marshaling (section 5.1 requires lowercase hex), the same way
//     MarshalMarker lowercases Snapshot. The copy is real, not a struct
//     copy sharing r's backing arrays: a struct copy alone would still
//     let this mutate the caller's own Segments and Updates slices in
//     place.
func MarshalRefTx(r *RefTransactionRecord) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: record cannot be nil", ErrInvalidRefTx)
	}
	if err := r.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRefTx, err)
	}
	if r.Signature == "" {
		return nil, fmt.Errorf("%w: missing signature", ErrInvalidSignature)
	}
	if _, err := ParseSignature(r.Signature); err != nil {
		return nil, err
	}
	for i, u := range r.Updates {
		if !utf8.ValidString(u.Ref) {
			return nil, fmt.Errorf("%w: %w: update[%d] ref is not valid UTF-8; v1's JSON record format cannot carry it losslessly (json.MarshalIndent would replace its bytes with U+FFFD, producing a record that could never verify again): %q", ErrInvalidRefTx, ErrInvalidRef, i, u.Ref)
		}
	}

	rCopy := *r
	rCopy.Segments = make([]string, len(r.Segments))
	for i, seg := range r.Segments {
		rCopy.Segments[i] = strings.ToLower(seg)
	}
	rCopy.Updates = make([]RefUpdate, len(r.Updates))
	for i, u := range r.Updates {
		rCopy.Updates[i] = RefUpdate{
			Ref:    u.Ref,
			OldOID: strings.ToLower(u.OldOID),
			NewOID: strings.ToLower(u.NewOID),
		}
	}

	data, err := json.MarshalIndent(&rCopy, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ref transaction: %w", err)
	}
	return append(data, '\n'), nil
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
//
// Deliberately not checked here: whether ref is valid UTF-8. Git does not
// require it, and this function is shared by paths with different
// guarantees about raw bytes. The signing layer — SignRefTx/VerifyRefTx via
// CanonicalRefUpdatePayload, a plain byte stream rather than JSON —
// preserves an arbitrary, non-UTF-8 byte sequence exactly; that is what
// TestRefNameRawBytePreservationNonUTF8 pins. v1's JSON record format
// cannot make the same promise (encoding/json replaces invalid UTF-8 with
// U+FFFD), which is why MarshalRefTx refuses such a ref rather than
// writing an unverifiable record: see its own doc comment for why.
//
// MarshalMarker (marker.go) marshals ref names to JSON the same way and
// has the identical hole — unfixed, and deliberately out of this ticket's
// five files. WALD-119 tracks the v1-format decision this implies and the
// MarshalMarker fix that follows from it.
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

// refTxShadow decodes tx/<seq>.json into pointer fields so that ParseRefTx
// can tell a field that is genuinely absent from one that decoded to its
// zero value — the same discipline markerShadow (marker.go) and
// tokenCreateShadow (token.go) already apply to their own record types.
//
// KeyEpoch is deliberately not a pointer here, unlike every other field:
// section 5.1 states plainly that "a record with no key_epoch at all is
// read as epoch 0, identically to an explicit 'key_epoch': '0'" — an
// absent key_epoch is not an error to catch, it is the documented
// default. Segments and Updates are plain slices for the same reason:
// Validate() already turns a nil Segments into an empty one and already
// refuses an Updates array with no entries (nil included), so a shadow
// presence check would only duplicate what Validate does, not catch
// anything it misses.
type refTxShadow struct {
	Version   *string     `json:"version"`
	Stream    *StreamID   `json:"stream"`
	Seq       *Seq        `json:"seq"`
	Type      *string     `json:"type"`
	KeyEpoch  Epoch       `json:"key_epoch"`
	Segments  []string    `json:"segments"`
	Updates   []RefUpdate `json:"updates"`
	Timestamp *string     `json:"timestamp"`
	Signature *string     `json:"signature"`
}

// ParseRefTx parses and validates a tx/<seq>.json ref-transaction record's
// JSON bytes, in the style of ParseMarker and ParseTokenCreate: decode into
// a shadow of pointer fields so a genuinely missing required field is
// refused by name rather than silently read as its zero value, then run
// Validate() before returning. Unknown JSON keys are ignored, per spec
// section 5.4's forward-compatibility rule.
//
// ParseRefTx does not itself verify the signature or assert Type ==
// "ref_update" beyond what Validate() already checks — callers replaying a
// stream do that against a *SigningChain (see (*SigningChain).VerifyRefTx),
// using the record's own declared Type rather than inferring it from where
// its key was found.
func ParseRefTx(data []byte) (*RefTransactionRecord, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty ref transaction data", ErrInvalidRefTx)
	}
	var shadow refTxShadow
	if err := json.Unmarshal(data, &shadow); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRefTx, err)
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
	case shadow.Timestamp == nil:
		missing = "timestamp"
	case shadow.Signature == nil:
		missing = "signature"
	}
	if missing != "" {
		return nil, fmt.Errorf("%w: missing required field %q", ErrInvalidRefTx, missing)
	}
	r := &RefTransactionRecord{
		Version:   *shadow.Version,
		Stream:    *shadow.Stream,
		Seq:       *shadow.Seq,
		Type:      *shadow.Type,
		KeyEpoch:  shadow.KeyEpoch,
		Segments:  shadow.Segments,
		Updates:   shadow.Updates,
		Timestamp: *shadow.Timestamp,
		Signature: *shadow.Signature,
	}
	if err := r.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRefTx, err)
	}
	return r, nil
}

// CanonicalRefUpdatePayload returns the deterministic canonical byte payload to sign/verify for a RefTransactionRecord.
// Ref names are embedded as exact byte sequences without Unicode normalization.
func CanonicalRefUpdatePayload(stream StreamID, seq Seq, keyEpoch Epoch, timestamp string, segments []string, updates []RefUpdate) []byte {
	var sb strings.Builder
	sb.WriteString("walden-ref-update:v1\n")
	sb.WriteString("stream:")
	sb.WriteString(string(stream))
	sb.WriteByte('\n')
	sb.WriteString("seq:")
	sb.WriteString(seq.String())
	sb.WriteByte('\n')
	sb.WriteString("key_epoch:")
	sb.WriteString(keyEpoch.String())
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
	payload := CanonicalRefUpdatePayload(r.Stream, r.Seq, r.KeyEpoch, r.Timestamp, r.Segments, r.Updates)
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
	payload := CanonicalRefUpdatePayload(r.Stream, r.Seq, r.KeyEpoch, r.Timestamp, r.Segments, r.Updates)
	if !ed25519.Verify(pubKey, payload, sigBytes) {
		return fmt.Errorf("%w: signature mismatch for ref update on stream %q at seq %d", ErrSignatureMismatch, r.Stream, r.Seq)
	}
	return nil
}

// VerifyRefTx verifies a ref transaction record against the key its own
// key_epoch names in the chain (spec section 8, step 3), rather than against
// whatever key happens to be active now. The epoch is a hint, not authority:
// the chain is still the one verified from genesis forward, an epoch outside
// it is refused rather than a reason to fall back to the active key, and an
// epoch lower than one already verified on this stream is refused too, or a
// retired key would go on validating records forever.
//
// VerifyRefTx mutates c: on success it raises c's per-stream floor to
// r.KeyEpoch — unless a prior (*SigningChain).VerifyMarker call already seeded
// a higher floor for this stream from a verified marker's key_epoch_floor
// (WALD-97), in which case a record naming an epoch below that floor is
// refused here exactly as one below a floor VerifyRefTx itself raised would
// be. A SigningChain carries the state of exactly one replay and is not safe
// for concurrent use — drive it from a single goroutine; do not call
// VerifyRefTx on the same chain from more than one goroutine at a time.
func (c *SigningChain) VerifyRefTx(r *RefTransactionRecord) error {
	if c == nil || !c.initialized {
		return fmt.Errorf("%w: cannot verify ref transaction before genesis", ErrGenesisMissing)
	}
	if r == nil {
		return fmt.Errorf("%w: record cannot be nil", ErrInvalidRefTx)
	}
	key, err := c.KeyAtEpoch(r.KeyEpoch)
	if err != nil {
		return RefuseUnknownKeyEpoch(r.Stream, r.Seq, r.KeyEpoch)
	}
	if last, seen := c.lastEpoch[r.Stream]; seen && r.KeyEpoch < last {
		return RefuseKeyEpochRegression(r.Stream, r.Seq, r.KeyEpoch, last)
	}
	if err := VerifyRefTx(r, key); err != nil {
		return err
	}
	if c.lastEpoch == nil {
		c.lastEpoch = make(map[StreamID]Epoch)
	}
	c.lastEpoch[r.Stream] = r.KeyEpoch
	return nil
}

// RefuseUnknownKeyEpoch returns a single-line operator-facing refusal when a
// ref-transaction record names a key_epoch with no corresponding key in the
// chain verified so far (spec section 8.1). The epoch is a hint, not
// authority, so an out-of-range value is refused rather than treated as
// license to fall back to the active key.
func RefuseUnknownKeyEpoch(stream StreamID, seq Seq, epoch Epoch) error {
	return refusal.RefuseWithCause(
		"refusal: replay failed",
		fmt.Sprintf("ref update on stream %s at seq %d names unknown key epoch %s", stream, seq, epoch),
		"",
		ErrUnknownKeyEpoch,
	)
}

// RefuseKeyEpochRegression returns a single-line operator-facing refusal when
// a ref-transaction record names a key_epoch lower than one already verified
// on the same stream (spec section 8.1). Without this check a retired key
// could go on validating records inserted after a later one on that stream,
// which defeats the reason a key is rotated at all.
func RefuseKeyEpochRegression(stream StreamID, seq Seq, epoch, lastEpoch Epoch) error {
	return refusal.RefuseWithCause(
		"refusal: replay failed",
		fmt.Sprintf("ref update on stream %s at seq %d names key epoch %s below epoch %s already seen on this stream", stream, seq, epoch, lastEpoch),
		"",
		ErrKeyEpochRegression,
	)
}

// RefuseRefTxSignatureMismatch returns a single-line operator-facing refusal
// when a ref-transaction record's signature does not verify against the key
// its own key_epoch names (spec section 8.1 rule 3). A reader replaying a
// stream maps the raw ErrSignatureMismatch VerifyRefTx returns onto this
// constructor rather than surfacing VerifyRefTx's own message, which quotes
// the stream id and is not the wording section 8.1 publishes.
func RefuseRefTxSignatureMismatch(stream StreamID, seq Seq) error {
	return refusal.RefuseWithCause(
		"refusal: replay failed",
		fmt.Sprintf("signature mismatch for ref update on stream %s at seq %d", stream, seq),
		"",
		ErrSignatureMismatch,
	)
}
