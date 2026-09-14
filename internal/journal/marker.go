// Package journal implements walden's append-only write-ahead log in object storage.
// Per ARCHITECTURE.md: Compaction writes a consolidated snapshot pack per stream
// plus a "replay from here" marker, so materialization does not require replaying all of history.
// Per spec/journal/v1/README.md: The marker's meaning is contract from the reader's side.
package journal

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/writtendev/walden/internal/refusal"
)

var (
	// ErrCorruptMarker indicates that marker.json contains malformed JSON or unparseable bytes.
	ErrCorruptMarker = errors.New("corrupt marker JSON")

	// ErrInvalidMarker indicates that a marker has invalid or missing fields.
	ErrInvalidMarker = errors.New("invalid marker")

	// ErrSnapshotNotFound indicates that the snapshot packfile referenced by a marker is missing in object storage.
	ErrSnapshotNotFound = errors.New("missing snapshot pack")

	// ErrSnapshotCorrupt indicates that a snapshot packfile fails SHA-256 verification or has an invalid Git pack header.
	ErrSnapshotCorrupt = errors.New("corrupt snapshot pack")

	// ErrSnapshotHashMismatch indicates that a snapshot pack's computed SHA-256 does not match the marker.
	ErrSnapshotHashMismatch = errors.New("snapshot hash mismatch")
)

// MarkerRef is one entry in a Marker's authoritative ref set: a ref name and the
// object id it stood at, as of the marker's baseline sequence. Ref names carry the
// same encoding as RefUpdate.Ref (section 5.2 of the spec, by reference): a plain
// JSON string holding the raw byte sequence, no normalization.
type MarkerRef struct {
	Ref string `json:"ref"`
	OID string `json:"oid"`
}

// Marker represents the replay-from-here baseline published by background compaction.
// It allows a reader/restorer to skip replaying history prior to Sequence.
//
// A marker is a signed record (WALD-97): it carries the authoritative ref set as of
// Sequence, so a reader applying the snapshot pack it names can set exactly those
// refs and no others, and the key-epoch floor as of Sequence, so a replay resuming
// from this baseline can enforce rule 15 (key epoch regression) against the
// stream's full history rather than starting blind at epoch 0. Field order mirrors
// RefTransactionRecord — epoch fields early, Signature last — because
// MarshalMarker writes the fixture bytes and the two record types read the same.
type Marker struct {
	Version  string   `json:"version"`
	Stream   StreamID `json:"stream"`
	Sequence Seq      `json:"sequence"`

	// KeyEpoch names the key that signed this marker, with section 5.1's semantics
	// word for word: a hint, not authority, refused if it falls outside the chain
	// verified from genesis.
	KeyEpoch Epoch `json:"key_epoch"`

	// KeyEpochFloor is the highest key_epoch carried by any record on this stream
	// at sequence <= Sequence. It is what a resumed replay seeds LastEpoch with.
	// KeyEpochFloor <= KeyEpoch MUST hold: a marker signed by a key older than the
	// history it claims to summarize is refused, not repaired.
	KeyEpochFloor Epoch `json:"key_epoch_floor"`

	Snapshot string `json:"snapshot"`

	// Refs is the authoritative ref set as of Sequence, not a delta: an array of
	// objects (never a JSON object map, which has no defined key order or
	// duplicate-key behavior, and this array is signed), sorted ascending by the
	// raw bytes of Ref, carrying no duplicate ref name and no zero OID. Refs MAY
	// be empty: a stream whose every ref has been deleted has an empty ref set,
	// and that is authoritative state, not a missing field.
	Refs []MarkerRef `json:"refs"`

	Timestamp string `json:"timestamp"`

	// Signature is "ed25519:<128-hex>" over CanonicalMarkerPayload.
	Signature string `json:"signature"`
}

// Validate validates that a Marker is well-formed according to the v1 specification.
func (m *Marker) Validate() error {
	if m == nil {
		return fmt.Errorf("%w: marker cannot be nil", ErrInvalidMarker)
	}
	if m.Version != VersionPrefix {
		return fmt.Errorf("%w: unsupported version %q (expected %q)", ErrInvalidMarker, m.Version, VersionPrefix)
	}
	if m.Stream == MetaStreamID {
		return fmt.Errorf("%w: snapshot markers cannot be written to meta stream %q", ErrInvalidMarker, MetaStreamID)
	}
	if err := ValidateStreamID(m.Stream); err != nil {
		return fmt.Errorf("%w: invalid stream: %w", ErrInvalidMarker, err)
	}
	if err := ValidateHash(m.Snapshot); err != nil {
		return fmt.Errorf("%w: invalid snapshot hash: %w", ErrInvalidMarker, err)
	}
	if m.Timestamp == "" {
		return fmt.Errorf("%w: timestamp cannot be empty", ErrInvalidMarker)
	}
	t, err := time.Parse(time.RFC3339, m.Timestamp)
	if err != nil {
		return fmt.Errorf("%w: invalid timestamp %q (must be RFC 3339): %w", ErrInvalidMarker, m.Timestamp, err)
	}
	if !strings.HasSuffix(m.Timestamp, "Z") && !strings.HasSuffix(m.Timestamp, "+00:00") && !strings.HasSuffix(m.Timestamp, "-00:00") {
		if t.Location() != time.UTC {
			return fmt.Errorf("%w: timestamp must be in UTC (got %q)", ErrInvalidMarker, m.Timestamp)
		}
	}
	if m.KeyEpochFloor > m.KeyEpoch {
		return fmt.Errorf("%w: key_epoch_floor %s exceeds key_epoch %s", ErrInvalidMarker, m.KeyEpochFloor, m.KeyEpoch)
	}
	if m.Refs == nil {
		m.Refs = []MarkerRef{}
	}
	seenRefs := make(map[string]bool, len(m.Refs))
	var expectedOIDLen int
	for i, ref := range m.Refs {
		if err := ValidateRefName(ref.Ref); err != nil {
			return fmt.Errorf("%w: refs[%d] invalid ref name: %w", ErrInvalidMarker, i, err)
		}
		if err := ValidateOID(ref.OID); err != nil {
			return fmt.Errorf("%w: refs[%d] invalid oid: %w", ErrInvalidMarker, i, err)
		}
		if isZeroOID(ref.OID) {
			return fmt.Errorf("%w: refs[%d] %q names the zero OID; a ref that does not exist must be absent, not present pointing at zeros", ErrInvalidMarker, i, ref.Ref)
		}
		if seenRefs[ref.Ref] {
			return fmt.Errorf("%w: duplicate ref %q in marker ref set", ErrInvalidMarker, ref.Ref)
		}
		seenRefs[ref.Ref] = true
		if i == 0 {
			expectedOIDLen = len(ref.OID)
		} else {
			if len(ref.OID) != expectedOIDLen {
				return fmt.Errorf("%w: mixed oid algorithms in marker ref set (refs[0] len %d vs refs[%d] len %d)", ErrInvalidMarker, expectedOIDLen, i, len(ref.OID))
			}
			if ref.Ref <= m.Refs[i-1].Ref {
				return fmt.Errorf("%w: refs must be sorted ascending by ref name (refs[%d] %q does not follow refs[%d] %q)", ErrInvalidMarker, i, ref.Ref, i-1, m.Refs[i-1].Ref)
			}
		}
	}
	return nil
}

// ValidateMarker validates that a Marker is well-formed.
func ValidateMarker(m *Marker) error {
	if m == nil {
		return fmt.Errorf("%w: marker cannot be nil", ErrInvalidMarker)
	}
	return m.Validate()
}

// markerShadow decodes marker.json into pointer fields so that ParseMarker can
// tell a field that is genuinely absent from one that decoded to its zero value.
// This matters more than it once did: an absent key_epoch_floor decoding to 0 is
// exactly the hole WALD-97 closes, wearing the clothes of a parser default —
// the same absent-vs-zero gap Seq.UnmarshalJSON and Epoch.UnmarshalJSON document
// on themselves and leave open, closed here instead by checking presence before
// ever handing the value to the real type.
type markerShadow struct {
	Version       *string      `json:"version"`
	Stream        *StreamID    `json:"stream"`
	Sequence      *Seq         `json:"sequence"`
	KeyEpoch      *Epoch       `json:"key_epoch"`
	KeyEpochFloor *Epoch       `json:"key_epoch_floor"`
	Snapshot      *string      `json:"snapshot"`
	Refs          *[]MarkerRef `json:"refs"`
	Timestamp     *string      `json:"timestamp"`
	Signature     *string      `json:"signature"`
}

// ParseMarker parses and validates a marker.json byte slice.
// Unknown JSON fields are ignored during unmarshaling for forward compatibility.
func ParseMarker(data []byte) (*Marker, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty marker data", ErrCorruptMarker)
	}
	var shadow markerShadow
	if err := json.Unmarshal(data, &shadow); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptMarker, err)
	}
	missing := ""
	switch {
	case shadow.Version == nil:
		missing = "version"
	case shadow.Stream == nil:
		missing = "stream"
	case shadow.Sequence == nil:
		missing = "sequence"
	case shadow.KeyEpoch == nil:
		missing = "key_epoch"
	case shadow.KeyEpochFloor == nil:
		missing = "key_epoch_floor"
	case shadow.Snapshot == nil:
		missing = "snapshot"
	case shadow.Refs == nil:
		missing = "refs"
	case shadow.Timestamp == nil:
		missing = "timestamp"
	case shadow.Signature == nil:
		missing = "signature"
	}
	if missing != "" {
		return nil, fmt.Errorf("%w: missing required field %q", ErrInvalidMarker, missing)
	}
	m := &Marker{
		Version:       *shadow.Version,
		Stream:        *shadow.Stream,
		Sequence:      *shadow.Sequence,
		KeyEpoch:      *shadow.KeyEpoch,
		KeyEpochFloor: *shadow.KeyEpochFloor,
		Snapshot:      *shadow.Snapshot,
		Refs:          *shadow.Refs,
		Timestamp:     *shadow.Timestamp,
		Signature:     *shadow.Signature,
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidMarker, err)
	}
	m.Snapshot = strings.ToLower(m.Snapshot)
	return m, nil
}

// MarshalMarker serializes a Marker to indented JSON with a trailing newline.
func MarshalMarker(m *Marker) ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("%w: marker cannot be nil", ErrInvalidMarker)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidMarker, err)
	}
	// Copy to ensure lowercase snapshot hash
	mCopy := *m
	mCopy.Snapshot = strings.ToLower(mCopy.Snapshot)
	data, err := json.MarshalIndent(&mCopy, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal marker: %w", err)
	}
	return append(data, '\n'), nil
}

// CanonicalMarkerPayload returns the deterministic canonical byte payload to
// sign/verify for a Marker, styled on CanonicalRefUpdatePayload. Ref names are
// embedded as exact byte sequences without Unicode normalization, in Refs order
// (which Validate already requires to be sorted ascending by ref name).
func CanonicalMarkerPayload(stream StreamID, seq Seq, keyEpoch, keyEpochFloor Epoch, timestamp, snapshot string, refs []MarkerRef) []byte {
	var sb strings.Builder
	sb.WriteString("walden-marker:v1\n")
	sb.WriteString("stream:")
	sb.WriteString(string(stream))
	sb.WriteByte('\n')
	sb.WriteString("sequence:")
	sb.WriteString(seq.String())
	sb.WriteByte('\n')
	sb.WriteString("key_epoch:")
	sb.WriteString(keyEpoch.String())
	sb.WriteByte('\n')
	sb.WriteString("key_epoch_floor:")
	sb.WriteString(keyEpochFloor.String())
	sb.WriteByte('\n')
	sb.WriteString("timestamp:")
	sb.WriteString(timestamp)
	sb.WriteByte('\n')
	sb.WriteString("snapshot:")
	sb.WriteString(strings.ToLower(snapshot))
	sb.WriteByte('\n')
	for _, ref := range refs {
		sb.WriteString("ref:")
		sb.WriteString(ref.Ref)
		sb.WriteByte(' ')
		sb.WriteString(strings.ToLower(ref.OID))
		sb.WriteByte('\n')
	}
	return []byte(sb.String())
}

// SignMarker signs a Marker using the server's Ed25519 private key.
func SignMarker(priv ed25519.PrivateKey, m *Marker) error {
	if m == nil {
		return fmt.Errorf("%w: marker cannot be nil", ErrInvalidMarker)
	}
	if err := m.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidMarker, err)
	}
	payload := CanonicalMarkerPayload(m.Stream, m.Sequence, m.KeyEpoch, m.KeyEpochFloor, m.Timestamp, m.Snapshot, m.Refs)
	sig := ed25519.Sign(priv, payload)
	m.Signature = FormatSignature(sig)
	return nil
}

// VerifyMarker verifies that a Marker is well-formed and cryptographically valid
// against activePublicKey.
func VerifyMarker(m *Marker, activePublicKey string) error {
	if m == nil {
		return fmt.Errorf("%w: marker cannot be nil", ErrInvalidMarker)
	}
	if err := m.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidMarker, err)
	}
	if m.Signature == "" {
		return fmt.Errorf("%w: missing signature", ErrInvalidSignature)
	}
	pubKey, err := ParsePublicKey(activePublicKey)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	sigBytes, err := ParseSignature(m.Signature)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	payload := CanonicalMarkerPayload(m.Stream, m.Sequence, m.KeyEpoch, m.KeyEpochFloor, m.Timestamp, m.Snapshot, m.Refs)
	if !ed25519.Verify(pubKey, payload, sigBytes) {
		return fmt.Errorf("%w: signature mismatch for marker on stream %q at sequence %d", ErrSignatureMismatch, m.Stream, m.Sequence)
	}
	return nil
}

// VerifyMarker verifies a Marker against the key its own key_epoch names in the
// chain (spec section 7.5), exactly as (*SigningChain).VerifyRefTx does for a ref
// transaction: the epoch is a hint, not authority, and an epoch outside the chain
// verified from genesis is refused rather than a reason to fall back to the
// active key.
//
// On success, VerifyMarker mutates c: it seeds c's per-stream epoch floor for
// m.Stream from m.KeyEpochFloor, which is what lets a replay resumed from this
// marker's baseline enforce rule 15 (key epoch regression) against the stream's
// full history rather than starting blind at epoch 0 (WALD-97). Seeding happens
// only here, as a side effect of verifying the signature that covers the floor —
// there is no second mechanism, so the floor cannot be raised except by a marker
// whose signature actually verifies.
func (c *SigningChain) VerifyMarker(m *Marker) error {
	if c == nil || !c.initialized {
		return fmt.Errorf("%w: cannot verify marker before genesis", ErrGenesisMissing)
	}
	if m == nil {
		return fmt.Errorf("%w: marker cannot be nil", ErrInvalidMarker)
	}
	key, err := c.KeyAtEpoch(m.KeyEpoch)
	if err != nil {
		return RefuseMarkerUnknownKeyEpoch(m.Stream, m.KeyEpoch)
	}
	if err := VerifyMarker(m, key); err != nil {
		return err
	}
	if c.lastEpoch == nil {
		c.lastEpoch = make(map[StreamID]Epoch)
	}
	c.lastEpoch[m.Stream] = m.KeyEpochFloor
	return nil
}

// ValidateSnapshot validates that data is a valid Git packfile and that its SHA-256 hash matches expectedHash.
func ValidateSnapshot(data []byte, expectedHash string) error {
	if err := ValidateHash(expectedHash); err != nil {
		return fmt.Errorf("%w: invalid expected snapshot hash: %w", ErrSnapshotCorrupt, err)
	}
	if err := ValidatePackfileHeader(data); err != nil {
		return fmt.Errorf("%w: %w", ErrSnapshotCorrupt, err)
	}
	computed := ComputeSegmentHash(data)
	if !strings.EqualFold(computed, expectedHash) {
		return fmt.Errorf("%w: expected %s, got %s: %w", ErrSnapshotHashMismatch, strings.ToLower(expectedHash), computed, ErrSnapshotCorrupt)
	}
	return nil
}

// ValidateSnapshotSHA256 validates that data is a valid Git packfile for SHA-256 repositories and that its SHA-256 hash matches expectedHash.
func ValidateSnapshotSHA256(data []byte, expectedHash string) error {
	if err := ValidateHash(expectedHash); err != nil {
		return fmt.Errorf("%w: invalid expected snapshot hash: %w", ErrSnapshotCorrupt, err)
	}
	if err := ValidatePackfileHeaderSHA256(data); err != nil {
		return fmt.Errorf("%w: %w", ErrSnapshotCorrupt, err)
	}
	computed := ComputeSegmentHash(data)
	if !strings.EqualFold(computed, expectedHash) {
		return fmt.Errorf("%w: expected %s, got %s: %w", ErrSnapshotHashMismatch, strings.ToLower(expectedHash), computed, ErrSnapshotCorrupt)
	}
	return nil
}

// ValidateSnapshotFromReader streams bytes from an io.Reader, verifies Git packfile framing rules, and asserts SHA-256 matches expectedHash.
func ValidateSnapshotFromReader(r io.Reader, expectedHash string) (int64, error) {
	if err := ValidateHash(expectedHash); err != nil {
		return 0, fmt.Errorf("%w: invalid expected snapshot hash: %w", ErrSnapshotCorrupt, err)
	}
	if r == nil {
		return 0, fmt.Errorf("%w: reader cannot be nil", ErrSnapshotCorrupt)
	}
	var hdr [PackfileMinSize]byte
	n, err := io.ReadFull(r, hdr[:])
	if err != nil {
		return int64(n), fmt.Errorf("%w: length %d is less than minimum packfile size of %d bytes: %w", ErrSnapshotCorrupt, n, PackfileMinSize, err)
	}
	if err := ValidatePackfileHeader(hdr[:]); err != nil {
		return int64(n), fmt.Errorf("%w: %w", ErrSnapshotCorrupt, err)
	}
	h := sha256.New()
	h.Write(hdr[:])
	copied, err := io.Copy(h, r)
	total := int64(n) + copied
	if err != nil {
		return total, fmt.Errorf("failed to read snapshot pack: %w", err)
	}
	computed := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(computed, expectedHash) {
		return total, fmt.Errorf("%w: expected %s, got %s: %w", ErrSnapshotHashMismatch, strings.ToLower(expectedHash), computed, ErrSnapshotCorrupt)
	}
	return total, nil
}

// ValidateSnapshotSHA256FromReader streams bytes from an io.Reader, verifies Git packfile framing rules for SHA-256 repos (>= 44 bytes), and asserts SHA-256 matches expectedHash.
func ValidateSnapshotSHA256FromReader(r io.Reader, expectedHash string) (int64, error) {
	if err := ValidateHash(expectedHash); err != nil {
		return 0, fmt.Errorf("%w: invalid expected snapshot hash: %w", ErrSnapshotCorrupt, err)
	}
	if r == nil {
		return 0, fmt.Errorf("%w: reader cannot be nil", ErrSnapshotCorrupt)
	}
	var hdr [PackfileMinSizeSHA256]byte
	n, err := io.ReadFull(r, hdr[:])
	if err != nil {
		return int64(n), fmt.Errorf("%w: length %d is less than minimum SHA-256 packfile size of %d bytes: %w", ErrSnapshotCorrupt, n, PackfileMinSizeSHA256, err)
	}
	if err := ValidatePackfileHeaderSHA256(hdr[:]); err != nil {
		return int64(n), fmt.Errorf("%w: %w", ErrSnapshotCorrupt, err)
	}
	h := sha256.New()
	h.Write(hdr[:])
	copied, err := io.Copy(h, r)
	total := int64(n) + copied
	if err != nil {
		return total, fmt.Errorf("failed to read snapshot pack: %w", err)
	}
	computed := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(computed, expectedHash) {
		return total, fmt.Errorf("%w: expected %s, got %s: %w", ErrSnapshotHashMismatch, strings.ToLower(expectedHash), computed, ErrSnapshotCorrupt)
	}
	return total, nil
}

// SnapshotMetadata returns the standard S3 user metadata key-value pairs for a snapshot packfile upload.
func SnapshotMetadata(stream StreamID, sha256Hex string) map[string]string {
	return SegmentMetadata(stream, sha256Hex)
}

// SnapshotContentType returns the HTTP Content-Type header value for snapshot packfiles.
func SnapshotContentType() string {
	return ContentTypeGitPackedObjects
}

// RefuseMissingSnapshot returns a single-line operator-facing refusal when a referenced snapshot pack is missing.
func RefuseMissingSnapshot(stream StreamID, sha256Hex string) error {
	return refusal.RefuseWithCause(
		"refusal: replay failed",
		fmt.Sprintf("missing snapshot pack %s on stream %s", strings.ToLower(sha256Hex), stream),
		"verify object storage bucket integrity or restore from backup",
		ErrSnapshotNotFound,
	)
}

// RefuseSnapshotHashMismatch returns a single-line operator-facing refusal when a downloaded snapshot does not match its hash.
func RefuseSnapshotHashMismatch(stream StreamID, expectedHash, computedHash string) error {
	return refusal.RefuseWithCause(
		"refusal: replay failed",
		fmt.Sprintf("snapshot hash mismatch for %s on stream %s (computed %s)", strings.ToLower(expectedHash), stream, computedHash),
		"snapshot pack in object storage is corrupt",
		fmt.Errorf("%w: %w", ErrSnapshotHashMismatch, ErrSnapshotCorrupt),
	)
}

// RefuseCorruptSnapshot returns a single-line operator-facing refusal when a snapshot pack header or payload is corrupt.
func RefuseCorruptSnapshot(stream StreamID, sha256Hex string, reason error) error {
	cause := ErrSnapshotCorrupt
	if reason != nil {
		cause = fmt.Errorf("%w: %w", ErrSnapshotCorrupt, reason)
	}
	return refusal.RefuseWithCause(
		"refusal: replay failed",
		fmt.Sprintf("corrupt snapshot pack %s on stream %s (%v)", strings.ToLower(sha256Hex), stream, reason),
		"packfile header is malformed",
		cause,
	)
}

// RefuseCorruptMarker returns a single-line operator-facing refusal when marker.json is malformed JSON.
func RefuseCorruptMarker(stream StreamID, reason error) error {
	cause := ErrCorruptMarker
	if reason != nil {
		cause = fmt.Errorf("%w: %w", ErrCorruptMarker, reason)
	}
	return refusal.RefuseWithCause(
		"refusal: replay failed",
		fmt.Sprintf("corrupt marker on stream %s (%v)", stream, reason),
		"marker.json in object storage is malformed",
		cause,
	)
}

// RefuseInvalidMarker returns a single-line operator-facing refusal when marker.json has invalid fields.
func RefuseInvalidMarker(stream StreamID, reason error) error {
	cause := ErrInvalidMarker
	if reason != nil {
		cause = fmt.Errorf("%w: %w", ErrInvalidMarker, reason)
	}
	return refusal.RefuseWithCause(
		"refusal: replay failed",
		fmt.Sprintf("invalid marker on stream %s (%v)", stream, reason),
		"marker.json in object storage is invalid",
		cause,
	)
}

// RefuseMarkerSignatureMismatch returns a single-line operator-facing refusal
// when a marker's signature does not verify against the key its key_epoch names.
func RefuseMarkerSignatureMismatch(stream StreamID, sequence Seq) error {
	return refusal.RefuseWithCause(
		"refusal: replay failed",
		fmt.Sprintf("signature mismatch for marker on stream %s at sequence %d", stream, sequence),
		"",
		ErrSignatureMismatch,
	)
}

// RefuseMarkerUnknownKeyEpoch returns a single-line operator-facing refusal when
// a marker's key_epoch is not a valid index into the signing chain verified so
// far, worded to match RefuseUnknownKeyEpoch's ref-transaction equivalent
// (WALD-96). The epoch is a hint, not authority, so an out-of-range value is
// refused rather than treated as license to fall back to the active key.
func RefuseMarkerUnknownKeyEpoch(stream StreamID, epoch Epoch) error {
	return refusal.RefuseWithCause(
		"refusal: replay failed",
		fmt.Sprintf("marker on stream %s names unknown key epoch %s", stream, epoch),
		"",
		ErrUnknownKeyEpoch,
	)
}

// RefuseMarkerRefNotInSnapshot returns a single-line operator-facing refusal
// when a marker names a ref pointing at an object the snapshot pack it also
// names does not carry — a violation of the Publish-Last Invariant (section 7.3).
func RefuseMarkerRefNotInSnapshot(stream StreamID, ref, oid string) error {
	return refusal.RefuseWithCause(
		"refusal: replay failed",
		fmt.Sprintf("marker on stream %s names %s at %s, which the snapshot pack does not carry", stream, ref, strings.ToLower(oid)),
		"marker.json in object storage is invalid",
		ErrInvalidMarker,
	)
}
