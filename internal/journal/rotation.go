// This file implements the local half of the key rotation record
// (spec/journal/v1 section 4.1, section 4.2's canonical payload): strict
// decode/encode of the record itself, and the two refusals specific to
// performing a rotation. It mirrors genesis.go's split exactly, for the
// same reason: it does no I/O against object storage, because
// internal/journal cannot import internal/store (that cycles), and only
// store can tell a 404 from a 403 or an ambiguous write. The GET-replay
// orchestration that discovers the chain's active key lives on
// (*store.Client).ReplayMeta (internal/store/meta.go); the
// conditional-append orchestration that performs a rotation lives on
// (*store.Client).RotateKey (internal/store/rotation.go), built on
// (*journal.Lease).Append (lease.go, WALD-29) rather than reimplementing
// head discovery or fencing here.
//
// The record type itself (KeyRotationRecord), its canonical payload
// (CanonicalRotationPayload), SignRotation, VerifyRotation, and
// (*SigningChain).ApplyRotation all already exist in identity.go — this
// file adds nothing to that half, only the construction, parsing,
// marshaling, and rotation-specific refusals around it.
package journal

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/writtendev/walden/internal/refusal"
)

// NewKeyRotationRecord builds the key_rotation record a rotation appends to
// _meta: the fixed fields spec section 4.1 requires (version "v1", stream
// "_meta", type "key_rotation"), seq supplied by the caller (a Lease's own
// sequence issuance owns that — see lease.go — not this constructor), and
// timestamp (RFC 3339 UTC) supplied by the caller so a rotation stays
// deterministic in tests. The record is unsigned until SignRotation is
// called on it, mirroring NewGenesisRecord's shape.
//
// oldKey is taken as the exact "ed25519:<64-hex>" string the caller already
// has in hand — the chain's own ActiveKey(), not a copy reformatted from
// decoded bytes — because VerifyRotation/ApplyRotation compare
// old_public_key against ActiveKey() as strings (identity.go), not as
// decoded key material. ParsePublicKey accepts uppercase hex, so a
// spec-non-conformant but parseable chain entry can carry
// "ed25519:8A88..."; a caller that checks its local signing key against the
// chain by decoded bytes (round 2 finding, store/rotation.go) but then
// rebuilt old_public_key from that decoded key would reformat it to
// lowercase and produce a record no future replay's string comparison
// could ever accept. Passing the chain's own string through unchanged is
// what keeps the two checks — decoded-byte identity here, string identity
// at replay — talking about the same fact. newKey has no such history: it
// is this rotation's freshly generated key, so this constructor formats it
// directly.
func NewKeyRotationRecord(seq Seq, oldKey string, newKey ed25519.PublicKey, timestamp string) *KeyRotationRecord {
	return &KeyRotationRecord{
		Version:      VersionPrefix,
		Stream:       MetaStreamID,
		Seq:          seq,
		Type:         RecordTypeKeyRotation,
		OldPublicKey: oldKey,
		NewPublicKey: FormatPublicKey(newKey),
		Timestamp:    timestamp,
	}
}

// keyRotationShadow decodes a key_rotation record into pointer fields so
// ParseKeyRotation can tell a field that is genuinely absent from one that
// decoded to its zero value — the same gap genesisShadow (genesis.go) and
// markerShadow (marker.go) close for their own records.
type keyRotationShadow struct {
	Version      *string   `json:"version"`
	Stream       *StreamID `json:"stream"`
	Seq          *Seq      `json:"seq"`
	Type         *string   `json:"type"`
	OldPublicKey *string   `json:"old_public_key"`
	NewPublicKey *string   `json:"new_public_key"`
	Timestamp    *string   `json:"timestamp"`
	Signature    *string   `json:"signature"`
}

// ParseKeyRotation parses a key_rotation record's JSON bytes: it decodes
// into a shadow struct of pointer fields and refuses an absent required
// field by name. Full field and chain validation (version, stream, type,
// key formats, old_public_key chaining to the active key, and the
// signature itself) stays in VerifyRotation/(*SigningChain).ApplyRotation,
// which every caller runs on the result — ParseKeyRotation itself checks
// presence only, exactly as ParseGenesis does for genesis.json.
func ParseKeyRotation(data []byte) (*KeyRotationRecord, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty key rotation data", ErrInvalidRotation)
	}
	var shadow keyRotationShadow
	if err := json.Unmarshal(data, &shadow); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRotation, err)
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
	case shadow.OldPublicKey == nil:
		missing = "old_public_key"
	case shadow.NewPublicKey == nil:
		missing = "new_public_key"
	case shadow.Timestamp == nil:
		missing = "timestamp"
	case shadow.Signature == nil:
		missing = "signature"
	}
	if missing != "" {
		return nil, fmt.Errorf("%w: missing required field %q", ErrInvalidRotation, missing)
	}
	return &KeyRotationRecord{
		Version:      *shadow.Version,
		Stream:       *shadow.Stream,
		Seq:          *shadow.Seq,
		Type:         *shadow.Type,
		OldPublicKey: *shadow.OldPublicKey,
		NewPublicKey: *shadow.NewPublicKey,
		Timestamp:    *shadow.Timestamp,
		Signature:    *shadow.Signature,
	}, nil
}

// MarshalKeyRotation serializes a KeyRotationRecord to indented JSON with a
// trailing newline, matching MarshalGenesis and MarshalMarker: a minted
// record is byte-identical to the golden fixture
// (spec/journal/v1/fixtures/v1/streams/_meta/tx/00000000000000000002.json)
// given the same keys, seq, and timestamp.
func MarshalKeyRotation(r *KeyRotationRecord) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: key rotation record cannot be nil", ErrInvalidRotation)
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key rotation record: %w", err)
	}
	return append(data, '\n'), nil
}

// RefuseCorruptRotation returns a one-line refusal when a key_rotation
// object under _meta cannot even be parsed — the same treatment
// RefuseCorruptGenesis (genesis.go) gives a malformed genesis record, for
// the same reason: a journal whose meta stream cannot be read at all is
// corrupt, not merely inconvenient, and there is nothing to fall back to.
func RefuseCorruptRotation(seq Seq, reason error) error {
	cause := ErrInvalidRotation
	if reason != nil {
		cause = fmt.Errorf("%w: %w", ErrInvalidRotation, reason)
	}
	return refusal.RefuseWithCause(
		"invalid journal",
		fmt.Sprintf("key rotation record at %s is corrupt (%v)", TxKey(MetaStreamID, seq), reason),
		"restore the _meta stream from a known-good journal, or point this instance at a fresh journal prefix",
		cause,
	)
}

// RefuseNotActiveSigningKey returns a one-line refusal when a rotation is
// attempted on an instance whose local signing.key is not the journal's
// currently active key (as ReplayMeta's chain reports it): this instance
// cannot produce old_public_key's signature (spec section 4.1's field
// table, section 4.2's canonical payload), so it cannot append a rotation
// that chains to genesis, and must not be allowed to try.
func RefuseNotActiveSigningKey(dataDir, localKey, activeKey string) error {
	return refusal.RefuseWithCause(
		"rotate-key refused",
		fmt.Sprintf("%s holds key %s, but the journal's active signing key is %s", SigningKeyPath(dataDir), localKey, activeKey),
		"run rotate-key against the instance whose signing.key matches the active key, or restore the correct signing.key here",
		ErrSigningKeyUnavailable,
	)
}
