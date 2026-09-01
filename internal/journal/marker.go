// Package journal implements walden's append-only write-ahead log in object storage.
// Per ARCHITECTURE.md: Compaction writes a consolidated snapshot pack per stream
// plus a "replay from here" marker, so materialization does not require replaying all of history.
// Per spec/journal/v1/README.md: The marker's meaning is contract from the reader's side.
package journal

import (
	"encoding/json"
	"errors"
	"fmt"
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

// Marker represents the replay-from-here baseline published by background compaction.
// It allows a reader/restorer to skip replaying history prior to Sequence.
type Marker struct {
	Version   string   `json:"version"`
	Stream    StreamID `json:"stream"`
	Sequence  uint64   `json:"sequence"`
	Snapshot  string   `json:"snapshot"`
	Timestamp string   `json:"timestamp"`
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
	return nil
}

// ValidateMarker validates that a Marker is well-formed.
func ValidateMarker(m *Marker) error {
	if m == nil {
		return fmt.Errorf("%w: marker cannot be nil", ErrInvalidMarker)
	}
	return m.Validate()
}

// ParseMarker parses and validates a marker.json byte slice.
// Unknown JSON fields are ignored during unmarshaling for forward compatibility.
func ParseMarker(data []byte) (*Marker, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty marker data", ErrCorruptMarker)
	}
	var m Marker
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptMarker, err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidMarker, err)
	}
	m.Snapshot = strings.ToLower(m.Snapshot)
	return &m, nil
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
