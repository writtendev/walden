// Package journal implements walden's append-only write-ahead log in object storage.
// Per ARCHITECTURE.md: "The journal is the design. Everything else is plumbing around it."
// Per spec/journal/v1/README.md: The format defines (stream-id, seq) as its primary coordinate.
package journal

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	ErrFenced         = errors.New("fenced: stale writer condition failed")
	ErrStreamNotFound = errors.New("journal stream not found")
	ErrInvalidStream  = errors.New("invalid stream id")
	ErrInvalidSeq     = errors.New("invalid sequence format")
	ErrInvalidHash    = errors.New("invalid hash format")
)

// StreamID uniquely identifies a journal stream (e.g. a repository or meta stream).
type StreamID string

// MetaStreamID is the reserved stream ID for configuration and token state.
const MetaStreamID StreamID = "_meta"

// VersionPrefix is the root prefix for v1 journal objects.
const VersionPrefix = "v1"

var validStreamIDRegexp = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
var hex64Regexp = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// ValidateStreamID validates that a stream ID meets the v1 specification requirements.
func ValidateStreamID(stream StreamID) error {
	s := string(stream)
	if s == "" {
		return fmt.Errorf("%w: cannot be empty", ErrInvalidStream)
	}
	if len(s) > 255 {
		return fmt.Errorf("%w: length %d exceeds maximum of 255 bytes", ErrInvalidStream, len(s))
	}
	if strings.Contains(s, "..") {
		return fmt.Errorf("%w: path traversal sequences are not allowed", ErrInvalidStream)
	}
	if strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") {
		return fmt.Errorf("%w: leading or trailing slashes are not allowed", ErrInvalidStream)
	}
	if !validStreamIDRegexp.MatchString(s) {
		return fmt.Errorf("%w: must contain only [a-zA-Z0-9._-]", ErrInvalidStream)
	}
	return nil
}

// FormatSeq formats a 64-bit unsigned sequence number as a 20-digit zero-padded decimal string.
// This guarantees that UTF-8 / ASCII lexicographical ordering matches numerical sequence order.
func FormatSeq(seq uint64) string {
	return fmt.Sprintf("%020d", seq)
}

// ParseSeq parses a 20-digit zero-padded sequence string into a uint64.
func ParseSeq(s string) (uint64, error) {
	if len(s) != 20 {
		return 0, fmt.Errorf("%w: sequence string must be exactly 20 digits, got %q", ErrInvalidSeq, s)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("%w: sequence string contains non-digit characters: %q", ErrInvalidSeq, s)
		}
	}
	seq, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrInvalidSeq, err)
	}
	return seq, nil
}

// StreamPrefix returns the base object prefix for a stream: "v1/streams/<stream-id>/".
func StreamPrefix(stream StreamID) string {
	return fmt.Sprintf("%s/streams/%s/", VersionPrefix, stream)
}

// TxPrefix returns the transaction listing prefix for a stream: "v1/streams/<stream-id>/tx/".
func TxPrefix(stream StreamID) string {
	return fmt.Sprintf("%s/streams/%s/tx/", VersionPrefix, stream)
}

// TxKey returns the object storage key for a transaction: "v1/streams/<stream-id>/tx/<seq>.json".
func TxKey(stream StreamID, seq uint64) string {
	return fmt.Sprintf("%s/streams/%s/tx/%020d.json", VersionPrefix, stream, seq)
}

// SegmentPrefix returns the segment listing prefix for a stream: "v1/streams/<stream-id>/segments/".
func SegmentPrefix(stream StreamID) string {
	return fmt.Sprintf("%s/streams/%s/segments/", VersionPrefix, stream)
}

// SegmentKey returns the object storage key for a pack segment: "v1/streams/<stream-id>/segments/<sha256>.pack".
func SegmentKey(stream StreamID, sha256Hex string) string {
	return fmt.Sprintf("%s/streams/%s/segments/%s.pack", VersionPrefix, stream, strings.ToLower(sha256Hex))
}

// SnapshotPrefix returns the snapshot listing prefix for a stream: "v1/streams/<stream-id>/snapshots/".
func SnapshotPrefix(stream StreamID) string {
	return fmt.Sprintf("%s/streams/%s/snapshots/", VersionPrefix, stream)
}

// SnapshotKey returns the object storage key for a snapshot packfile: "v1/streams/<stream-id>/snapshots/<sha256>.pack".
func SnapshotKey(stream StreamID, sha256Hex string) string {
	return fmt.Sprintf("%s/streams/%s/snapshots/%s.pack", VersionPrefix, stream, strings.ToLower(sha256Hex))
}

// MarkerKey returns the object storage key for the replay marker: "v1/streams/<stream-id>/marker.json".
func MarkerKey(stream StreamID) string {
	return fmt.Sprintf("%s/streams/%s/marker.json", VersionPrefix, stream)
}

// ValidateHash validates that a string is a 64-character hexadecimal SHA-256 hash.
func ValidateHash(hash string) error {
	if !hex64Regexp.MatchString(hash) {
		return fmt.Errorf("%w: must be 64 hexadecimal characters, got %q", ErrInvalidHash, hash)
	}
	return nil
}

// RefUpdate represents a single ref transition (e.g., refs/heads/main: OldOID -> NewOID).
// Ref names are stored as raw byte sequences.
type RefUpdate struct {
	Ref    string `json:"ref"`
	OldOID string `json:"old_oid"`
	NewOID string `json:"new_oid"`
}

// Journal represents the write-ahead append-only log interface.
type Journal interface {
	// AppendRefTx conditionally appends a ref transaction to the specified stream.
	AppendRefTx(ctx context.Context, stream StreamID, expectedSeq uint64, segments []string, updates []RefUpdate) (uint64, error)
}
