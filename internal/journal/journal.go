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

// Seq is a journal sequence number: the second half of the (stream-id, seq)
// coordinate, and a 64-bit unsigned integer.
//
// In JSON it is a string holding its exact decimal form, not a number. JSON
// numbers are IEEE-754 doubles in many readers — JavaScript's among them — which
// represent integers exactly only up to 2^53, so a number-encoded sequence near
// the top of the range comes back rounded and no longer agrees with the sequence
// in its own object key. A string is read exactly by every conformant parser.
type Seq uint64

// String returns the exact decimal form of a sequence number: no leading zeros,
// no sign, no whitespace.
func (s Seq) String() string {
	return strconv.FormatUint(uint64(s), 10)
}

// MarshalJSON encodes a sequence number as a JSON string holding its exact decimal form.
func (s Seq) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// UnmarshalJSON decodes a sequence number from a JSON string holding its exact
// decimal form. A JSON number is refused, and so is a string that is not the
// exact decimal form of the value it names: a rounded or reformatted sequence
// derives the wrong object key, so it is refused rather than silently accepted.
func (s *Seq) UnmarshalJSON(data []byte) error {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return fmt.Errorf("%w: sequence must be a JSON string holding its decimal form, got %s", ErrInvalidSeq, data)
	}
	seq, err := ParseSeqDecimal(string(data[1 : len(data)-1]))
	if err != nil {
		return err
	}
	*s = seq
	return nil
}

// ParseSeqDecimal parses the exact decimal form of a sequence number: no leading
// zeros, no sign, no whitespace, nothing a re-encoding would introduce.
func ParseSeqDecimal(s string) (Seq, error) {
	seq, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrInvalidSeq, err)
	}
	if strconv.FormatUint(seq, 10) != s {
		return 0, fmt.Errorf("%w: %q is not the exact decimal form of %d", ErrInvalidSeq, s, seq)
	}
	return Seq(seq), nil
}

// FormatSeq formats a 64-bit unsigned sequence number as a 20-digit zero-padded decimal string.
// This guarantees that UTF-8 / ASCII lexicographical ordering matches numerical sequence order.
func FormatSeq(seq Seq) string {
	return fmt.Sprintf("%020d", uint64(seq))
}

// ParseSeq parses a 20-digit zero-padded sequence string into a sequence number.
func ParseSeq(s string) (Seq, error) {
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
	return Seq(seq), nil
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
func TxKey(stream StreamID, seq Seq) string {
	return fmt.Sprintf("%s/streams/%s/tx/%020d.json", VersionPrefix, stream, uint64(seq))
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
	AppendRefTx(ctx context.Context, stream StreamID, expectedSeq Seq, segments []string, updates []RefUpdate) (Seq, error)
}
