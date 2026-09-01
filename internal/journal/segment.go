package journal

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/writtendev/walden/internal/refusal"
)

var (
	// ErrInvalidPackfile indicates that a packfile is corrupted or malformed.
	ErrInvalidPackfile = errors.New("invalid packfile")

	// ErrHashMismatch indicates that a packfile's computed SHA-256 does not match its expected content hash.
	ErrHashMismatch = errors.New("segment hash mismatch")

	// ErrMissingSegment indicates that a referenced pack segment is missing in object storage.
	ErrMissingSegment = errors.New("missing pack segment")
)

const (
	// PackfileMagic is the 4-byte header magic for Git packfiles ("PACK").
	PackfileMagic = "PACK"

	// PackfileHeaderSize is the 12-byte header size (4 bytes magic, 4 bytes version, 4 bytes object count).
	PackfileHeaderSize = 12

	// PackfileMinSizeSHA1 is the minimum valid packfile size for SHA-1 repositories (12-byte header + 20-byte checksum).
	PackfileMinSizeSHA1 = 32

	// PackfileMinSizeSHA256 is the minimum valid packfile size for SHA-256 repositories (12-byte header + 32-byte checksum).
	PackfileMinSizeSHA256 = 44

	// PackfileMinSize is the minimum absolute size of any valid Git packfile (32 bytes).
	PackfileMinSize = PackfileMinSizeSHA1

	// ContentTypeGitPackedObjects is the standard MIME type for Git packfiles.
	ContentTypeGitPackedObjects = "application/x-git-packed-objects"

	// MetaHeaderStream is the S3 user metadata header key for stream ID.
	MetaHeaderStream = "x-amz-meta-walden-stream"

	// MetaHeaderHash is the S3 user metadata header key for segment hash.
	MetaHeaderHash = "x-amz-meta-walden-hash"
)

// ComputeSegmentHash computes the 64-character lowercase hexadecimal SHA-256 digest over raw packfile bytes verbatim.
func ComputeSegmentHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ComputeSegmentHashFromReader streams bytes from an io.Reader and returns the 64-character lowercase hex SHA-256 digest and total bytes read.
func ComputeSegmentHashFromReader(r io.Reader) (string, int64, error) {
	if r == nil {
		return "", 0, fmt.Errorf("%w: reader cannot be nil", ErrInvalidPackfile)
	}
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return "", n, fmt.Errorf("failed to compute segment hash: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// ValidatePackfileHeader validates that data contains a valid Git packfile header.
// It checks minimum length (>= 32 bytes for SHA-1 repositories), the 'PACK' magic prefix, and supported version (2 or 3).
func ValidatePackfileHeader(data []byte) error {
	if len(data) < PackfileMinSize {
		return fmt.Errorf("%w: length %d is less than minimum packfile size of %d bytes", ErrInvalidPackfile, len(data), PackfileMinSize)
	}
	if string(data[:4]) != PackfileMagic {
		return fmt.Errorf("%w: invalid header magic %q (expected %q)", ErrInvalidPackfile, string(data[:4]), PackfileMagic)
	}
	version := binary.BigEndian.Uint32(data[4:8])
	if version != 2 && version != 3 {
		return fmt.Errorf("%w: unsupported packfile version %d (expected 2 or 3)", ErrInvalidPackfile, version)
	}
	return nil
}

// ValidatePackfileHeaderSHA256 validates that data contains a valid Git packfile header for SHA-256 repositories (>= 44 bytes).
func ValidatePackfileHeaderSHA256(data []byte) error {
	if len(data) < PackfileMinSizeSHA256 {
		return fmt.Errorf("%w: length %d is less than minimum SHA-256 packfile size of %d bytes", ErrInvalidPackfile, len(data), PackfileMinSizeSHA256)
	}
	return ValidatePackfileHeader(data)
}

// ValidateSegment validates that data is a valid Git packfile and that its SHA-256 hash matches expectedHash.
func ValidateSegment(data []byte, expectedHash string) error {
	if err := ValidateHash(expectedHash); err != nil {
		return fmt.Errorf("%w: invalid expected hash: %w", ErrInvalidPackfile, err)
	}
	if err := ValidatePackfileHeader(data); err != nil {
		return err
	}
	computed := ComputeSegmentHash(data)
	if !strings.EqualFold(computed, expectedHash) {
		return fmt.Errorf("%w: expected %s, got %s", ErrHashMismatch, strings.ToLower(expectedHash), computed)
	}
	return nil
}

// SegmentMetadata returns the standard S3 user metadata key-value pairs for a pack segment upload.
func SegmentMetadata(stream StreamID, sha256Hex string) map[string]string {
	return map[string]string{
		MetaHeaderStream: string(stream),
		MetaHeaderHash:   strings.ToLower(sha256Hex),
	}
}

// SegmentContentType returns the HTTP Content-Type header value for Git packfiles.
func SegmentContentType() string {
	return ContentTypeGitPackedObjects
}

// RefuseMissingSegment returns a single-line operator-facing refusal when a referenced pack segment is missing.
func RefuseMissingSegment(stream StreamID, sha256Hex string) error {
	return refusal.RefuseWithCause(
		"refusal: replay failed",
		fmt.Sprintf("missing pack segment %s on stream %s", strings.ToLower(sha256Hex), stream),
		"verify object storage bucket integrity or restore from backup",
		ErrMissingSegment,
	)
}

// RefuseSegmentHashMismatch returns a single-line operator-facing refusal when a downloaded pack segment does not match its hash.
func RefuseSegmentHashMismatch(stream StreamID, expectedHash, computedHash string) error {
	return refusal.RefuseWithCause(
		"refusal: replay failed",
		fmt.Sprintf("segment hash mismatch for %s on stream %s (computed %s)", strings.ToLower(expectedHash), stream, computedHash),
		"pack segment in object storage is corrupt",
		ErrHashMismatch,
	)
}

// RefuseCorruptSegment returns a single-line operator-facing refusal when a pack segment header or payload is corrupt.
func RefuseCorruptSegment(stream StreamID, sha256Hex string, reason error) error {
	return refusal.RefuseWithCause(
		"refusal: replay failed",
		fmt.Sprintf("corrupt pack segment %s on stream %s (%v)", strings.ToLower(sha256Hex), stream, reason),
		"packfile header is malformed",
		ErrInvalidPackfile,
	)
}
