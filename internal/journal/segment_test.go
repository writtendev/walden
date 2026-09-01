package journal_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
)

// validEmptyPackfile returns the 32-byte binary content of a valid 0-object Git packfile (SHA-1).
func validEmptyPackfile() []byte {
	return append([]byte("PACK\x00\x00\x00\x02\x00\x00\x00\x00"), []byte("\x02\x0a\x64\x03\x02\xdd\x49\x24\x73\x4f\x5a\x6e\x53\x04\x82\x5d\x79\x43\x9c\xb9")...)
}

// validEmptyPackfileSHA256 returns the 44-byte binary content of a valid 0-object Git packfile (SHA-256).
func validEmptyPackfileSHA256() []byte {
	header := []byte("PACK\x00\x00\x00\x02\x00\x00\x00\x00")
	// For SHA-256 Git repositories, the 32-byte trailing checksum is SHA-256 over all preceding bytes.
	sum := sha256.Sum256(header)
	return append(header, sum[:]...)
}

func TestComputeSegmentHash(t *testing.T) {
	data := validEmptyPackfile()
	hash := journal.ComputeSegmentHash(data)

	expected := "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db"
	if hash != expected {
		t.Errorf("ComputeSegmentHash = %q, want %q", hash, expected)
	}
	if len(hash) != 64 {
		t.Errorf("expected 64 hex characters, got %d", len(hash))
	}
	if hash != strings.ToLower(hash) {
		t.Errorf("expected lowercase hex hash, got %q", hash)
	}

	// Test streaming reader
	readerHash, n, err := journal.ComputeSegmentHashFromReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ComputeSegmentHashFromReader failed: %v", err)
	}
	if int(n) != len(data) {
		t.Errorf("expected %d bytes read, got %d", len(data), n)
	}
	if readerHash != expected {
		t.Errorf("reader hash = %q, want %q", readerHash, expected)
	}

	// Test streaming reader with nil reader
	_, _, err = journal.ComputeSegmentHashFromReader(nil)
	if err == nil {
		t.Fatalf("expected error from nil reader, got nil")
	}

	// Test streaming reader error
	errExpected := errors.New("simulated read error")
	errReader := &failingReader{err: errExpected}
	_, _, err = journal.ComputeSegmentHashFromReader(errReader)
	if err == nil {
		t.Fatalf("expected error from failing reader, got nil")
	}
	if !errors.Is(err, errExpected) {
		t.Errorf("expected wrapped simulated error, got %v", err)
	}
}

type failingReader struct {
	err error
}

func (f *failingReader) Read(p []byte) (n int, err error) {
	return 0, f.err
}

func TestValidatePackfileHeader(t *testing.T) {
	valid := validEmptyPackfile()
	if err := journal.ValidatePackfileHeader(valid); err != nil {
		t.Errorf("expected valid packfile header, got error: %v", err)
	}

	// Valid with version 3
	validV3 := make([]byte, len(valid))
	copy(validV3, valid)
	validV3[7] = 3
	if err := journal.ValidatePackfileHeader(validV3); err != nil {
		t.Errorf("expected valid version 3 packfile header, got error: %v", err)
	}

	invalid := []struct {
		name string
		data []byte
		err  string
	}{
		{"empty", []byte{}, "less than minimum packfile size"},
		{"too short (12 bytes)", []byte("PACK\x00\x00\x00\x02\x00\x00\x00\x00"), "less than minimum packfile size"},
		{"too short (31 bytes)", make([]byte, 31), "less than minimum packfile size"},
		{"wrong magic", append([]byte("GITP\x00\x00\x00\x02\x00\x00\x00\x00"), make([]byte, 20)...), "invalid header magic"},
		{"unsupported version 1", append([]byte("PACK\x00\x00\x00\x01\x00\x00\x00\x00"), make([]byte, 20)...), "unsupported packfile version"},
		{"unsupported version 4", append([]byte("PACK\x00\x00\x00\x04\x00\x00\x00\x00"), make([]byte, 20)...), "unsupported packfile version"},
	}

	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			err := journal.ValidatePackfileHeader(tc.data)
			if err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
				return
			}
			if !errors.Is(err, journal.ErrInvalidPackfile) {
				t.Errorf("expected ErrInvalidPackfile, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.err) {
				t.Errorf("expected error containing %q, got %q", tc.err, err.Error())
			}
		})
	}
}

func TestValidatePackfileHeaderSHA256(t *testing.T) {
	validSHA256 := validEmptyPackfileSHA256()
	if len(validSHA256) != 44 {
		t.Fatalf("expected 44 bytes for SHA-256 empty packfile, got %d", len(validSHA256))
	}
	if err := journal.ValidatePackfileHeaderSHA256(validSHA256); err != nil {
		t.Errorf("expected valid SHA-256 packfile header, got error: %v", err)
	}

	// 32-byte SHA-1 packfile is too short for SHA-256 repositories
	sha1Pack := validEmptyPackfile()
	err := journal.ValidatePackfileHeaderSHA256(sha1Pack)
	if err == nil || !errors.Is(err, journal.ErrInvalidPackfile) {
		t.Errorf("expected ErrInvalidPackfile for 32-byte pack in SHA-256 validator, got %v", err)
	}
	if !strings.Contains(err.Error(), "minimum SHA-256 packfile size of 44 bytes") {
		t.Errorf("unexpected error message: %v", err)
	}

	// 43-byte truncated packfile
	truncated := make([]byte, 43)
	copy(truncated, validSHA256[:43])
	err = journal.ValidatePackfileHeaderSHA256(truncated)
	if err == nil || !errors.Is(err, journal.ErrInvalidPackfile) {
		t.Errorf("expected ErrInvalidPackfile for 43-byte pack, got %v", err)
	}

	// Invalid magic with 44 bytes
	badMagic := append([]byte("GITP\x00\x00\x00\x02\x00\x00\x00\x00"), make([]byte, 32)...)
	err = journal.ValidatePackfileHeaderSHA256(badMagic)
	if err == nil || !errors.Is(err, journal.ErrInvalidPackfile) {
		t.Errorf("expected ErrInvalidPackfile for bad magic, got %v", err)
	}
}

func TestValidateSegment(t *testing.T) {
	data := validEmptyPackfile()
	expectedHash := "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db"

	// Valid
	if err := journal.ValidateSegment(data, expectedHash); err != nil {
		t.Errorf("expected ValidateSegment to succeed, got: %v", err)
	}

	// Case-insensitive hash match
	if err := journal.ValidateSegment(data, strings.ToUpper(expectedHash)); err != nil {
		t.Errorf("expected case-insensitive hash match to succeed, got: %v", err)
	}

	// Hash mismatch
	wrongHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	err := journal.ValidateSegment(data, wrongHash)
	if err == nil || !errors.Is(err, journal.ErrHashMismatch) {
		t.Errorf("expected ErrHashMismatch, got %v", err)
	}

	// Invalid expected hash format
	err = journal.ValidateSegment(data, "not-a-hash")
	if err == nil || !errors.Is(err, journal.ErrInvalidPackfile) {
		t.Errorf("expected ErrInvalidPackfile for invalid hash format, got %v", err)
	}

	// Corrupt packfile data
	corruptData := make([]byte, 32)
	err = journal.ValidateSegment(corruptData, expectedHash)
	if err == nil || !errors.Is(err, journal.ErrInvalidPackfile) {
		t.Errorf("expected ErrInvalidPackfile for corrupt data, got %v", err)
	}

	// Valid SHA-256 packfile
	sha256Data := validEmptyPackfileSHA256()
	sha256Hash := journal.ComputeSegmentHash(sha256Data)
	if err := journal.ValidateSegment(sha256Data, sha256Hash); err != nil {
		t.Errorf("expected ValidateSegment on SHA-256 packfile to succeed, got: %v", err)
	}
}

func TestSegmentMetadataAndContentType(t *testing.T) {
	stream := journal.StreamID("repo-alpha")
	hash := "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db"

	meta := journal.SegmentMetadata(stream, strings.ToUpper(hash))
	if meta[journal.MetaHeaderStream] != "repo-alpha" {
		t.Errorf("expected stream %q, got %q", "repo-alpha", meta[journal.MetaHeaderStream])
	}
	if meta[journal.MetaHeaderHash] != hash {
		t.Errorf("expected lowercase hash %q, got %q", hash, meta[journal.MetaHeaderHash])
	}

	if journal.SegmentContentType() != "application/x-git-packed-objects" {
		t.Errorf("expected Content-Type application/x-git-packed-objects, got %q", journal.SegmentContentType())
	}
}

func TestSegmentRefusalFormatting(t *testing.T) {
	stream := journal.StreamID("repo-alpha")
	hash := "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db"

	// 1. Missing segment refusal
	err := journal.RefuseMissingSegment(stream, hash)
	if err == nil {
		t.Fatalf("expected refusal error, got nil")
	}
	var ref *refusal.Refusal
	if !errors.As(err, &ref) {
		t.Fatalf("expected *refusal.Refusal type, got %T", err)
	}
	if !errors.Is(err, journal.ErrMissingSegment) {
		t.Errorf("expected errors.Is(err, ErrMissingSegment) to be true")
	}
	msg := err.Error()
	if strings.Contains(msg, "\n") {
		t.Errorf("refusal message contains newline: %q", msg)
	}
	if !strings.HasPrefix(msg, "refusal: replay failed: missing pack segment 2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db on stream repo-alpha") {
		t.Errorf("unexpected refusal message format: %q", msg)
	}

	// 2. Hash mismatch refusal
	computed := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	err = journal.RefuseSegmentHashMismatch(stream, hash, computed)
	if !errors.Is(err, journal.ErrHashMismatch) {
		t.Errorf("expected errors.Is(err, ErrHashMismatch) to be true")
	}
	msg = err.Error()
	if strings.Contains(msg, "\n") {
		t.Errorf("refusal message contains newline: %q", msg)
	}
	if !strings.HasPrefix(msg, "refusal: replay failed: segment hash mismatch for 2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db on stream repo-alpha (computed e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)") {
		t.Errorf("unexpected hash mismatch refusal format: %q", msg)
	}

	// 3. Corrupt segment refusal
	err = journal.RefuseCorruptSegment(stream, hash, journal.ErrInvalidPackfile)
	if !errors.Is(err, journal.ErrInvalidPackfile) {
		t.Errorf("expected errors.Is(err, ErrInvalidPackfile) to be true")
	}
	msg = err.Error()
	if strings.Contains(msg, "\n") {
		t.Errorf("refusal message contains newline: %q", msg)
	}
	if !strings.HasPrefix(msg, "refusal: replay failed: corrupt pack segment 2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db on stream repo-alpha") {
		t.Errorf("unexpected corrupt segment refusal format: %q", msg)
	}
}

func TestIdempotentSegmentStorage(t *testing.T) {
	// Re-uploading identical bytes produces identical content-addressed key and hash
	pack1 := validEmptyPackfile()
	pack2 := validEmptyPackfile()

	h1 := journal.ComputeSegmentHash(pack1)
	h2 := journal.ComputeSegmentHash(pack2)

	if h1 != h2 {
		t.Errorf("expected deterministic hash for identical packfiles: %q vs %q", h1, h2)
	}

	k1 := journal.SegmentKey("repo-test", h1)
	k2 := journal.SegmentKey("repo-test", h2)
	if k1 != k2 {
		t.Errorf("expected identical key for identical segment uploads: %q vs %q", k1, k2)
	}
}

func TestValidateSegmentFromReader(t *testing.T) {
	pack := validEmptyPackfile()
	hash := journal.ComputeSegmentHash(pack)

	// 1. Valid streaming segment
	n, err := journal.ValidateSegmentFromReader(bytes.NewReader(pack), hash)
	if err != nil {
		t.Fatalf("ValidateSegmentFromReader failed: %v", err)
	}
	if n != int64(len(pack)) {
		t.Errorf("bytes read = %d, want %d", n, len(pack))
	}

	// 2. Case-insensitive hash
	n, err = journal.ValidateSegmentFromReader(bytes.NewReader(pack), strings.ToUpper(hash))
	if err != nil {
		t.Fatalf("ValidateSegmentFromReader with uppercase hash failed: %v", err)
	}
	if n != int64(len(pack)) {
		t.Errorf("bytes read = %d, want %d", n, len(pack))
	}

	// 3. Nil reader
	_, err = journal.ValidateSegmentFromReader(nil, hash)
	if err == nil || !errors.Is(err, journal.ErrInvalidPackfile) {
		t.Errorf("expected ErrInvalidPackfile for nil reader, got %v", err)
	}

	// 4. Invalid expected hash
	_, err = journal.ValidateSegmentFromReader(bytes.NewReader(pack), "not-a-hash")
	if err == nil || !errors.Is(err, journal.ErrInvalidPackfile) {
		t.Errorf("expected ErrInvalidPackfile for invalid hash format, got %v", err)
	}

	// 5. Short stream (< 32 bytes)
	_, err = journal.ValidateSegmentFromReader(bytes.NewReader([]byte("PACK short")), hash)
	if err == nil || !errors.Is(err, journal.ErrInvalidPackfile) {
		t.Errorf("expected ErrInvalidPackfile for short stream, got %v", err)
	}

	// 6. Corrupt header magic
	corruptHdr := make([]byte, 32)
	copy(corruptHdr, pack)
	corruptHdr[0] = 'X'
	_, err = journal.ValidateSegmentFromReader(bytes.NewReader(corruptHdr), hash)
	if err == nil || !errors.Is(err, journal.ErrInvalidPackfile) {
		t.Errorf("expected ErrInvalidPackfile for corrupt header, got %v", err)
	}

	// 7. Hash mismatch
	wrongHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	_, err = journal.ValidateSegmentFromReader(bytes.NewReader(pack), wrongHash)
	if err == nil || !errors.Is(err, journal.ErrHashMismatch) {
		t.Errorf("expected ErrHashMismatch, got %v", err)
	}
}
