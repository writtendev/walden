package journal_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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

func TestGoldenPackSegmentFixtures(t *testing.T) {
	fixturesDir := filepath.Join("..", "..", "spec", "journal", "v1", "fixtures")
	if _, err := os.Stat(fixturesDir); os.IsNotExist(err) {
		t.Skipf("fixtures directory %s does not exist", fixturesDir)
	}

	// 1. Read segment packfile fixture
	expectedHash := "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db"
	segPath := filepath.Join(fixturesDir, "streams", "repo-alpha", "segments", expectedHash+".pack")
	data, err := os.ReadFile(segPath)
	if err != nil {
		t.Fatalf("failed to read segment fixture at %s: %v", segPath, err)
	}

	if len(data) != 32 {
		t.Errorf("expected segment fixture length 32 bytes, got %d", len(data))
	}

	if err := journal.ValidateSegment(data, expectedHash); err != nil {
		t.Errorf("ValidateSegment failed on golden segment fixture: %v", err)
	}

	// 2. Read snapshot packfile fixture
	snapPath := filepath.Join(fixturesDir, "streams", "repo-alpha", "snapshots", expectedHash+".pack")
	snapData, err := os.ReadFile(snapPath)
	if err != nil {
		t.Fatalf("failed to read snapshot fixture at %s: %v", snapPath, err)
	}

	if !bytes.Equal(data, snapData) {
		t.Errorf("snapshot fixture bytes do not match segment fixture bytes")
	}

	if err := journal.ValidateSegment(snapData, expectedHash); err != nil {
		t.Errorf("ValidateSegment failed on golden snapshot fixture: %v", err)
	}

	// 3. Verify all segments referenced in repo-alpha/tx/*.json match their files
	txFiles, err := filepath.Glob(filepath.Join(fixturesDir, "streams", "repo-alpha", "tx", "*.json"))
	if err != nil {
		t.Fatalf("failed to glob tx files: %v", err)
	}
	if len(txFiles) == 0 {
		t.Fatalf("expected repo-alpha tx fixtures to exist")
	}

	for _, txFile := range txFiles {
		txData, err := os.ReadFile(txFile)
		if err != nil {
			t.Fatalf("failed to read tx fixture %s: %v", txFile, err)
		}
		var tx journal.RefTransactionRecord
		if err := json.Unmarshal(txData, &tx); err != nil {
			t.Fatalf("failed to parse tx fixture %s: %v", txFile, err)
		}
		for _, segHash := range tx.Segments {
			segFixture := filepath.Join(fixturesDir, "streams", "repo-alpha", "segments", segHash+".pack")
			content, err := os.ReadFile(segFixture)
			if err != nil {
				t.Errorf("referenced segment %s in %s does not exist on disk: %v", segHash, txFile, err)
				continue
			}
			computed := journal.ComputeSegmentHash(content)
			if computed != segHash {
				t.Errorf("segment fixture %s hash mismatch: got %s, want %s", segFixture, computed, segHash)
			}
			if err := journal.ValidatePackfileHeader(content); err != nil {
				t.Errorf("segment fixture %s invalid packfile header: %v", segFixture, err)
			}
		}
	}
}

// TestSignFixtureHelper prints / generates the exact signed json fixtures.
func TestSignFixtureHelper(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 0x01
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	t.Logf("Genesis pub: %s", journal.FormatPublicKey(pub))

	hash := "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db"

	tx0 := &journal.RefTransactionRecord{
		Version: "v1",
		Stream:  "repo-alpha",
		Seq:     0,
		Type:    "ref_update",
		Segments: []string{
			hash,
		},
		Updates: []journal.RefUpdate{
			{
				Ref:    "refs/heads/main",
				OldOID: "0000000000000000000000000000000000000000",
				NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
			},
		},
		Timestamp: "2026-08-31T00:02:00Z",
	}
	if err := journal.SignRefTx(priv, tx0); err != nil {
		t.Fatalf("SignRefTx 0 failed: %v", err)
	}
	t.Logf("tx0 sig: %s", tx0.Signature)

	tx1 := &journal.RefTransactionRecord{
		Version: "v1",
		Stream:  "repo-alpha",
		Seq:     1,
		Type:    "ref_update",
		Segments: []string{
			hash,
		},
		Updates: []journal.RefUpdate{
			{
				Ref:    "refs/heads/main",
				OldOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
				NewOID: "8a65c6d3715c0e1e92d6e3e5362e49c7198cfb60",
			},
			{
				Ref:    "refs/heads/feature",
				OldOID: "0000000000000000000000000000000000000000",
				NewOID: "8a65c6d3715c0e1e92d6e3e5362e49c7198cfb60",
			},
		},
		Timestamp: "2026-08-31T00:03:00Z",
	}
	if err := journal.SignRefTx(priv, tx1); err != nil {
		t.Fatalf("SignRefTx 1 failed: %v", err)
	}
	t.Logf("tx1 sig: %s", tx1.Signature)
}
