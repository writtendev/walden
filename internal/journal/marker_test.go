package journal_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
)

func TestParseMarkerValid(t *testing.T) {
	raw := `{
		"version": "v1",
		"stream": "repo-beta",
		"sequence": "42",
		"snapshot": "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db",
		"timestamp": "2026-08-31T01:00:00Z"
	}`

	m, err := journal.ParseMarker([]byte(raw))
	if err != nil {
		t.Fatalf("ParseMarker failed: %v", err)
	}

	if m.Version != "v1" {
		t.Errorf("Version = %q, want %q", m.Version, "v1")
	}
	if m.Stream != "repo-beta" {
		t.Errorf("Stream = %q, want %q", m.Stream, "repo-beta")
	}
	if m.Sequence != 42 {
		t.Errorf("Sequence = %d, want 42", m.Sequence)
	}
	if m.Snapshot != "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db" {
		t.Errorf("Snapshot = %q, want %q", m.Snapshot, "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db")
	}
	if m.Timestamp != "2026-08-31T01:00:00Z" {
		t.Errorf("Timestamp = %q, want %q", m.Timestamp, "2026-08-31T01:00:00Z")
	}
}

func TestMarshalMarkerRoundTrip(t *testing.T) {
	orig := &journal.Marker{
		Version:   "v1",
		Stream:    "repo-gamma",
		Sequence:  100,
		Snapshot:  "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db",
		Timestamp: "2026-08-31T02:00:00Z",
	}

	data, err := journal.MarshalMarker(orig)
	if err != nil {
		t.Fatalf("MarshalMarker failed: %v", err)
	}

	if !strings.HasSuffix(string(data), "\n") {
		t.Errorf("expected trailing newline in marshaled marker JSON")
	}

	parsed, err := journal.ParseMarker(data)
	if err != nil {
		t.Fatalf("ParseMarker failed on marshaled data: %v", err)
	}

	if parsed.Version != orig.Version ||
		parsed.Stream != orig.Stream ||
		parsed.Sequence != orig.Sequence ||
		parsed.Snapshot != orig.Snapshot ||
		parsed.Timestamp != orig.Timestamp {
		t.Errorf("round-trip mismatch: got %+v, want %+v", parsed, orig)
	}

	// Uppercase snapshot hash should be normalized to lowercase
	origUpper := *orig
	origUpper.Snapshot = strings.ToUpper(orig.Snapshot)
	dataUpper, err := journal.MarshalMarker(&origUpper)
	if err != nil {
		t.Fatalf("MarshalMarker with uppercase hash failed: %v", err)
	}
	parsedUpper, err := journal.ParseMarker(dataUpper)
	if err != nil {
		t.Fatalf("ParseMarker with uppercase hash failed: %v", err)
	}
	if parsedUpper.Snapshot != strings.ToLower(orig.Snapshot) {
		t.Errorf("expected lowercase snapshot hash, got %q", parsedUpper.Snapshot)
	}
}

func TestParseMarkerInvalidJSON(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"empty data", []byte{}},
		{"nil data", nil},
		{"invalid json syntax", []byte("{not-json}")},
		{"truncated json", []byte(`{"version": "v1", "stream": `)},
		{"non-object json array", []byte(`["v1", "repo-alpha"]`)},
		{"non-object json scalar", []byte(`"v1"`)},
		// Section 1.1: the sequence is a JSON string holding its exact decimal form. A
		// number is refused rather than coerced, and so is a string that has been rounded
		// or reformatted — either one names a baseline that is not the one written.
		{"sequence as a json number", []byte(`{
			"version": "v1",
			"stream": "repo-beta",
			"sequence": 42,
			"snapshot": "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db",
			"timestamp": "2026-08-31T01:00:00Z"
		}`)},
		{"sequence with leading zeros", []byte(`{
			"version": "v1",
			"stream": "repo-beta",
			"sequence": "042",
			"snapshot": "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db",
			"timestamp": "2026-08-31T01:00:00Z"
		}`)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := journal.ParseMarker(tc.data)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
			if !errors.Is(err, journal.ErrCorruptMarker) {
				t.Errorf("expected ErrCorruptMarker, got %v", err)
			}
		})
	}
}

func TestValidateMarkerErrors(t *testing.T) {
	validHash := "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db"
	validTime := "2026-08-31T01:00:00Z"

	// 1. Nil marker
	var nilMarker *journal.Marker
	if err := nilMarker.Validate(); err == nil || !errors.Is(err, journal.ErrInvalidMarker) {
		t.Errorf("expected ErrInvalidMarker for nil marker, got %v", err)
	}
	if err := journal.ValidateMarker(nilMarker); err == nil || !errors.Is(err, journal.ErrInvalidMarker) {
		t.Errorf("expected ErrInvalidMarker from ValidateMarker(nil), got %v", err)
	}
	if _, err := journal.MarshalMarker(nilMarker); err == nil || !errors.Is(err, journal.ErrInvalidMarker) {
		t.Errorf("expected ErrInvalidMarker from MarshalMarker(nil), got %v", err)
	}

	invalidCases := []struct {
		name   string
		marker *journal.Marker
		errSub string
	}{
		{
			name: "unsupported version v2",
			marker: &journal.Marker{
				Version:   "v2",
				Stream:    "repo-alpha",
				Sequence:  0,
				Snapshot:  validHash,
				Timestamp: validTime,
			},
			errSub: "unsupported version",
		},
		{
			name: "meta stream rejected",
			marker: &journal.Marker{
				Version:   "v1",
				Stream:    journal.MetaStreamID,
				Sequence:  0,
				Snapshot:  validHash,
				Timestamp: validTime,
			},
			errSub: "meta stream",
		},
		{
			name: "empty stream",
			marker: &journal.Marker{
				Version:   "v1",
				Stream:    "",
				Sequence:  0,
				Snapshot:  validHash,
				Timestamp: validTime,
			},
			errSub: "invalid stream",
		},
		{
			name: "invalid stream characters",
			marker: &journal.Marker{
				Version:   "v1",
				Stream:    "repo/alpha",
				Sequence:  0,
				Snapshot:  validHash,
				Timestamp: validTime,
			},
			errSub: "invalid stream",
		},
		{
			name: "invalid snapshot hash length",
			marker: &journal.Marker{
				Version:   "v1",
				Stream:    "repo-alpha",
				Sequence:  0,
				Snapshot:  "2fe16ead",
				Timestamp: validTime,
			},
			errSub: "invalid snapshot hash",
		},
		{
			name: "invalid snapshot non-hex characters",
			marker: &journal.Marker{
				Version:   "v1",
				Stream:    "repo-alpha",
				Sequence:  0,
				Snapshot:  strings.Repeat("z", 64),
				Timestamp: validTime,
			},
			errSub: "invalid snapshot hash",
		},
		{
			name: "empty timestamp",
			marker: &journal.Marker{
				Version:   "v1",
				Stream:    "repo-alpha",
				Sequence:  0,
				Snapshot:  validHash,
				Timestamp: "",
			},
			errSub: "timestamp cannot be empty",
		},
		{
			name: "invalid timestamp format",
			marker: &journal.Marker{
				Version:   "v1",
				Stream:    "repo-alpha",
				Sequence:  0,
				Snapshot:  validHash,
				Timestamp: "not-a-date",
			},
			errSub: "invalid timestamp",
		},
		{
			name: "non-UTC timestamp",
			marker: &journal.Marker{
				Version:   "v1",
				Stream:    "repo-alpha",
				Sequence:  0,
				Snapshot:  validHash,
				Timestamp: "2026-08-31T01:00:00+05:00",
			},
			errSub: "timestamp must be in UTC",
		},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.marker.Validate()
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
			if !errors.Is(err, journal.ErrInvalidMarker) {
				t.Errorf("expected ErrInvalidMarker, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.errSub) {
				t.Errorf("expected error containing %q, got %q", tc.errSub, err.Error())
			}

			// ValidateMarker should produce identical error
			if err2 := journal.ValidateMarker(tc.marker); err2 == nil || !errors.Is(err2, journal.ErrInvalidMarker) {
				t.Errorf("ValidateMarker failed to match ErrInvalidMarker: %v", err2)
			}

			// MarshalMarker should refuse invalid marker
			if _, err2 := journal.MarshalMarker(tc.marker); err2 == nil || !errors.Is(err2, journal.ErrInvalidMarker) {
				t.Errorf("MarshalMarker failed to refuse invalid marker: %v", err2)
			}

			// ParseMarker on marshaled JSON of invalid struct should fail
			rawBytes, _ := json.Marshal(tc.marker)
			if _, err2 := journal.ParseMarker(rawBytes); err2 == nil || !errors.Is(err2, journal.ErrInvalidMarker) {
				t.Errorf("ParseMarker failed to refuse invalid marker JSON: %v", err2)
			}
		})
	}
}

func TestMarkerUnknownFieldsTolerance(t *testing.T) {
	rawWithUnknownFields := `{
		"version": "v1",
		"stream": "repo-alpha",
		"sequence": "15",
		"snapshot": "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db",
		"timestamp": "2026-08-31T01:00:00Z",
		"compactor_version": "1.2.0",
		"reachable_objects": 1520,
		"extra_metadata": {
			"duration_ms": 340,
			"pruned_bytes": 1048576
		}
	}`

	m, err := journal.ParseMarker([]byte(rawWithUnknownFields))
	if err != nil {
		t.Fatalf("ParseMarker failed on JSON with unknown fields: %v", err)
	}

	if m.Version != "v1" || m.Stream != "repo-alpha" || m.Sequence != 15 {
		t.Errorf("unexpected parsed marker values: %+v", m)
	}
}

func TestValidateSnapshot(t *testing.T) {
	// 1. Valid SHA-1 packfile snapshot
	sha1Pack := validEmptyPackfile()
	sha1Hash := journal.ComputeSegmentHash(sha1Pack)
	if err := journal.ValidateSnapshot(sha1Pack, sha1Hash); err != nil {
		t.Errorf("ValidateSnapshot failed on valid SHA-1 snapshot: %v", err)
	}

	// 2. Valid SHA-256 packfile snapshot
	sha256Pack := validEmptyPackfileSHA256()
	sha256Hash := journal.ComputeSegmentHash(sha256Pack)
	if err := journal.ValidateSnapshot(sha256Pack, sha256Hash); err != nil {
		t.Errorf("ValidateSnapshot failed on valid SHA-256 snapshot: %v", err)
	}

	// 3. Case-insensitive hash match
	if err := journal.ValidateSnapshot(sha1Pack, strings.ToUpper(sha1Hash)); err != nil {
		t.Errorf("ValidateSnapshot failed on uppercase expected hash: %v", err)
	}

	// 4. Hash mismatch
	wrongHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	err := journal.ValidateSnapshot(sha1Pack, wrongHash)
	if err == nil {
		t.Fatalf("expected error on hash mismatch, got nil")
	}
	if !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt, got %v", err)
	}
	if !errors.Is(err, journal.ErrSnapshotHashMismatch) {
		t.Errorf("expected ErrSnapshotHashMismatch, got %v", err)
	}

	// 5. Invalid expected hash format
	err = journal.ValidateSnapshot(sha1Pack, "invalid-hash")
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for bad hash format, got %v", err)
	}

	// 6. Corrupt packfile header
	corruptPack := make([]byte, 32)
	copy(corruptPack, sha1Pack)
	corruptPack[0] = 'B' // PACK -> BACK
	err = journal.ValidateSnapshot(corruptPack, sha1Hash)
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for corrupt header, got %v", err)
	}
	if !errors.Is(err, journal.ErrInvalidPackfile) {
		t.Errorf("expected ErrInvalidPackfile for corrupt header, got %v", err)
	}

	// 7. Truncated packfile (< 32 bytes)
	truncatedPack := make([]byte, 20)
	err = journal.ValidateSnapshot(truncatedPack, sha1Hash)
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for truncated pack, got %v", err)
	}
}

func TestValidateSnapshotSHA256(t *testing.T) {
	// 1. Valid SHA-256 packfile snapshot (>= 44 bytes)
	sha256Pack := validEmptyPackfileSHA256()
	sha256Hash := journal.ComputeSegmentHash(sha256Pack)
	if err := journal.ValidateSnapshotSHA256(sha256Pack, sha256Hash); err != nil {
		t.Errorf("ValidateSnapshotSHA256 failed on valid SHA-256 snapshot: %v", err)
	}

	// 2. Too short for SHA-256 repo (< 44 bytes, even if valid SHA-1 32 bytes)
	sha1Pack := validEmptyPackfile()
	sha1Hash := journal.ComputeSegmentHash(sha1Pack)
	err := journal.ValidateSnapshotSHA256(sha1Pack, sha1Hash)
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for 32-byte packfile in SHA-256 validation, got %v", err)
	}

	// 3. Invalid expected hash
	err = journal.ValidateSnapshotSHA256(sha256Pack, "invalid-hash")
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for invalid hash, got %v", err)
	}

	// 4. Hash mismatch
	err = journal.ValidateSnapshotSHA256(sha256Pack, sha1Hash)
	if err == nil || !errors.Is(err, journal.ErrSnapshotHashMismatch) {
		t.Errorf("expected ErrSnapshotHashMismatch, got %v", err)
	}
}

func TestSnapshotMetadataAndContentType(t *testing.T) {
	stream := journal.StreamID("repo-delta")
	hash := "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db"

	meta := journal.SnapshotMetadata(stream, strings.ToUpper(hash))
	if meta[journal.MetaHeaderStream] != "repo-delta" {
		t.Errorf("MetaHeaderStream = %q, want %q", meta[journal.MetaHeaderStream], "repo-delta")
	}
	if meta[journal.MetaHeaderHash] != hash {
		t.Errorf("MetaHeaderHash = %q, want %q", meta[journal.MetaHeaderHash], hash)
	}

	if got := journal.SnapshotContentType(); got != "application/x-git-packed-objects" {
		t.Errorf("SnapshotContentType = %q, want %q", got, "application/x-git-packed-objects")
	}
}

func TestMarkerRefusalFormatting(t *testing.T) {
	stream := journal.StreamID("repo-alpha")
	hash := "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db"

	// 1. Missing snapshot refusal
	err := journal.RefuseMissingSnapshot(stream, hash)
	if err == nil {
		t.Fatalf("expected refusal error, got nil")
	}
	var ref *refusal.Refusal
	if !errors.As(err, &ref) {
		t.Fatalf("expected *refusal.Refusal type, got %T", err)
	}
	if !errors.Is(err, journal.ErrSnapshotNotFound) {
		t.Errorf("expected errors.Is(err, ErrSnapshotNotFound) to be true")
	}
	msg := err.Error()
	if strings.Contains(msg, "\n") {
		t.Errorf("refusal message contains newline: %q", msg)
	}
	expectedPrefix := "refusal: replay failed: missing snapshot pack 2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db on stream repo-alpha"
	if !strings.HasPrefix(msg, expectedPrefix) {
		t.Errorf("unexpected refusal message format: got %q, want prefix %q", msg, expectedPrefix)
	}

	// 2. Snapshot hash mismatch refusal
	computed := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	err = journal.RefuseSnapshotHashMismatch(stream, hash, computed)
	if !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected errors.Is(err, ErrSnapshotCorrupt) to be true")
	}
	if !errors.Is(err, journal.ErrSnapshotHashMismatch) {
		t.Errorf("expected errors.Is(err, ErrSnapshotHashMismatch) to be true")
	}
	msg = err.Error()
	if strings.Contains(msg, "\n") {
		t.Errorf("refusal message contains newline: %q", msg)
	}
	expectedMismatch := "refusal: replay failed: snapshot hash mismatch for 2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db on stream repo-alpha (computed e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)"
	if !strings.HasPrefix(msg, expectedMismatch) {
		t.Errorf("unexpected hash mismatch refusal format: got %q, want prefix %q", msg, expectedMismatch)
	}

	// 3. Corrupt snapshot refusal
	err = journal.RefuseCorruptSnapshot(stream, hash, journal.ErrInvalidPackfile)
	if !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected errors.Is(err, ErrSnapshotCorrupt) to be true")
	}
	if !errors.Is(err, journal.ErrInvalidPackfile) {
		t.Errorf("expected errors.Is(err, ErrInvalidPackfile) to be true")
	}
	msg = err.Error()
	if strings.Contains(msg, "\n") {
		t.Errorf("refusal message contains newline: %q", msg)
	}
	expectedCorrupt := "refusal: replay failed: corrupt snapshot pack 2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db on stream repo-alpha"
	if !strings.HasPrefix(msg, expectedCorrupt) {
		t.Errorf("unexpected corrupt snapshot refusal format: got %q, want prefix %q", msg, expectedCorrupt)
	}

	// 4. Corrupt marker refusal
	eofErr := errors.New("unexpected EOF")
	err = journal.RefuseCorruptMarker(stream, eofErr)
	if !errors.Is(err, journal.ErrCorruptMarker) {
		t.Errorf("expected errors.Is(err, ErrCorruptMarker) to be true")
	}
	if !errors.Is(err, eofErr) {
		t.Errorf("expected errors.Is(err, eofErr) to be true")
	}
	msg = err.Error()
	if strings.Contains(msg, "\n") {
		t.Errorf("refusal message contains newline: %q", msg)
	}
	expectedMarkerCorrupt := "refusal: replay failed: corrupt marker on stream repo-alpha (unexpected EOF) (marker.json in object storage is malformed)"
	if msg != expectedMarkerCorrupt {
		t.Errorf("unexpected corrupt marker refusal: got %q, want %q", msg, expectedMarkerCorrupt)
	}

	// 5. Invalid marker refusal
	err = journal.RefuseInvalidMarker(stream, journal.ErrInvalidMarker)
	if !errors.Is(err, journal.ErrInvalidMarker) {
		t.Errorf("expected errors.Is(err, ErrInvalidMarker) to be true")
	}
	msg = err.Error()
	if strings.Contains(msg, "\n") {
		t.Errorf("refusal message contains newline: %q", msg)
	}
	expectedMarkerInvalid := "refusal: replay failed: invalid marker on stream repo-alpha (invalid marker) (marker.json in object storage is invalid)"
	if msg != expectedMarkerInvalid {
		t.Errorf("unexpected invalid marker refusal: got %q, want %q", msg, expectedMarkerInvalid)
	}
}

func TestValidateSnapshotFromReader(t *testing.T) {
	pack := validEmptyPackfile()
	hash := journal.ComputeSegmentHash(pack)

	// 1. Valid streaming snapshot
	n, err := journal.ValidateSnapshotFromReader(bytes.NewReader(pack), hash)
	if err != nil {
		t.Fatalf("ValidateSnapshotFromReader failed: %v", err)
	}
	if n != int64(len(pack)) {
		t.Errorf("bytes read = %d, want %d", n, len(pack))
	}

	// 2. Case-insensitive hash match
	n, err = journal.ValidateSnapshotFromReader(bytes.NewReader(pack), strings.ToUpper(hash))
	if err != nil {
		t.Fatalf("ValidateSnapshotFromReader with uppercase hash failed: %v", err)
	}
	if n != int64(len(pack)) {
		t.Errorf("bytes read = %d, want %d", n, len(pack))
	}

	// 3. Nil reader
	_, err = journal.ValidateSnapshotFromReader(nil, hash)
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for nil reader, got %v", err)
	}

	// 4. Invalid expected hash
	_, err = journal.ValidateSnapshotFromReader(bytes.NewReader(pack), "not-a-hash")
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for invalid hash format, got %v", err)
	}

	// 5. Short stream (< 32 bytes)
	_, err = journal.ValidateSnapshotFromReader(bytes.NewReader([]byte("PACK short")), hash)
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for short stream, got %v", err)
	}

	// 6. Corrupt header magic
	corruptHdr := make([]byte, 32)
	copy(corruptHdr, pack)
	corruptHdr[0] = 'Z'
	_, err = journal.ValidateSnapshotFromReader(bytes.NewReader(corruptHdr), hash)
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for corrupt header, got %v", err)
	}

	// 7. Hash mismatch
	wrongHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	_, err = journal.ValidateSnapshotFromReader(bytes.NewReader(pack), wrongHash)
	if err == nil || !errors.Is(err, journal.ErrSnapshotHashMismatch) {
		t.Errorf("expected ErrSnapshotHashMismatch, got %v", err)
	}
}

func TestValidateSnapshotSHA256FromReader(t *testing.T) {
	pack := validEmptyPackfileSHA256()
	hash := journal.ComputeSegmentHash(pack)

	// 1. Valid streaming SHA-256 snapshot
	n, err := journal.ValidateSnapshotSHA256FromReader(bytes.NewReader(pack), hash)
	if err != nil {
		t.Fatalf("ValidateSnapshotSHA256FromReader failed: %v", err)
	}
	if n != int64(len(pack)) {
		t.Errorf("bytes read = %d, want %d", n, len(pack))
	}

	// 2. Too short for SHA-256 repo (< 44 bytes)
	sha1Pack := validEmptyPackfile()
	sha1Hash := journal.ComputeSegmentHash(sha1Pack)
	_, err = journal.ValidateSnapshotSHA256FromReader(bytes.NewReader(sha1Pack), sha1Hash)
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for 32-byte pack in SHA-256 validator, got %v", err)
	}

	// 3. Nil reader
	_, err = journal.ValidateSnapshotSHA256FromReader(nil, hash)
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for nil reader, got %v", err)
	}

	// 4. Invalid expected hash
	_, err = journal.ValidateSnapshotSHA256FromReader(bytes.NewReader(pack), "not-a-hash")
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for invalid hash format, got %v", err)
	}

	// 5. Hash mismatch
	_, err = journal.ValidateSnapshotSHA256FromReader(bytes.NewReader(pack), sha1Hash)
	if err == nil || !errors.Is(err, journal.ErrSnapshotHashMismatch) {
		t.Errorf("expected ErrSnapshotHashMismatch, got %v", err)
	}
}
