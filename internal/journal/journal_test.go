package journal_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/journal"
)

func TestMetaStreamID(t *testing.T) {
	if journal.MetaStreamID != "_meta" {
		t.Errorf("expected MetaStreamID to be '_meta', got %q", journal.MetaStreamID)
	}
}

func TestValidateStreamID(t *testing.T) {
	valid := []journal.StreamID{
		"_meta",
		"repo-1",
		"my.repo_name-123",
		"r_8f3a2b1c",
		"a",
		journal.StreamID(strings.Repeat("a", 255)),
	}

	for _, s := range valid {
		if err := journal.ValidateStreamID(s); err != nil {
			t.Errorf("expected valid stream ID %q, got error: %v", s, err)
		}
	}

	invalid := []struct {
		id  journal.StreamID
		err string
	}{
		{"", "cannot be empty"},
		{journal.StreamID(strings.Repeat("a", 256)), "exceeds maximum of 255 bytes"},
		{"repo/sub", "must contain only"},
		{"/leading", "leading or trailing slashes"},
		{"trailing/", "leading or trailing slashes"},
		{"path/../traversal", "path traversal sequences"},
		{"repo..name", "path traversal sequences"},
		{"repo name", "must contain only"},
		{"repo@name", "must contain only"},
		{"repo:name", "must contain only"},
	}

	for _, tc := range invalid {
		err := journal.ValidateStreamID(tc.id)
		if err == nil {
			t.Errorf("expected error for stream ID %q, got nil", tc.id)
			continue
		}
		if !errors.Is(err, journal.ErrInvalidStream) {
			t.Errorf("expected ErrInvalidStream for %q, got %v", tc.id, err)
		}
		if !strings.Contains(err.Error(), tc.err) {
			t.Errorf("expected error to contain %q, got %q", tc.err, err.Error())
		}
	}
}

func TestFormatAndParseSeq(t *testing.T) {
	tests := []struct {
		seq uint64
		str string
	}{
		{0, "00000000000000000000"},
		{1, "00000000000000000001"},
		{42, "00000000000000000042"},
		{1000, "00000000000000001000"},
		{18446744073709551615, "18446744073709551615"},
	}

	for _, tc := range tests {
		formatted := journal.FormatSeq(tc.seq)
		if formatted != tc.str {
			t.Errorf("FormatSeq(%d) = %q, expected %q", tc.seq, formatted, tc.str)
		}
		parsed, err := journal.ParseSeq(formatted)
		if err != nil {
			t.Fatalf("ParseSeq(%q) unexpected error: %v", formatted, err)
		}
		if parsed != tc.seq {
			t.Errorf("ParseSeq(%q) = %d, expected %d", formatted, parsed, tc.seq)
		}
	}
}

func TestParseSeqErrors(t *testing.T) {
	invalid := []string{
		"",
		"1",
		"0000000000000000001",   // 19 digits
		"000000000000000000001", // 21 digits
		"0000000000000000000a",  // non-digit
		"000000000000000000-1",  // negative sign
		"                    ",  // spaces
	}

	for _, s := range invalid {
		_, err := journal.ParseSeq(s)
		if err == nil {
			t.Errorf("expected ParseSeq(%q) to fail, got nil", s)
			continue
		}
		if !errors.Is(err, journal.ErrInvalidSeq) {
			t.Errorf("expected ErrInvalidSeq for %q, got %v", s, err)
		}
	}
}

func TestLexicographicalOrdering(t *testing.T) {
	sequences := []uint64{
		0, 1, 2, 9, 10, 11, 99, 100, 101, 999, 1000,
		999999, 1000000, 18446744073709551614, 18446744073709551615,
	}

	formatted := make([]string, len(sequences))
	for i, seq := range sequences {
		formatted[i] = journal.FormatSeq(seq)
	}

	if !sort.StringsAreSorted(formatted) {
		t.Errorf("formatted sequence strings are not lexicographically sorted: %v", formatted)
	}

	txKeys := make([]string, len(sequences))
	for i, seq := range sequences {
		txKeys[i] = journal.TxKey("my-stream", seq)
	}

	if !sort.StringsAreSorted(txKeys) {
		t.Errorf("transaction keys are not lexicographically sorted: %v", txKeys)
	}
}

func TestKeyConstructors(t *testing.T) {
	stream := journal.StreamID("repo-test")
	hash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	if want, got := "v1/streams/repo-test/", journal.StreamPrefix(stream); want != got {
		t.Errorf("StreamPrefix = %q, want %q", got, want)
	}
	if want, got := "v1/streams/repo-test/tx/", journal.TxPrefix(stream); want != got {
		t.Errorf("TxPrefix = %q, want %q", got, want)
	}
	if want, got := "v1/streams/repo-test/tx/00000000000000000005.json", journal.TxKey(stream, 5); want != got {
		t.Errorf("TxKey = %q, want %q", got, want)
	}
	if want, got := fmt.Sprintf("v1/streams/repo-test/segments/%s.pack", hash), journal.SegmentKey(stream, hash); want != got {
		t.Errorf("SegmentKey = %q, want %q", got, want)
	}
	if want, got := fmt.Sprintf("v1/streams/repo-test/snapshots/%s.pack", hash), journal.SnapshotKey(stream, hash); want != got {
		t.Errorf("SnapshotKey = %q, want %q", got, want)
	}
	if want, got := "v1/streams/repo-test/marker.json", journal.MarkerKey(stream); want != got {
		t.Errorf("MarkerKey = %q, want %q", got, want)
	}

	// Meta stream keys
	if want, got := "v1/streams/_meta/tx/00000000000000000000.json", journal.TxKey(journal.MetaStreamID, 0); want != got {
		t.Errorf("Meta TxKey(0) = %q, want %q", got, want)
	}
}

func TestValidateHash(t *testing.T) {
	valid := []string{
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
		"0000000000000000000000000000000000000000000000000000000000000000",
	}
	for _, h := range valid {
		if err := journal.ValidateHash(h); err != nil {
			t.Errorf("expected hash %q to be valid, got: %v", h, err)
		}
	}

	invalid := []string{
		"",
		"e3b0c4", // too short
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550", // 65 chars
		"g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  // non-hex 'g'
	}
	for _, h := range invalid {
		err := journal.ValidateHash(h)
		if err == nil {
			t.Errorf("expected hash %q to fail validation, got nil", h)
			continue
		}
		if !errors.Is(err, journal.ErrInvalidHash) {
			t.Errorf("expected ErrInvalidHash for %q, got %v", h, err)
		}
	}
}

func TestSpecFixturesLayout(t *testing.T) {
	fixturesDir := filepath.Join("..", "..", "spec", "journal", "v1", "fixtures")
	if _, err := os.Stat(fixturesDir); os.IsNotExist(err) {
		t.Skipf("fixtures directory %s does not exist", fixturesDir)
	}

	// Verify _meta stream fixtures exist
	metaGenesis := filepath.Join(fixturesDir, "streams", "_meta", "tx", "00000000000000000000.json")
	if _, err := os.Stat(metaGenesis); err != nil {
		t.Errorf("missing fixture: %s", metaGenesis)
	}

	metaToken := filepath.Join(fixturesDir, "streams", "_meta", "tx", "00000000000000000001.json")
	if _, err := os.Stat(metaToken); err != nil {
		t.Errorf("missing fixture: %s", metaToken)
	}

	metaRotation := filepath.Join(fixturesDir, "streams", "_meta", "tx", "00000000000000000002.json")
	if _, err := os.Stat(metaRotation); err != nil {
		t.Errorf("missing fixture: %s", metaRotation)
	}

	// Verify repo stream fixtures exist
	for _, seq := range []string{"00000000000000000000", "00000000000000000001", "00000000000000000002"} {
		repoTx := filepath.Join(fixturesDir, "streams", "repo-alpha", "tx", seq+".json")
		if _, err := os.Stat(repoTx); err != nil {
			t.Errorf("missing fixture: %s", repoTx)
		}
	}

	repoMarker := filepath.Join(fixturesDir, "streams", "repo-alpha", "marker.json")
	if _, err := os.Stat(repoMarker); err != nil {
		t.Errorf("missing fixture: %s", repoMarker)
	}

	// Check segment and snapshot filenames are valid 64-hex hashes + .pack
	entries, err := os.ReadDir(filepath.Join(fixturesDir, "streams", "repo-alpha", "segments"))
	if err != nil {
		t.Fatalf("failed to read segments dir: %v", err)
	}
	if len(entries) == 0 {
		t.Errorf("expected at least one segment fixture")
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".pack") {
			t.Errorf("segment fixture %q missing .pack suffix", name)
		}
		hash := strings.TrimSuffix(name, ".pack")
		if err := journal.ValidateHash(hash); err != nil {
			t.Errorf("segment fixture hash %q invalid: %v", hash, err)
		}
	}
}
