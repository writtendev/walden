package journal_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
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
		seq journal.Seq
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

// TestSeqJSONRoundTrip covers spec section 1.1: a sequence number is written as a JSON
// string holding its exact decimal form, and reads back as the same number — including at
// the top of the range, where a JSON number would come back rounded to something that is
// not the sequence its object key names.
func TestSeqJSONRoundTrip(t *testing.T) {
	sequences := []journal.Seq{0, 1, 42, 1 << 53, 1<<53 + 1, journal.Seq(^uint64(0))}

	for _, seq := range sequences {
		data, err := json.Marshal(seq)
		if err != nil {
			t.Fatalf("json.Marshal(%d) unexpected error: %v", uint64(seq), err)
		}
		want := `"` + strconv.FormatUint(uint64(seq), 10) + `"`
		if string(data) != want {
			t.Errorf("json.Marshal(%d) = %s, expected %s", uint64(seq), data, want)
		}
		var parsed journal.Seq
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("json.Unmarshal(%s) unexpected error: %v", data, err)
		}
		if parsed != seq {
			t.Errorf("json.Unmarshal(%s) = %d, expected %d", data, uint64(parsed), uint64(seq))
		}
	}
}

// TestSeqJSONRefusesInexactForms covers the other half of section 1.1: a sequence that is
// not the exact decimal form in a JSON string is refused rather than coerced, because a
// rounded or reformatted sequence derives the wrong object key.
func TestSeqJSONRefusesInexactForms(t *testing.T) {
	invalid := []string{
		`3`,                      // a JSON number, which is the encoding this format does not use
		`18446744073709551615`,   // the same, at the top of the range
		`18446744073709552000`,   // what a reader with double-precision numbers makes of it
		`"007"`,                  // leading zeros
		`"+7"`,                   // a sign
		`"-7"`,                   // a negative sequence is not a sequence
		`" 7"`,                   // leading whitespace
		`"7 "`,                   // trailing whitespace
		`"7e0"`,                  // an exponent
		`"0x7"`,                  // another base
		`"18446744073709551616"`, // one past the top of the range
		`""`,
		`null`,
		`true`,
		`[]`,
		`{}`,
	}

	for _, s := range invalid {
		var seq journal.Seq
		err := json.Unmarshal([]byte(s), &seq)
		if err == nil {
			t.Errorf("expected json.Unmarshal(%s) to fail, got %d", s, uint64(seq))
			continue
		}
		if !errors.Is(err, journal.ErrInvalidSeq) {
			t.Errorf("expected ErrInvalidSeq for %s, got %v", s, err)
		}
	}
}

func TestLexicographicalOrdering(t *testing.T) {
	sequences := []journal.Seq{
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
	if want, got := "v1/streams/repo-test/segments/", journal.SegmentPrefix(stream); want != got {
		t.Errorf("SegmentPrefix = %q, want %q", got, want)
	}
	if want, got := fmt.Sprintf("v1/streams/repo-test/segments/%s.pack", hash), journal.SegmentKey(stream, hash); want != got {
		t.Errorf("SegmentKey = %q, want %q", got, want)
	}
	if want, got := "v1/streams/repo-test/snapshots/", journal.SnapshotPrefix(stream); want != got {
		t.Errorf("SnapshotPrefix = %q, want %q", got, want)
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
