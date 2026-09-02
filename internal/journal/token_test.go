package journal_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/journal"
)

// validTokenCreate returns a well-formed token_create record the tests then break in one
// place each.
func validTokenCreate() *journal.TokenCreateRecord {
	return &journal.TokenCreateRecord{
		Version:   journal.VersionPrefix,
		Stream:    journal.MetaStreamID,
		Seq:       1,
		Type:      journal.RecordTypeTokenCreate,
		TokenID:   "tok_admin_01",
		TokenHash: "sha256:b807af8cbdd0849e534474c93408ecdc1593e7e3de172261bd717e6484425ceb",
		Scopes:    []string{"rwc:*"},
		Timestamp: "2026-08-31T00:01:00Z",
	}
}

// validTokenRevoke returns a well-formed token_revoke record.
func validTokenRevoke() *journal.TokenRevokeRecord {
	return &journal.TokenRevokeRecord{
		Version:   journal.VersionPrefix,
		Stream:    journal.MetaStreamID,
		Seq:       3,
		Type:      journal.RecordTypeTokenRevoke,
		TokenID:   "tok_admin_01",
		TokenHash: "sha256:b807af8cbdd0849e534474c93408ecdc1593e7e3de172261bd717e6484425ceb",
		Timestamp: "2026-08-31T00:08:00Z",
	}
}

func TestTokenCreateValidate(t *testing.T) {
	if err := validTokenCreate().Validate(); err != nil {
		t.Fatalf("Validate failed on a well-formed record: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*journal.TokenCreateRecord)
	}{
		{"wrong version", func(r *journal.TokenCreateRecord) { r.Version = "v2" }},
		{"repository stream", func(r *journal.TokenCreateRecord) { r.Stream = "repo-alpha" }},
		{"genesis sequence", func(r *journal.TokenCreateRecord) { r.Seq = 0 }},
		{"wrong type", func(r *journal.TokenCreateRecord) { r.Type = journal.RecordTypeTokenRevoke }},
		{"empty token id", func(r *journal.TokenCreateRecord) { r.TokenID = "" }},
		{"token id with a slash", func(r *journal.TokenCreateRecord) { r.TokenID = "tok/admin" }},
		{"unprefixed hash", func(r *journal.TokenCreateRecord) { r.TokenHash = strings.TrimPrefix(r.TokenHash, "sha256:") }},
		{"uppercase hash", func(r *journal.TokenCreateRecord) { r.TokenHash = strings.ToUpper(r.TokenHash) }},
		{"short hash", func(r *journal.TokenCreateRecord) { r.TokenHash = "sha256:b807af8c" }},
		{"no scopes", func(r *journal.TokenCreateRecord) { r.Scopes = nil }},
		{"empty scopes", func(r *journal.TokenCreateRecord) { r.Scopes = []string{} }},
		{"empty scope string", func(r *journal.TokenCreateRecord) { r.Scopes = []string{"rwc:*", ""} }},
		{"duplicate scope", func(r *journal.TokenCreateRecord) { r.Scopes = []string{"r:docs", "r:docs"} }},
		{"empty timestamp", func(r *journal.TokenCreateRecord) { r.Timestamp = "" }},
		{"unparseable timestamp", func(r *journal.TokenCreateRecord) { r.Timestamp = "31 August 2026" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := validTokenCreate()
			tc.mutate(rec)
			if err := rec.Validate(); err == nil {
				t.Error("Validate accepted the record")
			}
		})
	}

	// A raw token in the token_hash field is the mistake that would put the secret in the
	// journal, and the format check is what stands between the two.
	rec := validTokenCreate()
	rec.TokenHash = "walden_sec_admin_0123456789abcdef"
	if err := rec.Validate(); !errors.Is(err, journal.ErrInvalidTokenHash) {
		t.Errorf("Validate on a raw token in token_hash returned %v, want ErrInvalidTokenHash", err)
	}

	// More than one scope is the case a single scope field cannot hold, and it is the whole
	// reason this field is an array.
	rec = validTokenCreate()
	rec.Scopes = []string{"rw:blog-*", "r:docs"}
	if err := rec.Validate(); err != nil {
		t.Errorf("Validate rejected a two-scope token: %v", err)
	}
}

func TestTokenRevokeValidate(t *testing.T) {
	if err := validTokenRevoke().Validate(); err != nil {
		t.Fatalf("Validate failed on a well-formed record: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*journal.TokenRevokeRecord)
	}{
		{"wrong version", func(r *journal.TokenRevokeRecord) { r.Version = "v2" }},
		{"repository stream", func(r *journal.TokenRevokeRecord) { r.Stream = "repo-alpha" }},
		{"genesis sequence", func(r *journal.TokenRevokeRecord) { r.Seq = 0 }},
		{"wrong type", func(r *journal.TokenRevokeRecord) { r.Type = journal.RecordTypeTokenCreate }},
		{"empty token id", func(r *journal.TokenRevokeRecord) { r.TokenID = "" }},
		{"missing hash", func(r *journal.TokenRevokeRecord) { r.TokenHash = "" }},
		{"empty timestamp", func(r *journal.TokenRevokeRecord) { r.Timestamp = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := validTokenRevoke()
			tc.mutate(rec)
			if err := rec.Validate(); err == nil {
				t.Error("Validate accepted the record")
			}
		})
	}
}

// TestTokenRecordSeqEncoding covers spec section 1.1 at the token records: `seq` is written
// as a JSON string holding its exact decimal form, like every other sequence in the format,
// and a record encoding it any other way is refused on parse rather than coerced.
func TestTokenRecordSeqEncoding(t *testing.T) {
	rec := validTokenCreate()
	rec.Seq = journal.Seq(^uint64(0))
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if !strings.Contains(string(data), `"seq":"18446744073709551615"`) {
		t.Errorf("record does not carry seq as a decimal string: %s", data)
	}

	var parsed journal.TokenCreateRecord
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if parsed.Seq != rec.Seq {
		t.Errorf("seq round-tripped to %d, want %d", uint64(parsed.Seq), uint64(rec.Seq))
	}

	var numeric journal.TokenRevokeRecord
	if err := json.Unmarshal([]byte(`{"version":"v1","stream":"_meta","seq":3,"type":"token_revoke"}`), &numeric); !errors.Is(err, journal.ErrInvalidSeq) {
		t.Errorf("a JSON number sequence parsed with %v, want ErrInvalidSeq", err)
	}
}

// TestTokenRecordRoundTrip checks that a token record survives the encoding it is published
// in: scopes keep their order and their count, and nothing is dropped on the way back.
func TestTokenRecordRoundTrip(t *testing.T) {
	rec := validTokenCreate()
	rec.TokenID = "tok_writer_02"
	rec.TokenHash = "sha256:5453e0186b8b6f1d4852424e8ae33ecf685ce338a44862fc8db2acddc7b40d2a"
	rec.Scopes = []string{"rw:blog-*", "r:docs"}

	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	var parsed journal.TokenCreateRecord
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if err := parsed.Validate(); err != nil {
		t.Fatalf("Validate failed after a round trip: %v", err)
	}
	if parsed.TokenHash != rec.TokenHash {
		t.Errorf("token_hash round-tripped to %q, want %q", parsed.TokenHash, rec.TokenHash)
	}
	if got, want := strings.Join(parsed.Scopes, ","), strings.Join(rec.Scopes, ","); got != want {
		t.Errorf("scopes round-tripped to %q, want %q", got, want)
	}

	// Forward compatibility, as section 5.4 has it for ref transactions: an unknown key is
	// ignored rather than refused.
	var extended journal.TokenCreateRecord
	augmented := strings.Replace(string(data), `{"version"`, `{"future_field":"ignored","version"`, 1)
	if err := json.Unmarshal([]byte(augmented), &extended); err != nil {
		t.Fatalf("json.Unmarshal failed on a record carrying an unknown field: %v", err)
	}
	if err := extended.Validate(); err != nil {
		t.Errorf("Validate rejected a record carrying an unknown field: %v", err)
	}
}
