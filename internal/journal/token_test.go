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

// TestTokenHashRefusalWithholdsTheValue holds the refusals of ValidateTokenHash to the
// reason the check exists. The check is what keeps a raw bearer token out of the journal
// (spec section 8.1, rule 13): a writer that puts one where the hash belongs is refused
// rather than publishing the secret. A refusal that quoted the offending value would
// publish it anyway — to the operator's terminal, the server log, and whatever aggregates
// that log — on a code path whose whole premise is that the value may be a live credential.
// So the message reports the length and the failing rule, and never the bytes.
func TestTokenHashRefusalWithholdsTheValue(t *testing.T) {
	// Shaped like the mistake this guards against: a raw bearer token, and a raw token
	// pasted after the prefix. Both are the published fixture tokens, so nothing secret is
	// in this file either.
	rawToken := "walden_sec_writer_0123456789abcdef"

	tests := []struct {
		name    string
		hash    string
		secrets []string
	}{
		{"raw token where the hash belongs", rawToken, []string{rawToken}},
		{"raw token after the prefix", journal.TokenHashPrefix + rawToken, []string{rawToken}},
		{"uppercase hex", journal.TokenHashPrefix + strings.ToUpper("b807af8cbdd0849e534474c93408ecdc1593e7e3de172261bd717e6484425ceb"), []string{strings.ToUpper("b807af8cbdd0849e534474c93408ecdc1593e7e3de172261bd717e6484425ceb")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := journal.ValidateTokenHash(tt.hash)
			if err == nil {
				t.Fatalf("ValidateTokenHash(%d-byte value) accepted it, want a refusal", len(tt.hash))
			}
			if !errors.Is(err, journal.ErrInvalidTokenHash) {
				t.Errorf("error is not ErrInvalidTokenHash: %v", err)
			}
			msg := err.Error()
			for _, secret := range tt.secrets {
				if strings.Contains(msg, secret) {
					t.Errorf("the refusal echoes the value it refused, which may be a live credential; message = %q", msg)
				}
			}
			if strings.Contains(msg, "\n") {
				t.Errorf("the refusal is not one line: %q", msg)
			}
		})
	}

	// The same must hold through a whole record: Validate wraps ValidateTokenHash, and a
	// wrapper that re-quoted the field would undo this.
	create := validTokenCreate()
	create.TokenHash = rawToken
	revoke := validTokenRevoke()
	revoke.TokenHash = rawToken
	for name, err := range map[string]error{
		"TokenCreateRecord.Validate": create.Validate(),
		"TokenRevokeRecord.Validate": revoke.Validate(),
	} {
		if err == nil {
			t.Fatalf("%s accepted a raw token where the hash belongs", name)
		}
		if strings.Contains(err.Error(), rawToken) {
			t.Errorf("%s echoes the raw token in its refusal: %q", name, err.Error())
		}
	}

	// The identifier is a different case and stays quoted: spec section 4.3 makes a token id
	// a name, not a secret, and an operator needs to see which one failed.
	idErr := journal.ValidateTokenID("tok admin 01")
	if idErr == nil || !strings.Contains(idErr.Error(), "tok admin 01") {
		t.Errorf("ValidateTokenID should name the identifier it refused, got %v", idErr)
	}
}
