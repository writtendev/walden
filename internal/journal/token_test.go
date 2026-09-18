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
		{"scope containing a newline", func(r *journal.TokenCreateRecord) { r.Scopes = []string{"r:docs\nscope:rwc:*"} }},
		{"scope containing a control character", func(r *journal.TokenCreateRecord) { r.Scopes = []string{"r:docs\x00"} }},
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

// TestTokenScopeDelimiterAmbiguityRefused is the round-1 review's own attack: the Canonical
// Token Creation Signing Payload frames one scope per line as `scope:<scope>\n`, so a scope
// string that itself contains "\nscope:" makes a one-scope record's payload byte-for-byte
// identical to a two-scope record's — a signature over `scopes: ["r:docs\nscope:rwc:*"]`
// verifies unchanged for `scopes: ["r:docs", "rwc:*"]`, silently escalating a minted token to
// rwc:*. CanonicalTokenCreatePayload itself does no validation, so it still folds the two
// scope sets to the same bytes below; what closes the hole is that ValidateTokenScope (via
// TokenCreateRecord.Validate) refuses the poisoned scope before either SignTokenCreate or
// VerifyTokenCreate ever computes a payload from it, so no compliant implementation ever
// produces or accepts a signature over it.
func TestTokenScopeDelimiterAmbiguityRefused(t *testing.T) {
	poisoned := validTokenCreate()
	poisoned.Scopes = []string{"r:docs\nscope:rwc:*"}
	split := validTokenCreate()
	split.Scopes = []string{"r:docs", "rwc:*"}

	// The two records payloads collide at the raw formatting layer — this is the defect,
	// demonstrated directly against the function the signature is computed over.
	poisonedPayload := journal.CanonicalTokenCreatePayload(poisoned.Stream, poisoned.Seq, poisoned.TokenID, poisoned.TokenHash, poisoned.Scopes, poisoned.Timestamp)
	splitPayload := journal.CanonicalTokenCreatePayload(split.Stream, split.Seq, split.TokenID, split.TokenHash, split.Scopes, split.Timestamp)
	if string(poisonedPayload) != string(splitPayload) {
		t.Fatalf("test no longer demonstrates the delimiter collision CanonicalTokenCreatePayload alone permits; got %q vs %q", poisonedPayload, splitPayload)
	}

	// Validate refuses the poisoned record by name, before a signature is ever computed.
	if err := poisoned.Validate(); err == nil {
		t.Fatal("Validate accepted a scope containing the payload's own line delimiter")
	} else if !errors.Is(err, journal.ErrInvalidTokenScope) {
		t.Errorf("error = %v, want ErrInvalidTokenScope", err)
	}

	// SignTokenCreate and VerifyTokenCreate both call Validate first, so neither ever
	// produces or accepts a signature over the colliding payload above. The split (honest
	// two-scope) record signs and verifies normally.
	priv, pub := deterministicKeypair(0x02)
	formattedPub := journal.FormatPublicKey(pub)

	if err := journal.SignTokenCreate(priv, poisoned); err == nil {
		t.Error("SignTokenCreate signed a record with a scope containing the payload delimiter")
	}
	if err := journal.SignTokenCreate(priv, split); err != nil {
		t.Fatalf("SignTokenCreate failed on the honest two-scope record: %v", err)
	}
	if err := journal.VerifyTokenCreate(split, formattedPub); err != nil {
		t.Errorf("VerifyTokenCreate rejected the honest two-scope record's own signature: %v", err)
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

// TestCanonicalTokenCreatePayload pins the exact byte layout of the canonical token_create
// signing payload, the same shape as TestCanonicalMarkerPayload and
// TestCanonicalRefUpdatePayload — a golden fixture regenerated by this same function is not
// an independent check against a payload edit, so this test is.
func TestCanonicalTokenCreatePayload(t *testing.T) {
	payload := journal.CanonicalTokenCreatePayload(
		journal.MetaStreamID, 1, "tok_admin_01",
		"sha256:b807af8cbdd0849e534474c93408ecdc1593e7e3de172261bd717e6484425ceb",
		[]string{"rwc:*"},
		"2026-08-31T00:01:00Z",
	)
	expected := "walden-token-create:v1\n" +
		"stream:_meta\n" +
		"seq:1\n" +
		"token_id:tok_admin_01\n" +
		"token_hash:sha256:b807af8cbdd0849e534474c93408ecdc1593e7e3de172261bd717e6484425ceb\n" +
		"scope:rwc:*\n" +
		"timestamp:2026-08-31T00:01:00Z\n"
	if string(payload) != expected {
		t.Errorf("payload mismatch:\ngot:\n%s\nwant:\n%s", string(payload), expected)
	}

	// A second scope is a second scope: line, in array order — not folded into the first.
	multi := journal.CanonicalTokenCreatePayload(
		journal.MetaStreamID, 4, "tok_writer_02",
		"sha256:5453e0186b8b6f1d4852424e8ae33ecf685ce338a44862fc8db2acddc7b40d2a",
		[]string{"rw:blog-*", "r:docs"},
		"2026-08-31T00:09:00Z",
	)
	expectedMulti := "walden-token-create:v1\n" +
		"stream:_meta\n" +
		"seq:4\n" +
		"token_id:tok_writer_02\n" +
		"token_hash:sha256:5453e0186b8b6f1d4852424e8ae33ecf685ce338a44862fc8db2acddc7b40d2a\n" +
		"scope:rw:blog-*\n" +
		"scope:r:docs\n" +
		"timestamp:2026-08-31T00:09:00Z\n"
	if string(multi) != expectedMulti {
		t.Errorf("payload mismatch on two scopes:\ngot:\n%s\nwant:\n%s", string(multi), expectedMulti)
	}
}

// TestCanonicalTokenRevokePayload is TestCanonicalTokenCreatePayload's counterpart for
// token_revoke: no scopes field, so no scope: lines at all.
func TestCanonicalTokenRevokePayload(t *testing.T) {
	payload := journal.CanonicalTokenRevokePayload(
		journal.MetaStreamID, 3, "tok_admin_01",
		"sha256:b807af8cbdd0849e534474c93408ecdc1593e7e3de172261bd717e6484425ceb",
		"2026-08-31T00:08:00Z",
	)
	expected := "walden-token-revoke:v1\n" +
		"stream:_meta\n" +
		"seq:3\n" +
		"token_id:tok_admin_01\n" +
		"token_hash:sha256:b807af8cbdd0849e534474c93408ecdc1593e7e3de172261bd717e6484425ceb\n" +
		"timestamp:2026-08-31T00:08:00Z\n"
	if string(payload) != expected {
		t.Errorf("payload mismatch:\ngot:\n%s\nwant:\n%s", string(payload), expected)
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

// TestNewTokenCreateRecord covers NewTokenCreateRecord's fixed fields and its scopes clone
// (WALD-33): the record is built with version/stream/type fixed, seq and timestamp from the
// caller, unsigned, and scopes independent of the slice the caller passed in.
func TestNewTokenCreateRecord(t *testing.T) {
	scopes := []string{"rw:blog-*", "r:docs"}
	rec := journal.NewTokenCreateRecord(4, "tok_writer_02", "sha256:5453e0186b8b6f1d4852424e8ae33ecf685ce338a44862fc8db2acddc7b40d2a", scopes, "2026-08-31T00:09:00Z")

	if rec.Version != journal.VersionPrefix {
		t.Errorf("Version = %q, want %q", rec.Version, journal.VersionPrefix)
	}
	if rec.Stream != journal.MetaStreamID {
		t.Errorf("Stream = %q, want %q", rec.Stream, journal.MetaStreamID)
	}
	if rec.Type != journal.RecordTypeTokenCreate {
		t.Errorf("Type = %q, want %q", rec.Type, journal.RecordTypeTokenCreate)
	}
	if rec.Seq != 4 {
		t.Errorf("Seq = %d, want 4", rec.Seq)
	}
	if rec.Signature != "" {
		t.Errorf("Signature = %q, want unsigned", rec.Signature)
	}
	if got, want := strings.Join(rec.Scopes, ","), strings.Join(scopes, ","); got != want {
		t.Errorf("Scopes = %q, want %q", got, want)
	}

	// The clone is real: mutating the caller's slice after the call must not reach the
	// record.
	scopes[0] = "rwc:*"
	if rec.Scopes[0] == "rwc:*" {
		t.Error("NewTokenCreateRecord aliased the caller's scopes slice instead of cloning it")
	}

	if err := journal.SignTokenCreate(fixtureKey(0x01), rec); err != nil {
		t.Fatalf("SignTokenCreate on a freshly constructed record failed: %v", err)
	}
}

// TestNewTokenRevokeRecord is TestNewTokenCreateRecord's counterpart for token_revoke.
func TestNewTokenRevokeRecord(t *testing.T) {
	rec := journal.NewTokenRevokeRecord(3, "tok_admin_01", "sha256:b807af8cbdd0849e534474c93408ecdc1593e7e3de172261bd717e6484425ceb", "2026-08-31T00:08:00Z")

	if rec.Version != journal.VersionPrefix {
		t.Errorf("Version = %q, want %q", rec.Version, journal.VersionPrefix)
	}
	if rec.Stream != journal.MetaStreamID {
		t.Errorf("Stream = %q, want %q", rec.Stream, journal.MetaStreamID)
	}
	if rec.Type != journal.RecordTypeTokenRevoke {
		t.Errorf("Type = %q, want %q", rec.Type, journal.RecordTypeTokenRevoke)
	}
	if rec.Seq != 3 {
		t.Errorf("Seq = %d, want 3", rec.Seq)
	}
	if rec.Signature != "" {
		t.Errorf("Signature = %q, want unsigned", rec.Signature)
	}

	if err := journal.SignTokenRevoke(fixtureKey(0x01), rec); err != nil {
		t.Fatalf("SignTokenRevoke on a freshly constructed record failed: %v", err)
	}
}

// TestMarshalTokenCreateRoundTrip covers MarshalTokenCreate's happy path: a signed,
// two-scope record marshals to indented JSON with a trailing newline and parses/verifies
// back to the same record (WALD-33).
func TestMarshalTokenCreateRoundTrip(t *testing.T) {
	priv, pub := deterministicKeypair(0x03)
	rec := journal.NewTokenCreateRecord(4, "tok_writer_02", "sha256:5453e0186b8b6f1d4852424e8ae33ecf685ce338a44862fc8db2acddc7b40d2a", []string{"rw:blog-*", "r:docs"}, "2026-08-31T00:09:00Z")
	if err := journal.SignTokenCreate(priv, rec); err != nil {
		t.Fatalf("SignTokenCreate failed: %v", err)
	}

	data, err := journal.MarshalTokenCreate(rec)
	if err != nil {
		t.Fatalf("MarshalTokenCreate failed: %v", err)
	}
	if data[len(data)-1] != '\n' {
		t.Error("MarshalTokenCreate did not append a trailing newline")
	}

	parsed, err := journal.ParseTokenCreate(data)
	if err != nil {
		t.Fatalf("ParseTokenCreate on the marshaled record failed: %v", err)
	}
	if err := journal.VerifyTokenCreate(parsed, journal.FormatPublicKey(pub)); err != nil {
		t.Errorf("VerifyTokenCreate on the round-tripped record failed: %v", err)
	}
	if got, want := strings.Join(parsed.Scopes, ","), "rw:blog-*,r:docs"; got != want {
		t.Errorf("scopes round-tripped to %q, want %q", got, want)
	}

	if _, err := journal.MarshalTokenCreate(nil); err == nil {
		t.Error("MarshalTokenCreate accepted a nil record")
	}
}

// TestMarshalTokenCreateRefusesInvalidUTF8Scope covers WALD-33's UTF-8 guard: a scope
// carrying invalid UTF-8 would otherwise be silently replaced with U+FFFD by
// json.MarshalIndent, producing a record whose bytes no longer match the ones its
// signature was computed over. MarshalTokenCreate refuses it by index instead of writing
// it, the same treatment MarshalRefTx gives a non-UTF-8 ref name.
func TestMarshalTokenCreateRefusesInvalidUTF8Scope(t *testing.T) {
	priv, _ := deterministicKeypair(0x03)
	rec := journal.NewTokenCreateRecord(1, "tok_admin_01", "sha256:b807af8cbdd0849e534474c93408ecdc1593e7e3de172261bd717e6484425ceb", []string{"rwc:*"}, "2026-08-31T00:01:00Z")
	// Slip the invalid byte in after signing (a signature computed over the honest scope
	// still lets Validate pass, which is exactly the case MarshalTokenCreate's own doc
	// comment says ValidateTokenScope does not catch): ValidateTokenScope bans only
	// 0x00-0x1F and 0x7F, and 0xFF alone is not.
	if err := journal.SignTokenCreate(priv, rec); err != nil {
		t.Fatalf("SignTokenCreate failed: %v", err)
	}
	rec.Scopes = []string{"rwc:*", "r:doc\xffs"}
	if err := rec.Validate(); err != nil {
		t.Fatalf("test no longer demonstrates the gap ValidateTokenScope leaves open: Validate itself now refuses this scope: %v", err)
	}

	_, err := journal.MarshalTokenCreate(rec)
	if err == nil {
		t.Fatal("MarshalTokenCreate accepted a scope that is not valid UTF-8")
	}
	if !errors.Is(err, journal.ErrInvalidTokenScope) {
		t.Errorf("error = %v, want ErrInvalidTokenScope", err)
	}
	if !strings.Contains(err.Error(), "scopes[1]") {
		t.Errorf("error does not name the offending index: %v", err)
	}
}

// TestMarshalTokenRevokeRoundTrip is TestMarshalTokenCreateRoundTrip's counterpart for
// token_revoke: no scopes, so nothing for the UTF-8 guard to check, but nil is still
// refused.
func TestMarshalTokenRevokeRoundTrip(t *testing.T) {
	priv, pub := deterministicKeypair(0x03)
	rec := journal.NewTokenRevokeRecord(3, "tok_admin_01", "sha256:b807af8cbdd0849e534474c93408ecdc1593e7e3de172261bd717e6484425ceb", "2026-08-31T00:08:00Z")
	if err := journal.SignTokenRevoke(priv, rec); err != nil {
		t.Fatalf("SignTokenRevoke failed: %v", err)
	}

	data, err := journal.MarshalTokenRevoke(rec)
	if err != nil {
		t.Fatalf("MarshalTokenRevoke failed: %v", err)
	}
	if data[len(data)-1] != '\n' {
		t.Error("MarshalTokenRevoke did not append a trailing newline")
	}

	parsed, err := journal.ParseTokenRevoke(data)
	if err != nil {
		t.Fatalf("ParseTokenRevoke on the marshaled record failed: %v", err)
	}
	if err := journal.VerifyTokenRevoke(parsed, journal.FormatPublicKey(pub)); err != nil {
		t.Errorf("VerifyTokenRevoke on the round-tripped record failed: %v", err)
	}

	if _, err := journal.MarshalTokenRevoke(nil); err == nil {
		t.Error("MarshalTokenRevoke accepted a nil record")
	}
}
