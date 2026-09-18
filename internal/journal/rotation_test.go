// Tests for rotation.go (WALD-31): NewKeyRotationRecord/ParseKeyRotation/
// MarshalKeyRotation against the golden fixture, and the two
// rotation-specific refusals. The append orchestration that actually
// performs a rotation is exercised in internal/store/rotation_test.go,
// since that behavior lives on (*store.Client).RotateKey; the replay that
// discovers the active key is exercised in internal/store/meta_test.go.
package journal_test

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/journal"
)

// TestNewKeyRotationRecordMatchesGoldenFixture reproduces the golden
// journal's own seq 2 rotation, byte for byte, from the production
// constructor and marshaler — the same pair fixtures_gen_test.go's
// generator now uses (WALD-31 change 7).
func TestNewKeyRotationRecordMatchesGoldenFixture(t *testing.T) {
	genesisKey := fixtureKey(0x01)
	rotatedKey := fixtureKey(0x02)

	rec := journal.NewKeyRotationRecord(2, genesisKey.Public().(ed25519.PublicKey), rotatedKey.Public().(ed25519.PublicKey), "2026-08-31T00:06:00Z")
	if err := journal.SignRotation(genesisKey, rec); err != nil {
		t.Fatalf("SignRotation failed: %v", err)
	}
	got, err := journal.MarshalKeyRotation(rec)
	if err != nil {
		t.Fatalf("MarshalKeyRotation failed: %v", err)
	}

	want, err := os.ReadFile(fixtureKeyPath(journal.TxKey(journal.MetaStreamID, 2)))
	if err != nil {
		t.Fatalf("failed to read golden rotation fixture: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("marshaled rotation does not match the golden fixture:\ngot:  %s\nwant: %s", got, want)
	}
}

// TestParseKeyRotationValid parses the golden rotation fixture and checks
// every field lands where spec section 4.1 says it should.
func TestParseKeyRotationValid(t *testing.T) {
	data, err := os.ReadFile(fixtureKeyPath(journal.TxKey(journal.MetaStreamID, 2)))
	if err != nil {
		t.Fatalf("failed to read golden rotation fixture: %v", err)
	}

	r, err := journal.ParseKeyRotation(data)
	if err != nil {
		t.Fatalf("ParseKeyRotation failed on the golden fixture: %v", err)
	}
	if r.Version != journal.VersionPrefix {
		t.Errorf("Version = %q, want %q", r.Version, journal.VersionPrefix)
	}
	if r.Stream != journal.MetaStreamID {
		t.Errorf("Stream = %q, want %q", r.Stream, journal.MetaStreamID)
	}
	if r.Seq != 2 {
		t.Errorf("Seq = %d, want 2", r.Seq)
	}
	if r.Type != journal.RecordTypeKeyRotation {
		t.Errorf("Type = %q, want %q", r.Type, journal.RecordTypeKeyRotation)
	}
	if r.OldPublicKey == "" || r.NewPublicKey == "" || r.OldPublicKey == r.NewPublicKey {
		t.Errorf("OldPublicKey = %q, NewPublicKey = %q, want distinct non-empty keys", r.OldPublicKey, r.NewPublicKey)
	}
	if r.Timestamp == "" {
		t.Error("Timestamp is empty")
	}
	if r.Signature == "" {
		t.Error("Signature is empty")
	}

	genesisKey := fixtureKey(0x01)
	wantActive := journal.FormatPublicKey(genesisKey.Public().(ed25519.PublicKey))
	if err := journal.VerifyRotation(r, wantActive); err != nil {
		t.Errorf("VerifyRotation on the golden fixture failed: %v", err)
	}
}

// TestParseKeyRotationMissingField checks that every required field, when
// absent from the JSON entirely (not merely zero-valued), is named in the
// refusal — the same presence-vs-zero-value distinction ParseGenesis and
// ParseTokenCreate/ParseTokenRevoke already enforce for their own records.
func TestParseKeyRotationMissingField(t *testing.T) {
	full := map[string]any{
		"version":        "v1",
		"stream":         "_meta",
		"seq":            "2",
		"type":           "key_rotation",
		"old_public_key": "ed25519:" + strings.Repeat("00", 32),
		"new_public_key": "ed25519:" + strings.Repeat("11", 32),
		"timestamp":      "2026-08-31T00:06:00Z",
		"signature":      "ed25519:" + strings.Repeat("22", 64),
	}

	for field := range full {
		t.Run(field, func(t *testing.T) {
			partial := make(map[string]any, len(full)-1)
			for k, v := range full {
				if k == field {
					continue
				}
				partial[k] = v
			}
			data, marshalErr := json.Marshal(partial)
			if marshalErr != nil {
				t.Fatalf("failed to marshal test JSON: %v", marshalErr)
			}

			_, err := journal.ParseKeyRotation(data)
			if err == nil {
				t.Fatalf("expected an error with %q absent, got nil", field)
			}
			if !errors.Is(err, journal.ErrInvalidRotation) {
				t.Errorf("expected errors.Is(_, ErrInvalidRotation), got %v", err)
			}
			if !strings.Contains(err.Error(), field) {
				t.Errorf("error %q does not name the missing field %q", err.Error(), field)
			}
		})
	}
}

// TestParseKeyRotationEmpty checks the empty-input guard.
func TestParseKeyRotationEmpty(t *testing.T) {
	_, err := journal.ParseKeyRotation(nil)
	if !errors.Is(err, journal.ErrInvalidRotation) {
		t.Fatalf("expected errors.Is(_, ErrInvalidRotation), got %v", err)
	}
}

// TestMarshalKeyRotationNil checks MarshalKeyRotation's nil guard.
func TestMarshalKeyRotationNil(t *testing.T) {
	_, err := journal.MarshalKeyRotation(nil)
	if !errors.Is(err, journal.ErrInvalidRotation) {
		t.Fatalf("expected errors.Is(_, ErrInvalidRotation), got %v", err)
	}
}

// TestRefuseCorruptRotationIsOneLine checks PHILOSOPHY.md's one-line
// refusal convention holds for a corrupt rotation record.
func TestRefuseCorruptRotationIsOneLine(t *testing.T) {
	err := journal.RefuseCorruptRotation(2, errors.New("missing required field \"signature\""))
	if err == nil {
		t.Fatal("expected a non-nil refusal")
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
	if !strings.Contains(err.Error(), journal.TxKey(journal.MetaStreamID, 2)) {
		t.Errorf("refusal does not name the object key: %q", err.Error())
	}
}

// TestRefuseNotActiveSigningKeyIsOneLine checks PHILOSOPHY.md's one-line
// refusal convention holds for RotateKey's own precondition refusal, and
// that it wraps ErrSigningKeyUnavailable so a caller can classify it the
// same way every other signing-key-unavailable refusal is classified.
func TestRefuseNotActiveSigningKeyIsOneLine(t *testing.T) {
	dataDir := t.TempDir()
	localKey := "ed25519:" + strings.Repeat("aa", 32)
	activeKey := "ed25519:" + strings.Repeat("bb", 32)

	err := journal.RefuseNotActiveSigningKey(dataDir, localKey, activeKey)
	if err == nil {
		t.Fatal("expected a non-nil refusal")
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
	if !errors.Is(err, journal.ErrSigningKeyUnavailable) {
		t.Errorf("expected errors.Is(_, ErrSigningKeyUnavailable), got %v", err)
	}
	if !strings.Contains(err.Error(), localKey) || !strings.Contains(err.Error(), activeKey) {
		t.Errorf("refusal does not name both keys: %q", err.Error())
	}
}
