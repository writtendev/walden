// Tests for genesis.go (WALD-28): ParseGenesis/MarshalGenesis against the
// golden fixture, and the signing-key file round trip. The GET-then-
// conditional-PUT orchestration that decides mint vs adopt is exercised in
// internal/store/genesis_test.go, since that behavior lives on
// (*store.Client).EnsureGenesis.
package journal_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/journal"
)

// TestParseGenesisValid parses the golden genesis fixture and checks every
// field lands where spec section 3.1 says it should.
func TestParseGenesisValid(t *testing.T) {
	data, err := os.ReadFile(fixtureKeyPath(journal.TxKey(journal.MetaStreamID, 0)))
	if err != nil {
		t.Fatalf("failed to read golden genesis fixture: %v", err)
	}

	g, err := journal.ParseGenesis(data)
	if err != nil {
		t.Fatalf("ParseGenesis failed on the golden fixture: %v", err)
	}
	if g.Version != "v1" {
		t.Errorf("Version = %q, want %q", g.Version, "v1")
	}
	if g.Stream != journal.MetaStreamID {
		t.Errorf("Stream = %q, want %q", g.Stream, journal.MetaStreamID)
	}
	if g.Seq != 0 {
		t.Errorf("Seq = %d, want 0", g.Seq)
	}
	if g.Type != journal.RecordTypeGenesis {
		t.Errorf("Type = %q, want %q", g.Type, journal.RecordTypeGenesis)
	}
	if g.PublicKey != "ed25519:8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c" {
		t.Errorf("PublicKey = %q, want the fixture's key", g.PublicKey)
	}
	if g.Timestamp != "2026-08-31T00:00:00Z" {
		t.Errorf("Timestamp = %q, want %q", g.Timestamp, "2026-08-31T00:00:00Z")
	}
}

// TestParseGenesisMissingFields covers the presence check ParseGenesis's
// shadow struct performs, styled on TestParseMarkerMissingFields: a genesis
// record missing any required field is refused by name, rather than an
// absent seq silently decoding to 0 (the same gap WALD-97 closed for
// markers).
func TestParseGenesisMissingFields(t *testing.T) {
	complete := map[string]any{
		"version":    "v1",
		"stream":     "_meta",
		"seq":        "0",
		"type":       "genesis",
		"public_key": "ed25519:8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
		"timestamp":  "2026-08-31T00:00:00Z",
	}

	for _, field := range []string{"version", "stream", "seq", "type", "public_key", "timestamp"} {
		t.Run("missing "+field, func(t *testing.T) {
			doc := make(map[string]any, len(complete))
			for k, v := range complete {
				if k == field {
					continue
				}
				doc[k] = v
			}
			data, err := json.Marshal(doc)
			if err != nil {
				t.Fatalf("failed to marshal test document: %v", err)
			}
			_, err = journal.ParseGenesis(data)
			if err == nil {
				t.Fatalf("expected error for a genesis record missing %q, got nil", field)
			}
			if !errors.Is(err, journal.ErrInvalidGenesis) {
				t.Errorf("expected ErrInvalidGenesis for missing %q, got %v", field, err)
			}
			if !strings.Contains(err.Error(), field) {
				t.Errorf("expected error naming the missing field %q, got %q", field, err.Error())
			}
		})
	}

	// The complete document, unmodified, must parse: the control that proves
	// each failure above comes from the field actually being absent.
	data, err := json.Marshal(complete)
	if err != nil {
		t.Fatalf("failed to marshal complete test document: %v", err)
	}
	if _, err := journal.ParseGenesis(data); err != nil {
		t.Fatalf("ParseGenesis failed on a complete document: %v", err)
	}
}

// TestParseGenesisRefusesJSONNumberSeq covers section 1.1's discipline: seq
// is a JSON string holding its exact decimal form, not a JSON number, so a
// bare 0 is refused rather than silently accepted.
func TestParseGenesisRefusesJSONNumberSeq(t *testing.T) {
	raw := `{
		"version": "v1",
		"stream": "_meta",
		"seq": 0,
		"type": "genesis",
		"public_key": "ed25519:8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
		"timestamp": "2026-08-31T00:00:00Z"
	}`
	_, err := journal.ParseGenesis([]byte(raw))
	if err == nil {
		t.Fatal("expected error for a JSON-number seq, got nil")
	}
	if !errors.Is(err, journal.ErrInvalidGenesis) {
		t.Errorf("expected ErrInvalidGenesis, got %v", err)
	}
}

// TestParseGenesisRefusesBadPublicKey covers a public_key that is present
// but not a well-formed "ed25519:<64-hex>" string.
func TestParseGenesisRefusesBadPublicKey(t *testing.T) {
	raw := `{
		"version": "v1",
		"stream": "_meta",
		"seq": "0",
		"type": "genesis",
		"public_key": "not-a-key",
		"timestamp": "2026-08-31T00:00:00Z"
	}`
	_, err := journal.ParseGenesis([]byte(raw))
	if err == nil {
		t.Fatal("expected error for a malformed public_key, got nil")
	}
	if !errors.Is(err, journal.ErrInvalidGenesis) {
		t.Errorf("expected ErrInvalidGenesis, got %v", err)
	}
}

// TestMarshalGenesisMatchesFixture pins MarshalGenesis's byte layout against
// the golden fixture: a minted record, given the fixture's own key and
// timestamp, must be byte-identical to what a real journal already carries.
func TestMarshalGenesisMatchesFixture(t *testing.T) {
	want, err := os.ReadFile(fixtureKeyPath(journal.TxKey(journal.MetaStreamID, 0)))
	if err != nil {
		t.Fatalf("failed to read golden genesis fixture: %v", err)
	}

	pub, err := journal.ParsePublicKey("ed25519:8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c")
	if err != nil {
		t.Fatalf("ParsePublicKey failed: %v", err)
	}
	rec := journal.NewGenesisRecord(pub, "2026-08-31T00:00:00Z")

	got, err := journal.MarshalGenesis(rec)
	if err != nil {
		t.Fatalf("MarshalGenesis failed: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("MarshalGenesis output does not match the golden fixture:\ngot:  %q\nwant: %q", got, want)
	}
}

// TestSigningKeyRoundTrip covers SaveSigningKey/LoadSigningKey: a saved
// keypair is reconstructed exactly, and the file lands at mode 0600.
func TestSigningKeyRoundTrip(t *testing.T) {
	dataDir := t.TempDir()
	priv, _, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	if err := journal.SaveSigningKey(dataDir, priv); err != nil {
		t.Fatalf("SaveSigningKey failed: %v", err)
	}

	loaded, err := journal.LoadSigningKey(dataDir)
	if err != nil {
		t.Fatalf("LoadSigningKey failed: %v", err)
	}
	if !priv.Equal(loaded) {
		t.Errorf("loaded key does not match saved key")
	}

	path := journal.SigningKeyPath(dataDir)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s) failed: %v", path, err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("signing key file mode = %o, want 0600", perm)
	}

	if tmp := path + ".tmp"; fileExists(tmp) {
		t.Errorf("temp file %s left behind after SaveSigningKey", tmp)
	}
}

// TestLoadSigningKeyAbsent covers LoadSigningKey's "absent" convention: a
// data directory with no signing.key at all reports through
// os.IsNotExist(err), the same convention FileTokenStore.load uses for a
// missing tokens.json.
func TestLoadSigningKeyAbsent(t *testing.T) {
	dataDir := t.TempDir()
	_, err := journal.LoadSigningKey(dataDir)
	if err == nil {
		t.Fatal("expected error for a missing signing key file, got nil")
	}
	if !os.IsNotExist(err) {
		t.Errorf("expected os.IsNotExist(err) to be true, got %v", err)
	}
}

// TestLoadSigningKeyMalformed covers a signing.key that exists but is not
// the single "ed25519:<64-hex seed>" line LoadSigningKey expects: refused
// in one line, with no embedded newline, wrapping ErrSigningKeyUnavailable.
func TestLoadSigningKeyMalformed(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"empty-file", ""},
		{"wrong-prefix", "not-ed25519:deadbeef\n"},
		{"truncated-hex", "ed25519:deadbeef\n"},
		{"non-hex", "ed25519:" + strings.Repeat("z", 64) + "\n"},
		{"two-lines", "ed25519:" + strings.Repeat("a", 64) + "\ned25519:" + strings.Repeat("b", 64) + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataDir := t.TempDir()
			path := journal.SigningKeyPath(dataDir)
			if err := os.WriteFile(path, []byte(tt.content), 0600); err != nil {
				t.Fatalf("failed to seed signing key file: %v", err)
			}
			_, err := journal.LoadSigningKey(dataDir)
			if err == nil {
				t.Fatalf("expected error for malformed signing key file %q, got nil", tt.name)
			}
			if os.IsNotExist(err) {
				t.Errorf("expected a malformed-file error, got a not-exist error: %v", err)
			}
			if !errors.Is(err, journal.ErrSigningKeyUnavailable) {
				t.Errorf("expected ErrSigningKeyUnavailable, got %v", err)
			}
			if strings.ContainsAny(err.Error(), "\n\r") {
				t.Errorf("error is not a single line: %q", err.Error())
			}
		})
	}
}

// TestWriteSigningKeyTempThenCommit covers the two-step sequence
// EnsureGenesis's mint path drives directly: WriteSigningKeyTemp leaves only
// a temp file behind (LoadSigningKey still sees "absent"), and
// CommitSigningKey renames the returned path into place.
func TestWriteSigningKeyTempThenCommit(t *testing.T) {
	dataDir := t.TempDir()
	priv, _, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	tmpPath, err := journal.WriteSigningKeyTemp(dataDir, priv)
	if err != nil {
		t.Fatalf("WriteSigningKeyTemp failed: %v", err)
	}
	if _, err := journal.LoadSigningKey(dataDir); !os.IsNotExist(err) {
		t.Fatalf("LoadSigningKey before commit: err = %v, want os.IsNotExist", err)
	}
	if !fileExists(tmpPath) {
		t.Fatalf("expected temp file %s to exist after WriteSigningKeyTemp", tmpPath)
	}
	if tmpPath == journal.SigningKeyPath(dataDir)+".tmp" {
		t.Errorf("tmpPath = %q, want a random per-call suffix rather than the old fixed name", tmpPath)
	}

	if err := journal.CommitSigningKey(dataDir, tmpPath); err != nil {
		t.Fatalf("CommitSigningKey failed: %v", err)
	}
	if fileExists(tmpPath) {
		t.Errorf("temp file %s left behind after CommitSigningKey", tmpPath)
	}
	loaded, err := journal.LoadSigningKey(dataDir)
	if err != nil {
		t.Fatalf("LoadSigningKey after commit failed: %v", err)
	}
	if !priv.Equal(loaded) {
		t.Errorf("loaded key does not match the key written to the temp file")
	}
}

// TestWriteSigningKeyTempNamesDistinctFiles covers round 1 finding 1's fix
// directly: two calls to WriteSigningKeyTemp against the same data
// directory (as two racing processes sharing one --data-dir would each
// make) must never collide on the same path or overwrite each other's
// bytes — each gets its own temp file, and each is independently readable
// back through a rename to a distinct destination.
func TestWriteSigningKeyTempNamesDistinctFiles(t *testing.T) {
	dataDir := t.TempDir()
	privA, _, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	privB, _, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	tmpA, err := journal.WriteSigningKeyTemp(dataDir, privA)
	if err != nil {
		t.Fatalf("WriteSigningKeyTemp (A) failed: %v", err)
	}
	tmpB, err := journal.WriteSigningKeyTemp(dataDir, privB)
	if err != nil {
		t.Fatalf("WriteSigningKeyTemp (B) failed: %v", err)
	}
	if tmpA == tmpB {
		t.Fatalf("two WriteSigningKeyTemp calls produced the same path %q", tmpA)
	}
	if !fileExists(tmpA) {
		t.Errorf("expected %s to still exist after a second, independent WriteSigningKeyTemp call", tmpA)
	}
	if !fileExists(tmpB) {
		t.Errorf("expected %s to exist", tmpB)
	}

	if err := journal.CommitSigningKey(dataDir, tmpA); err != nil {
		t.Fatalf("CommitSigningKey(A) failed: %v", err)
	}
	loaded, err := journal.LoadSigningKey(dataDir)
	if err != nil {
		t.Fatalf("LoadSigningKey failed: %v", err)
	}
	if !privA.Equal(loaded) {
		t.Errorf("committed key does not match privA: A's temp file must not have been clobbered by B's write")
	}
	journal.RemoveSigningKeyTemp(tmpB)
}

// TestRemoveSigningKeyTemp covers the cleanup EnsureGenesis performs when
// its conditional PUT does not win: RemoveSigningKeyTemp deletes the temp
// file and is a harmless no-op when there is nothing to remove.
func TestRemoveSigningKeyTemp(t *testing.T) {
	dataDir := t.TempDir()
	priv, _, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	tmpPath, err := journal.WriteSigningKeyTemp(dataDir, priv)
	if err != nil {
		t.Fatalf("WriteSigningKeyTemp failed: %v", err)
	}
	if !fileExists(tmpPath) {
		t.Fatalf("expected temp file %s to exist", tmpPath)
	}

	journal.RemoveSigningKeyTemp(tmpPath)
	if fileExists(tmpPath) {
		t.Errorf("temp file %s still present after RemoveSigningKeyTemp", tmpPath)
	}

	// A second call with nothing to remove must not panic or error visibly.
	journal.RemoveSigningKeyTemp(tmpPath)
}

// TestGenesisRefusalsAreSingleLine covers the shape of every refusal this
// file adds: one line, "<what>: <why> (<fix>)", no embedded newlines.
func TestGenesisRefusalsAreSingleLine(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	errs := []error{
		journal.RefuseCorruptGenesis(errors.New("unexpected end of JSON input")),
		journal.RefuseNoSigningKey(dataDir),
		journal.RefuseSigningKeyMismatch(dataDir, "ed25519:aa", "ed25519:bb"),
		journal.RefuseInvalidSigningKeyFile(dataDir, errors.New("bad line")),
		journal.RefuseSigningKeyUnreadable(errors.New("open " + dataDir + "/signing.key: permission denied")),
		journal.RefuseSigningKeyPresentOnMint(dataDir),
		journal.RefuseSigningKeyCommitFailed(dataDir, dataDir+"/signing.key.tmp.deadbeef", errors.New("cross-device link")),
	}
	for _, err := range errs {
		if err == nil {
			t.Fatal("refusal constructor returned nil")
		}
		if strings.ContainsAny(err.Error(), "\n\r") {
			t.Errorf("refusal is not a single line: %q", err.Error())
		}
	}
	if !errors.Is(errs[0], journal.ErrInvalidGenesis) {
		t.Errorf("RefuseCorruptGenesis does not wrap ErrInvalidGenesis: %v", errs[0])
	}
	for _, err := range errs[1:] {
		if !errors.Is(err, journal.ErrSigningKeyUnavailable) {
			t.Errorf("expected ErrSigningKeyUnavailable, got %v", err)
		}
	}
}

// TestRefuseNoSigningKeyNamesLeftoverTemp covers round 1 finding 3:
// RefuseNoSigningKey must tell an interrupted mint (its temp file fsynced
// and still on disk, only the final rename missing) apart from a key that
// was never written or was genuinely lost, and name the leftover file when
// one is present rather than telling the operator the key is simply gone.
func TestRefuseNoSigningKeyNamesLeftoverTemp(t *testing.T) {
	dataDir := t.TempDir()

	plain := journal.RefuseNoSigningKey(dataDir)
	if strings.Contains(plain.Error(), ".tmp.") {
		t.Errorf("refusal names a temp file that does not exist: %q", plain.Error())
	}

	priv, _, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	tmpPath, err := journal.WriteSigningKeyTemp(dataDir, priv)
	if err != nil {
		t.Fatalf("WriteSigningKeyTemp failed: %v", err)
	}

	withLeftover := journal.RefuseNoSigningKey(dataDir)
	if !strings.Contains(withLeftover.Error(), tmpPath) {
		t.Errorf("refusal does not name the leftover temp file %s: %q", tmpPath, withLeftover.Error())
	}
	if strings.ContainsAny(withLeftover.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", withLeftover.Error())
	}
	if strings.Contains(withLeftover.Error(), "restore signing.key from backup, or point") {
		t.Errorf("refusal still uses the no-leftover wording once a temp file is found: %q", withLeftover.Error())
	}
}

// TestRefuseInvalidSigningKeyFileNoDoublePath covers round 1 finding 8: the
// path must appear once, not twice, in the refusal's single line — an
// earlier version printed it both directly and inside the wrapped LoadSigningKey
// error, which already names the path itself.
func TestRefuseInvalidSigningKeyFileNoDoublePath(t *testing.T) {
	dataDir := t.TempDir()
	path := journal.SigningKeyPath(dataDir)
	if err := os.WriteFile(path, []byte("not-ed25519:deadbeef\n"), 0600); err != nil {
		t.Fatalf("failed to seed signing key file: %v", err)
	}

	_, loadErr := journal.LoadSigningKey(dataDir)
	if loadErr == nil {
		t.Fatal("expected LoadSigningKey to fail on a malformed file")
	}

	refusal := journal.RefuseInvalidSigningKeyFile(dataDir, loadErr)
	if n := strings.Count(refusal.Error(), path); n != 1 {
		t.Errorf("path %s appears %d times in %q, want exactly once", path, n, refusal.Error())
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
