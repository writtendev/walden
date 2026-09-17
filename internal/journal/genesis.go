// This file implements the local half of the genesis record (spec/journal/v1
// section 3, section 2.1's signing identity lifecycle): strict decode/encode
// of the record itself, plus the signing-key file kept beside the token
// store on server disk. It does no I/O against object storage — the
// GET-then-conditional-PUT orchestration that decides mint vs adopt lives on
// (*store.Client).EnsureGenesis (internal/store/genesis.go), because
// internal/journal cannot import internal/store (that cycles) and only
// store can tell a 404 from a 403 or an ambiguous write. internal/store/
// probe.go is the precedent for that split: a boot-time, journal-governed
// behavior implemented as a method on *store.Client that borrows this
// package for its refusal text.
package journal

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/writtendev/walden/internal/refusal"
)

// ErrSigningKeyUnavailable indicates this instance cannot produce the
// private key that matches an adopted genesis record's public half: the
// signing-key file is absent, malformed, or names a different key than the
// genesis record does. An instance that cannot sign cannot journal, and a
// push it could not journal must not be acknowledged (spec/journal/v1
// section 2.2's permanent-private-key-loss case). This is the one new
// sentinel this file adds; every other failure wraps ErrInvalidGenesis
// (identity.go), already defined for a malformed or invalid genesis record.
var ErrSigningKeyUnavailable = errors.New("signing key unavailable")

// signingKeyFileName is the signing key file's name under a walden data
// directory. There is no configuration knob for it: like tokens.json
// (internal/auth/filestore.go), its path derives entirely from the data
// directory, knob one of five.
const signingKeyFileName = "signing.key"

// signingKeyTmpSuffix names the sibling temp file SaveSigningKey and its two
// halves (WriteSigningKeyTemp, CommitSigningKey) use for the same atomic
// write-then-rename discipline FileTokenStore.save uses for tokens.json.
const signingKeyTmpSuffix = ".tmp"

// signingKeyPrefix is the on-disk line's prefix. The line holds the
// Ed25519 seed (ed25519.NewKeyFromSeed's 32-byte input), not the derived
// public key: SaveSigningKey stores exactly what LoadSigningKey needs to
// reconstruct the full private key.
const signingKeyPrefix = "ed25519:"

// genesisShadow decodes genesis.json into pointer fields so ParseGenesis can
// tell a field that is genuinely absent from one that decoded to its zero
// value. This mirrors markerShadow in marker.go (WALD-97's fix for the same
// absent-vs-zero gap Seq.UnmarshalJSON documents on itself and leaves open):
// genesis is the root of trust for everything else in the journal, so the
// gap is closed here the same way.
type genesisShadow struct {
	Version   *string   `json:"version"`
	Stream    *StreamID `json:"stream"`
	Seq       *Seq      `json:"seq"`
	Type      *string   `json:"type"`
	PublicKey *string   `json:"public_key"`
	Timestamp *string   `json:"timestamp"`
}

// ParseGenesis parses a genesis.json byte slice: it decodes into a shadow
// struct of pointer fields and refuses an absent required field by name.
// Full field validation (version, stream, seq, type, and public-key format)
// stays in (*SigningChain).ApplyGenesis, which every caller runs on a fresh
// NewSigningChain() before trusting the record — ParseGenesis itself checks
// presence only, exactly as ParseMarker does for marker.json.
func ParseGenesis(data []byte) (*GenesisRecord, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty genesis data", ErrInvalidGenesis)
	}
	var shadow genesisShadow
	if err := json.Unmarshal(data, &shadow); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidGenesis, err)
	}
	missing := ""
	switch {
	case shadow.Version == nil:
		missing = "version"
	case shadow.Stream == nil:
		missing = "stream"
	case shadow.Seq == nil:
		missing = "seq"
	case shadow.Type == nil:
		missing = "type"
	case shadow.PublicKey == nil:
		missing = "public_key"
	case shadow.Timestamp == nil:
		missing = "timestamp"
	}
	if missing != "" {
		return nil, fmt.Errorf("%w: missing required field %q", ErrInvalidGenesis, missing)
	}
	// public_key's encoding ("ed25519:<64-hex>") is checked here, ahead of
	// ApplyGenesis, because it is the one field a malformed value renders
	// outright unusable rather than merely invalid for this record's
	// position in the chain — every other field (version, stream, seq,
	// type) ApplyGenesis validates in full.
	if _, err := ParsePublicKey(*shadow.PublicKey); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidGenesis, err)
	}
	return &GenesisRecord{
		Version:   *shadow.Version,
		Stream:    *shadow.Stream,
		Seq:       *shadow.Seq,
		Type:      *shadow.Type,
		PublicKey: *shadow.PublicKey,
		Timestamp: *shadow.Timestamp,
	}, nil
}

// MarshalGenesis serializes a GenesisRecord to indented JSON with a trailing
// newline, matching MarshalMarker and the fixture writer: a minted record is
// byte-identical to the golden fixture
// (spec/journal/v1/fixtures/v1/streams/_meta/tx/00000000000000000000.json)
// given the same key and timestamp.
func MarshalGenesis(g *GenesisRecord) ([]byte, error) {
	if g == nil {
		return nil, fmt.Errorf("%w: genesis record cannot be nil", ErrInvalidGenesis)
	}
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal genesis record: %w", err)
	}
	return append(data, '\n'), nil
}

// NewGenesisRecord builds the genesis record a first boot mints: the fixed
// fields spec section 3.1 requires (version "v1", stream "_meta", seq 0,
// type "genesis"), pub formatted as "ed25519:<64-hex>", and timestamp
// (RFC 3339 UTC) supplied by the caller so minting stays deterministic in
// tests.
func NewGenesisRecord(pub ed25519.PublicKey, timestamp string) *GenesisRecord {
	return &GenesisRecord{
		Version:   VersionPrefix,
		Stream:    MetaStreamID,
		Seq:       0,
		Type:      RecordTypeGenesis,
		PublicKey: FormatPublicKey(pub),
		Timestamp: timestamp,
	}
}

// SigningKeyPath returns the signing key file's path under dataDir:
// <dataDir>/signing.key. There is no configuration knob for it — like
// tokens.json, it derives entirely from the data directory.
func SigningKeyPath(dataDir string) string {
	return filepath.Join(dataDir, signingKeyFileName)
}

// LoadSigningKey reads and parses the signing key file at
// SigningKeyPath(dataDir). A missing file is returned as the raw *PathError
// os.ReadFile produces, so a caller can tell "no local key yet" from "the
// file exists and is broken" with the standard os.IsNotExist(err) check —
// the same "absent" convention FileTokenStore.load uses for a missing
// tokens.json. Any other failure, including malformed content, is wrapped
// in ErrSigningKeyUnavailable.
func LoadSigningKey(dataDir string) (ed25519.PrivateKey, error) {
	path := SigningKeyPath(dataDir)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	line := strings.TrimSuffix(string(data), "\n")
	if line == "" || strings.Contains(line, "\n") || !strings.HasPrefix(line, signingKeyPrefix) {
		return nil, fmt.Errorf("%w: %s is not a single %q line", ErrSigningKeyUnavailable, path, signingKeyPrefix+"<64-hex>")
	}
	hexSeed := strings.TrimPrefix(line, signingKeyPrefix)
	if len(hexSeed) != ed25519.SeedSize*2 {
		return nil, fmt.Errorf("%w: %s seed must be %d hex characters, got %d", ErrSigningKeyUnavailable, path, ed25519.SeedSize*2, len(hexSeed))
	}
	seed, err := hex.DecodeString(hexSeed)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrSigningKeyUnavailable, path, err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// WriteSigningKeyTemp writes priv to the signing key file's sibling temp
// path (SigningKeyPath(dataDir)+".tmp"): create at mode 0600, Chmod(0600),
// write, fsync, close — the write half of the discipline FileTokenStore.save
// uses for tokens.json (internal/auth/filestore.go). It does not rename the
// temp file into place; CommitSigningKey does that. The two are separate
// calls because EnsureGenesis (internal/store/genesis.go) must write this
// file before it knows whether its conditional PUT of the genesis record
// will win the race to initialize the journal — the private key can only be
// committed to disk once that PUT has won.
func WriteSigningKeyTemp(dataDir string, priv ed25519.PrivateKey) error {
	path := SigningKeyPath(dataDir)
	tmpPath := path + signingKeyTmpSuffix
	line := signingKeyPrefix + hex.EncodeToString(priv.Seed()) + "\n"

	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("cannot create %s: %w", tmpPath, err)
	}
	// OpenFile's mode argument only applies when it creates the file: a
	// signing.key.tmp left behind by an earlier crash is instead reused at
	// its existing mode. Chmod makes the final mode 0600 unconditionally.
	if err := f.Chmod(0600); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("cannot set permissions on %s: %w", tmpPath, err)
	}
	if _, err := f.WriteString(line); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("cannot write %s: %w", tmpPath, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("cannot sync %s: %w", tmpPath, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("cannot close %s: %w", tmpPath, err)
	}
	return nil
}

// CommitSigningKey renames the signing key file's temp path into place and
// fsyncs the containing directory: the second half of the sequence
// WriteSigningKeyTemp begins, and the actual commit point for a minted
// identity. A crash or failure between a winning conditional PUT and this
// rename leaves a genesis record in the bucket whose signing key never
// reached disk — EnsureGenesis's doc comment names this window; it is
// narrowed to one atomic rename, not eliminated, and there is no recovery
// mode that papers over it.
func CommitSigningKey(dataDir string) error {
	path := SigningKeyPath(dataDir)
	tmpPath := path + signingKeyTmpSuffix
	dir := filepath.Dir(path)

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("cannot replace %s: %w", path, err)
	}

	dirFile, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("cannot open data directory %s to sync it: %w", dir, err)
	}
	defer dirFile.Close()
	if err := dirFile.Sync(); err != nil {
		return fmt.Errorf("cannot sync data directory %s: %w", dir, err)
	}
	return nil
}

// RemoveSigningKeyTemp removes the signing key file's temp path, best
// effort. EnsureGenesis calls it when its conditional PUT does not win the
// race to initialize the journal (store.ErrPrecondition), when the PUT's
// outcome cannot be proven either way (store.ErrOutcomeUnknown), or when the
// PUT fails outright: in every one of those cases this instance must not
// leave behind a signing.key.tmp for a genesis record it does not own. It
// is never called once CommitSigningKey has been attempted — a failure
// there means the temp file may hold the only surviving copy of the private
// key, so it is left on disk rather than deleted.
func RemoveSigningKeyTemp(dataDir string) {
	os.Remove(SigningKeyPath(dataDir) + signingKeyTmpSuffix)
}

// SaveSigningKey persists priv as dataDir's signing key file in one call:
// WriteSigningKeyTemp followed immediately by CommitSigningKey. It exists
// for callers with no reason to split the two — tests exercising the
// key-file round trip, mainly; EnsureGenesis's mint path calls the two
// halves separately instead, for the reason WriteSigningKeyTemp's doc
// comment gives.
func SaveSigningKey(dataDir string, priv ed25519.PrivateKey) error {
	if err := WriteSigningKeyTemp(dataDir, priv); err != nil {
		return err
	}
	return CommitSigningKey(dataDir)
}

// RefuseCorruptGenesis returns a one-line refusal when the genesis object at
// _meta seq 0 cannot be parsed or does not validate (spec section 3.2 item
// 3: a journal with transactions but no valid genesis record is corrupt).
func RefuseCorruptGenesis(reason error) error {
	cause := ErrInvalidGenesis
	if reason != nil {
		cause = fmt.Errorf("%w: %w", ErrInvalidGenesis, reason)
	}
	return refusal.RefuseWithCause(
		"invalid journal",
		fmt.Sprintf("genesis record at %s is corrupt (%v)", TxKey(MetaStreamID, 0), reason),
		"restore the _meta stream from a known-good journal, or point this instance at a fresh journal prefix",
		cause,
	)
}

// RefuseNoSigningKey returns a one-line refusal when this instance has
// adopted a genesis record but holds no local signing key file at all: it
// cannot sign, so it cannot journal (spec section 2.2's permanent-private-
// key-loss case, encountered here on an instance that never had the key in
// the first place rather than one that lost it).
func RefuseNoSigningKey(dataDir string) error {
	return refusal.RefuseWithCause(
		"invalid journal",
		fmt.Sprintf("genesis record adopted but %s holds no signing key", SigningKeyPath(dataDir)),
		"restore signing.key from backup, or point this instance at a fresh journal prefix",
		ErrSigningKeyUnavailable,
	)
}

// RefuseSigningKeyMismatch returns a one-line refusal when this instance's
// local signing key does not match the adopted genesis record's public key:
// signing with it would never verify against this journal's root of trust.
func RefuseSigningKeyMismatch(dataDir, want, got string) error {
	return refusal.RefuseWithCause(
		"invalid journal",
		fmt.Sprintf("%s holds key %s, genesis at %s names %s", SigningKeyPath(dataDir), got, TxKey(MetaStreamID, 0), want),
		"restore the correct signing.key, or point this instance at a fresh journal prefix",
		ErrSigningKeyUnavailable,
	)
}

// RefuseInvalidSigningKeyFile returns a one-line refusal when the signing
// key file exists but is not the single "ed25519:<64-hex seed>" line
// LoadSigningKey expects.
func RefuseInvalidSigningKeyFile(dataDir string, reason error) error {
	cause := ErrSigningKeyUnavailable
	if reason != nil {
		cause = fmt.Errorf("%w: %w", ErrSigningKeyUnavailable, reason)
	}
	return refusal.RefuseWithCause(
		"invalid journal",
		fmt.Sprintf("%s is malformed (%v)", SigningKeyPath(dataDir), reason),
		"restore signing.key from backup",
		cause,
	)
}
