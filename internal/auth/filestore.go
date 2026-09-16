package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
)

const (
	// tokensFileName is the built-in token table's filename under a walden data directory.
	// There is no configuration knob for it: the path derives entirely from the data
	// directory, knob one of five.
	tokensFileName = "tokens.json"
	// tokensLockFileName is the cross-process write lock's sibling filename.
	tokensLockFileName = "tokens.lock"
	// tokensFileVersion is the "version" field tokens.json itself carries.
	tokensFileVersion = "v1"
)

// FileTokenStore is a TokenStore backed by a single JSON file, tokens.json, under a walden
// data directory. It is the built-in token table's storage for cycle 1, before WALD-33 adds
// a meta-stream journal writer above it — see TokenStore's doc comment for the mutation
// vocabulary that later addition builds on.
//
// Reads (GetTokenByHash, GetTokenByID, ListTokens) take no lock and re-read the file on
// every call rather than caching it: `walden token revoke` runs as a second process
// (typically `docker exec`) against a running server, so a cached table would let a
// revocation not take effect until restart.
//
// Mutations (CreateToken, RevokeToken) take an exclusive cross-process lock (see
// filelock_unix.go), re-read the file under it, change it, and replace it atomically (see
// save), so two concurrent writers cannot lose one another's update.
type FileTokenStore struct {
	path     string
	lockPath string
}

// NewFileTokenStore creates a FileTokenStore persisting to <dataDir>/tokens.json.
func NewFileTokenStore(dataDir string) *FileTokenStore {
	return &FileTokenStore{
		path:     filepath.Join(dataDir, tokensFileName),
		lockPath: filepath.Join(dataDir, tokensLockFileName),
	}
}

// diskToken is one token record's on-disk shape: {"token_id","token_hash","scopes":["rwc:*"],
// "created_at","revoked","revoked_at"}. It is written out explicitly here rather than
// inherited from TokenRecord, so tokens.json's format is decided once, in this file, and
// does not silently move if TokenRecord's fields are ever reordered or retyped for some
// other reason. Scopes round-trip through Scope.String() / ParseScopes, so the file speaks
// the same "<actions>:<pattern>" vocabulary a later token_create journal record carries
// verbatim — not TokenRecord's Go-side nested {Actions,Pattern} shape.
type diskToken struct {
	TokenID   string     `json:"token_id"`
	TokenHash string     `json:"token_hash"`
	Scopes    []string   `json:"scopes"`
	CreatedAt time.Time  `json:"created_at"`
	Revoked   bool       `json:"revoked"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// diskTable is tokens.json's top-level shape: {"version":"v1","tokens":[...]}.
type diskTable struct {
	Version string      `json:"version"`
	Tokens  []diskToken `json:"tokens"`
}

// tryDecode attempts the same conversion toRecord performs — a disk-encoded token back into
// the TokenRecord shape the rest of the package works with — but returns ParseScopes' error
// unwrapped rather than as an operator-facing refusal. It is the one place a disk-encoded
// token is turned back into a TokenRecord, so a real read (toRecord, below) and CreateToken's
// pre-write guard (validateForWrite) run the exact same round trip and each shapes its own
// refusal around the result, instead of the write side reimplementing the round trip and
// drifting from what a read actually does.
func (d diskToken) tryDecode() (*TokenRecord, error) {
	scopes, err := ParseScopes(d.Scopes)
	if err != nil {
		return nil, err
	}
	return &TokenRecord{
		TokenID:   d.TokenID,
		TokenHash: d.TokenHash,
		Scopes:    scopes,
		CreatedAt: d.CreatedAt,
		Revoked:   d.Revoked,
		RevokedAt: d.RevokedAt,
	}, nil
}

// toRecord converts a disk-encoded token into the TokenRecord shape the rest of the package
// works with, parsing its scopes back into the published vocabulary. path is the tokens.json
// path this record was read from, purely so a parse failure can be wrapped as a corrupted
// store naming the file — a scope string an operator never typed must not refuse under
// ErrInvalidScope blaming input, and it is the one corrupt-store path errors.Is(err,
// ErrStoreUnavailable) would otherwise miss.
func (d diskToken) toRecord(path string) (*TokenRecord, error) {
	rec, err := d.tryDecode()
	if err != nil {
		return nil, refusal.RefuseWithCause(
			"token store corrupted",
			fmt.Sprintf("%s carries token %q with an unparseable scope: %s", path, d.TokenID, err.Error()),
			"restore tokens.json from backup; it will not be recreated automatically",
			ErrStoreUnavailable,
		)
	}
	return rec, nil
}

// diskTokenFromRecord converts a TokenRecord into its on-disk shape.
func diskTokenFromRecord(record *TokenRecord) diskToken {
	scopes := make([]string, len(record.Scopes))
	for i, s := range record.Scopes {
		scopes[i] = s.String()
	}
	return diskToken{
		TokenID:   record.TokenID,
		TokenHash: record.TokenHash,
		Scopes:    scopes,
		CreatedAt: record.CreatedAt,
		Revoked:   record.Revoked,
		RevokedAt: record.RevokedAt,
	}
}

// load reads tokens.json. A missing file is an empty table, not an error — a fresh data
// directory has no tokens. A file that exists but is not valid JSON in the expected shape is
// refused loudly (ErrStoreUnavailable) rather than read as an empty table: silently emptying
// the table would invalidate every token and look like a configuration problem to whoever
// hits it next, rather than the corrupted file it is.
func (s *FileTokenStore) load() (*diskTable, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return &diskTable{Version: tokensFileVersion}, nil
		}
		return nil, refusal.RefuseWithCause(
			"token store unavailable",
			fmt.Sprintf("cannot read %s: %s", s.path, err.Error()),
			"verify the data directory is readable",
			ErrStoreUnavailable,
		)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var table diskTable
	if err := dec.Decode(&table); err != nil {
		return nil, refusal.RefuseWithCause(
			"token store corrupted",
			fmt.Sprintf("%s is not a valid token table: %s", s.path, err.Error()),
			"restore tokens.json from backup; it will not be recreated automatically",
			ErrStoreUnavailable,
		)
	}
	if dec.More() {
		return nil, refusal.RefuseWithCause(
			"token store corrupted",
			fmt.Sprintf("%s carries trailing data after its JSON object", s.path),
			"restore tokens.json from backup; it will not be recreated automatically",
			ErrStoreUnavailable,
		)
	}
	// A decoded table that is not recognisably a table is corruption, not an empty table:
	// `null`, `{}`, and an unrecognised version all decode above with no error and a
	// zero-valued table, and `{"tokens":null}` decodes with a nil Tokens even under a
	// recognised version. Only the missing-file case above is legitimately empty; anything
	// that made it this far came from a file that exists and must decode to the real shape.
	if table.Version != tokensFileVersion {
		return nil, refusal.RefuseWithCause(
			"token store corrupted",
			fmt.Sprintf("%s carries unrecognised version %q, want %q", s.path, table.Version, tokensFileVersion),
			"restore tokens.json from backup; it will not be recreated automatically",
			ErrStoreUnavailable,
		)
	}
	if table.Tokens == nil {
		return nil, refusal.RefuseWithCause(
			"token store corrupted",
			fmt.Sprintf("%s has no tokens array", s.path),
			"restore tokens.json from backup; it will not be recreated automatically",
			ErrStoreUnavailable,
		)
	}
	return &table, nil
}

// save replaces tokens.json with table's contents atomically: marshal, write a sibling
// tokens.json.tmp at mode 0600, fsync it, rename it over tokens.json, then fsync the
// containing directory. A reader therefore ever sees the whole old table or the whole new
// one, never a torn file — POSIX rename within one filesystem is atomic, and it is the only
// step here a concurrent reader can observe mid-flight.
func (s *FileTokenStore) save(table *diskTable) error {
	data, err := json.MarshalIndent(table, "", "  ")
	if err != nil {
		return refusal.RefuseWithCause(
			"token store unavailable",
			fmt.Sprintf("failed to encode token table: %s", err.Error()),
			"this indicates an internal bug; please report it",
			ErrStoreUnavailable,
		)
	}
	data = append(data, '\n')

	dir := filepath.Dir(s.path)
	tmpPath := s.path + ".tmp"

	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return refusal.RefuseWithCause(
			"token store unavailable",
			fmt.Sprintf("cannot create %s: %s", tmpPath, err.Error()),
			"verify the data directory is writable",
			ErrStoreUnavailable,
		)
	}
	// OpenFile's mode argument only applies when it creates the file: a tokens.json.tmp left
	// behind by an operator, a backup tool, or an earlier crash is instead reused at its
	// existing mode, and that mode would ride the rename into tokens.json itself. Chmod makes
	// the final mode 0600 unconditionally, regardless of whether this file was just created or
	// already existed.
	if err := f.Chmod(0600); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return refusal.RefuseWithCause(
			"token store unavailable",
			fmt.Sprintf("cannot set permissions on %s: %s", tmpPath, err.Error()),
			"verify the data directory is writable",
			ErrStoreUnavailable,
		)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return refusal.RefuseWithCause(
			"token store unavailable",
			fmt.Sprintf("cannot write %s: %s", tmpPath, err.Error()),
			"verify the data directory is writable",
			ErrStoreUnavailable,
		)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return refusal.RefuseWithCause(
			"token store unavailable",
			fmt.Sprintf("cannot sync %s: %s", tmpPath, err.Error()),
			"verify the data directory's filesystem is healthy",
			ErrStoreUnavailable,
		)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return refusal.RefuseWithCause(
			"token store unavailable",
			fmt.Sprintf("cannot close %s: %s", tmpPath, err.Error()),
			"verify the data directory's filesystem is healthy",
			ErrStoreUnavailable,
		)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		os.Remove(tmpPath)
		return refusal.RefuseWithCause(
			"token store unavailable",
			fmt.Sprintf("cannot replace %s: %s", s.path, err.Error()),
			"verify the data directory is writable",
			ErrStoreUnavailable,
		)
	}

	dirFile, err := os.Open(dir)
	if err != nil {
		return refusal.RefuseWithCause(
			"token store unavailable",
			fmt.Sprintf("cannot open data directory %s to sync it: %s", dir, err.Error()),
			"verify the data directory is accessible",
			ErrStoreUnavailable,
		)
	}
	defer dirFile.Close()
	if err := dirFile.Sync(); err != nil {
		return refusal.RefuseWithCause(
			"token store unavailable",
			fmt.Sprintf("cannot sync data directory %s: %s", dir, err.Error()),
			"verify the data directory's filesystem is healthy",
			ErrStoreUnavailable,
		)
	}
	return nil
}

// GetTokenByHash returns the token record with the given storage hash, or nil if none exists.
func (s *FileTokenStore) GetTokenByHash(ctx context.Context, hash string) (*TokenRecord, error) {
	table, err := s.load()
	if err != nil {
		return nil, err
	}
	for _, dt := range table.Tokens {
		if dt.TokenHash == hash {
			return dt.toRecord(s.path)
		}
	}
	return nil, nil
}

// GetTokenByID returns the token record with the given token ID, refusing under
// ErrTokenNotFound if no record carries it — see that sentinel's doc comment in auth.go.
func (s *FileTokenStore) GetTokenByID(ctx context.Context, tokenID string) (*TokenRecord, error) {
	table, err := s.load()
	if err != nil {
		return nil, err
	}
	for _, dt := range table.Tokens {
		if dt.TokenID == tokenID {
			return dt.toRecord(s.path)
		}
	}
	return nil, refusal.RefuseWithCause(
		"token lookup refused",
		fmt.Sprintf("no token with id %q exists", tokenID),
		"verify the token id with 'walden token list'",
		ErrTokenNotFound,
	)
}

// ListTokens returns every token record in the table.
func (s *FileTokenStore) ListTokens(ctx context.Context) ([]*TokenRecord, error) {
	table, err := s.load()
	if err != nil {
		return nil, err
	}
	records := make([]*TokenRecord, 0, len(table.Tokens))
	for _, dt := range table.Tokens {
		rec, err := dt.toRecord(s.path)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, nil
}

// validateForWrite is the one gate every field of record passes through before CreateToken
// appends it, enforcing two invariants by construction rather than assumption:
//
//  1. Journal parity: A record this store accepts must be journalable as a token_create record
//     by internal/journal when the meta-stream writer (WALD-33) lands later. This is verified
//     by constructing an internal/journal.TokenCreateRecord and calling its Validate() method.
//     TokenID, TokenHash, non-empty Scopes, scope character classes, scope uniqueness, and
//     canonical UTC timestamp bounds are all checked against the journal record's schema in one
//     step, so that future addition remains an addition rather than a repair or rewrite.
//
//  2. Read parity: Anything CreateToken writes must be readable back from disk by this store
//     unmodified. This is verified by simulating the full persistence pipeline: encoding a single-
//     token diskTable to JSON via json.Marshal, decoding it back through json.Decoder with
//     DisallowUnknownFields (matching load()), and running tryDecode() (matching toRecord()).
//     Finally, it asserts that record.CreatedAt survives the RFC 3339 round-trip identically
//     (rejecting non-whole-minute timezone offsets that cannot be faithfully encoded).
//
// Refusals return caller-fault sentinels (journal.ErrInvalidTokenID, journal.ErrInvalidTokenHash,
// journal.ErrInvalidTokenScope, or journal.ErrInvalidTokenRecord) — never ErrStoreUnavailable,
// which is reserved for operator-fault disk corruption.
func (s *FileTokenStore) validateForWrite(record *TokenRecord) error {
	scopeStrs := make([]string, len(record.Scopes))
	for i, sc := range record.Scopes {
		scopeStrs[i] = sc.String()
	}
	jrec := &journal.TokenCreateRecord{
		Version:   journal.VersionPrefix,
		Stream:    journal.MetaStreamID,
		Seq:       1,
		Type:      journal.RecordTypeTokenCreate,
		TokenID:   record.TokenID,
		TokenHash: record.TokenHash,
		Scopes:    scopeStrs,
		Timestamp: record.CreatedAt.UTC().Format(time.RFC3339),
	}
	if err := jrec.Validate(); err != nil {
		switch {
		case errors.Is(err, journal.ErrInvalidTokenID):
			return refusal.RefuseWithCause(
				"token create refused",
				err.Error(),
				"pass a token id containing only [a-zA-Z0-9._-]",
				journal.ErrInvalidTokenID,
			)
		case errors.Is(err, journal.ErrInvalidTokenHash):
			return refusal.RefuseWithCause(
				"token create refused",
				err.Error(),
				"pass the sha256:<64-hex> storage hash from HashToken, not the raw token",
				journal.ErrInvalidTokenHash,
			)
		default:
			return refusal.RefuseWithCause(
				"token create refused",
				err.Error(),
				"pass scopes and a timestamp that satisfy the token_create record schema",
				journal.ErrInvalidTokenRecord,
			)
		}
	}

	dt := diskTokenFromRecord(record)
	probeTable := diskTable{
		Version: tokensFileVersion,
		Tokens:  []diskToken{dt},
	}
	data, err := json.Marshal(probeTable)
	if err != nil {
		return refusal.RefuseWithCause(
			"token create refused",
			fmt.Sprintf("record cannot be encoded as JSON: %s", err.Error()),
			"pass fields that can be encoded as JSON",
			journal.ErrInvalidTokenRecord,
		)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var decodedTable diskTable
	if err := dec.Decode(&decodedTable); err != nil || len(decodedTable.Tokens) != 1 {
		return refusal.RefuseWithCause(
			"token create refused",
			"record cannot be decoded back from JSON",
			"pass fields that survive a JSON round-trip",
			journal.ErrInvalidTokenRecord,
		)
	}
	decodedDT := decodedTable.Tokens[0]
	rec, err := decodedDT.tryDecode()
	if err != nil {
		return refusal.RefuseWithCause(
			"token create refused",
			fmt.Sprintf("record would not read back once written: %s", err.Error()),
			"pass scopes that round-trip through Scope.String()/ParseScopes: each needs at least one action and a non-empty pattern",
			journal.ErrInvalidTokenRecord,
		)
	}
	if !rec.CreatedAt.Equal(record.CreatedAt) {
		return refusal.RefuseWithCause(
			"token create refused",
			fmt.Sprintf("created_at timestamp %v does not survive RFC 3339 round-trip (zone offset must be a whole number of minutes)", record.CreatedAt),
			"pass a timestamp with a whole-minute timezone offset (e.g. UTC)",
			journal.ErrInvalidTokenRecord,
		)
	}
	return nil
}

// CreateToken appends a new token record, refusing (ErrTokenExists) rather than overwriting
// when a record already exists with the same TokenID or TokenHash — a create is always a
// create, never an upsert a caller must infer from success alone. record.CreatedAt is
// persisted as given; CreateToken never calls time.Now, so a future meta-stream journal
// writer (WALD-33) can stamp both records from the same instant.
//
// Before anything else, record is run through validateForWrite: "raw tokens never touch
// disk" and "a record this store accepts can be read back" are properties this store holds
// itself to, not ones it merely assumes of its callers. A rejected hash withholds the value,
// since it may be a live raw token; nothing else record carries is a secret.
func (s *FileTokenStore) CreateToken(ctx context.Context, record *TokenRecord) error {
	if record == nil {
		return refusal.Refuse("token create refused", "record is nil", "pass a non-nil token record")
	}
	if err := s.validateForWrite(record); err != nil {
		return err
	}

	lock, err := acquireStoreLock(ctx, s.lockPath)
	if err != nil {
		return err
	}
	defer lock.release()

	table, err := s.load()
	if err != nil {
		return err
	}
	for _, existing := range table.Tokens {
		if existing.TokenID == record.TokenID {
			return refusal.RefuseWithCause(
				"token create refused",
				fmt.Sprintf("token id %q already exists", record.TokenID),
				"choose a different token id",
				ErrTokenExists,
			)
		}
		if existing.TokenHash == record.TokenHash {
			return refusal.RefuseWithCause(
				"token create refused",
				"a token with this hash already exists",
				"generate a new token rather than reusing a hash",
				ErrTokenExists,
			)
		}
	}

	table.Tokens = append(table.Tokens, diskTokenFromRecord(record))
	return s.save(table)
}

// RevokeToken marks the token identified by tokenID as revoked at the given instant.
// RevokeToken only ever narrows a grant: revoking an unknown token id is refused
// (ErrTokenNotFound), and revoking an already-revoked token is refused too
// (ErrTokenAlreadyRevoked) rather than treated as a no-op — see that sentinel's doc comment
// in auth.go. RevokeToken never calls time.Now; at is the caller's, for the same journaling
// reason CreateToken takes CreatedAt as given.
//
// Two records sharing a token_id is a damaged store — CreateToken refuses that shape under
// its own lock, so it can only arise from something editing tokens.json by hand — and
// RevokeToken refuses under ErrStoreUnavailable rather than silently acting on the first
// match and reporting success while a second record with the same id keeps authenticating.
// This check lives here rather than in load: load runs on every unlocked read (GetTokenByHash
// included, on the request path), where paying a uniqueness scan is a worse trade than
// catching the shape at the one mutation that can act on it wrongly.
func (s *FileTokenStore) RevokeToken(ctx context.Context, tokenID string, at time.Time) error {
	lock, err := acquireStoreLock(ctx, s.lockPath)
	if err != nil {
		return err
	}
	defer lock.release()

	table, err := s.load()
	if err != nil {
		return err
	}

	match := -1
	matches := 0
	for i := range table.Tokens {
		if table.Tokens[i].TokenID == tokenID {
			match = i
			matches++
		}
	}

	if matches > 1 {
		return refusal.RefuseWithCause(
			"token revoke refused",
			fmt.Sprintf("%s carries %d records with token id %q", s.path, matches, tokenID),
			"restore tokens.json from backup; it will not be recreated automatically",
			ErrStoreUnavailable,
		)
	}

	if matches == 1 {
		if table.Tokens[match].Revoked {
			return refusal.RefuseWithCause(
				"token revoke refused",
				fmt.Sprintf("token id %q is already revoked", tokenID),
				"no action needed; the token is already inactive",
				ErrTokenAlreadyRevoked,
			)
		}
		revokedAt := at.UTC()
		table.Tokens[match].Revoked = true
		table.Tokens[match].RevokedAt = &revokedAt
		return s.save(table)
	}

	return refusal.RefuseWithCause(
		"token revoke refused",
		fmt.Sprintf("no token with id %q exists", tokenID),
		"verify the token id with 'walden token list'",
		ErrTokenNotFound,
	)
}
