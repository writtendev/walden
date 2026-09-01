package journal_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/journal"
)

// The golden journal under spec/journal/v1/fixtures is generated, not hand-written:
// every SHA-256 is the real digest of the file it names, every packfile comes out of
// the real git binary, and every signature is produced by the canonical payload
// builders in this package. Regenerate with:
//
//	WALDEN_REGENERATE_FIXTURES=1 go test ./internal/journal -run TestRegenerateFixtures
//
// then commit the result. Signing keys, timestamps, and git object dates are all
// fixed, so the records reproduce byte for byte. Packfile bytes are produced by the
// local git binary; a different git version may pack the same objects differently,
// which changes the content-addressed segment names but not their correctness.

// fixtureGitDate is the fixed author and committer date for every fixture commit.
const fixtureGitDate = "1767225600 +0000"

// fixtureKey derives the deterministic Ed25519 signing key whose seed is seedByte repeated.
func fixtureKey(seedByte byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	return ed25519.NewKeyFromSeed(seed)
}

// gitRepo is a throwaway bare repository used to mint real commits and real packfiles.
type gitRepo struct {
	t   *testing.T
	dir string
}

func newGitRepo(t *testing.T) *gitRepo {
	t.Helper()
	r := &gitRepo{t: t, dir: t.TempDir()}
	r.run(nil, "init", "--quiet", "--bare", ".")
	return r
}

func (r *gitRepo) run(stdin []byte, args ...string) []byte {
	r.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = r.dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=walden fixtures",
		"GIT_AUTHOR_EMAIL=fixtures@walden.invalid",
		"GIT_COMMITTER_NAME=walden fixtures",
		"GIT_COMMITTER_EMAIL=fixtures@walden.invalid",
		"GIT_AUTHOR_DATE="+fixtureGitDate,
		"GIT_COMMITTER_DATE="+fixtureGitDate,
	)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		r.t.Fatalf("git %s failed: %v: %s", strings.Join(args, " "), err, stderr.String())
	}
	return out
}

// commit writes a single-file tree and a commit over it, returning the commit OID.
func (r *gitRepo) commit(parent, filename, content, message string) string {
	r.t.Helper()
	blob := strings.TrimSpace(string(r.run([]byte(content), "hash-object", "-w", "--stdin")))
	tree := strings.TrimSpace(string(r.run([]byte(fmt.Sprintf("100644 blob %s\t%s\n", blob, filename)), "mktree")))
	args := []string{"commit-tree", tree}
	if parent != "" {
		args = append(args, "-p", parent)
	}
	args = append(args, "-m", message)
	return strings.TrimSpace(string(r.run(nil, args...)))
}

// pack returns the verbatim bytes of a packfile holding the objects selected by revs.
func (r *gitRepo) pack(revs ...string) []byte {
	r.t.Helper()
	return r.run([]byte(strings.Join(revs, "\n")+"\n"), "pack-objects", "--stdout", "--revs")
}

// fixtureWriter accumulates the object tree that will be written under fixtures/.
type fixtureWriter struct {
	t    *testing.T
	root string
}

func (w *fixtureWriter) write(rel string, data []byte) {
	w.t.Helper()
	path := filepath.Join(w.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		w.t.Fatalf("failed to create %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		w.t.Fatalf("failed to write %s: %v", path, err)
	}
}

// writeJSON writes an indented JSON document with a trailing newline.
func (w *fixtureWriter) writeJSON(rel string, v any) {
	w.t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		w.t.Fatalf("failed to marshal %s: %v", rel, err)
	}
	w.write(rel, append(data, '\n'))
}

// writeSegment writes a pack segment under its own SHA-256 and returns that hash.
func (w *fixtureWriter) writeSegment(stream journal.StreamID, pack []byte) string {
	w.t.Helper()
	hash := journal.ComputeSegmentHash(pack)
	if err := journal.ValidateSegment(pack, hash); err != nil {
		w.t.Fatalf("generated segment for stream %s is not a valid packfile: %v", stream, err)
	}
	w.write(fmt.Sprintf("streams/%s/segments/%s.pack", stream, hash), pack)
	return hash
}

// writeRefTx signs and writes a ref transaction record, returning nothing but failing on error.
func (w *fixtureWriter) writeRefTx(priv ed25519.PrivateKey, rec *journal.RefTransactionRecord) {
	w.t.Helper()
	if err := journal.SignRefTx(priv, rec); err != nil {
		w.t.Fatalf("failed to sign %s seq %d: %v", rec.Stream, rec.Seq, err)
	}
	w.writeJSON(fmt.Sprintf("streams/%s/tx/%s.json", rec.Stream, journal.FormatSeq(rec.Seq)), rec)
}

// metaRecord is a meta-stream record that carries no signature (genesis and token mutations).
type metaRecord struct {
	Version   string           `json:"version"`
	Stream    journal.StreamID `json:"stream"`
	Seq       uint64           `json:"seq"`
	Type      string           `json:"type"`
	PublicKey string           `json:"public_key,omitempty"`
	TokenID   string           `json:"token_id,omitempty"`
	Scope     string           `json:"scope,omitempty"`
	Timestamp string           `json:"timestamp"`
}

func TestRegenerateFixtures(t *testing.T) {
	if os.Getenv("WALDEN_REGENERATE_FIXTURES") == "" {
		t.Skip("set WALDEN_REGENERATE_FIXTURES=1 to rewrite spec/journal/v1/fixtures")
	}

	root := journalFixturesDir()
	if err := os.RemoveAll(filepath.Join(root, "streams")); err != nil {
		t.Fatalf("failed to clear streams: %v", err)
	}
	w := &fixtureWriter{t: t, root: root}

	genesisKey := fixtureKey(0x01)
	rotatedKey := fixtureKey(0x02)
	genesisPub := journal.FormatPublicKey(genesisKey.Public().(ed25519.PublicKey))
	rotatedPub := journal.FormatPublicKey(rotatedKey.Public().(ed25519.PublicKey))

	// --- Ruling 1: the signing identity is born with the journal and rotates inside it.
	w.writeJSON("streams/_meta/tx/00000000000000000000.json", metaRecord{
		Version:   journal.VersionPrefix,
		Stream:    journal.MetaStreamID,
		Seq:       0,
		Type:      journal.RecordTypeGenesis,
		PublicKey: genesisPub,
		Timestamp: "2026-08-31T00:00:00Z",
	})
	w.writeJSON("streams/_meta/tx/00000000000000000001.json", metaRecord{
		Version:   journal.VersionPrefix,
		Stream:    journal.MetaStreamID,
		Seq:       1,
		Type:      "token_create",
		TokenID:   "tok_admin_01",
		Scope:     "rwc:*",
		Timestamp: "2026-08-31T00:01:00Z",
	})

	rotation := &journal.KeyRotationRecord{
		Version:      journal.VersionPrefix,
		Stream:       journal.MetaStreamID,
		Seq:          2,
		Type:         journal.RecordTypeKeyRotation,
		OldPublicKey: genesisPub,
		NewPublicKey: rotatedPub,
		Timestamp:    "2026-08-31T00:06:00Z",
	}
	if err := journal.SignRotation(genesisKey, rotation); err != nil {
		t.Fatalf("failed to sign key rotation: %v", err)
	}
	w.writeJSON("streams/_meta/tx/00000000000000000002.json", rotation)

	w.writeJSON("streams/_meta/tx/00000000000000000003.json", metaRecord{
		Version:   journal.VersionPrefix,
		Stream:    journal.MetaStreamID,
		Seq:       3,
		Type:      "token_revoke",
		TokenID:   "tok_admin_01",
		Timestamp: "2026-08-31T00:08:00Z",
	})

	// --- Rulings 3 and 4: real commits, real packfiles, real ref transitions.
	repo := newGitRepo(t)
	c1 := repo.commit("", "README.md", "walden fixture repository\n", "first commit")
	c2 := repo.commit(c1, "README.md", "walden fixture repository\nsecond line\n", "second commit")
	c3 := repo.commit(c1, "README.md", "walden fixture repository\nrewritten line\n", "rewritten second commit")

	segC1 := w.writeSegment(fixtureRepoStream, repo.pack(c1))
	segC2 := w.writeSegment(fixtureRepoStream, repo.pack(c2, "^"+c1))
	segC3 := w.writeSegment(fixtureRepoStream, repo.pack(c3, "^"+c1))

	// seq 0: first push into an empty repository — the ref is created from the zero OID.
	w.writeRefTx(genesisKey, &journal.RefTransactionRecord{
		Version:  journal.VersionPrefix,
		Stream:   fixtureRepoStream,
		Seq:      0,
		Type:     journal.RecordTypeRefUpdate,
		Segments: []string{segC1},
		Updates: []journal.RefUpdate{
			{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: c1},
		},
		Timestamp: "2026-08-31T00:02:00Z",
	})

	// seq 1: fast-forward main and create a second branch in one atomic transaction.
	w.writeRefTx(genesisKey, &journal.RefTransactionRecord{
		Version:  journal.VersionPrefix,
		Stream:   fixtureRepoStream,
		Seq:      1,
		Type:     journal.RecordTypeRefUpdate,
		Segments: []string{segC2},
		Updates: []journal.RefUpdate{
			{Ref: "refs/heads/main", OldOID: c1, NewOID: c2},
			{Ref: "refs/heads/feature", OldOID: journal.ZeroOID40, NewOID: c2},
		},
		Timestamp: "2026-08-31T00:03:00Z",
	})

	// seq 2: branch delete — no new objects, so the segments array is empty.
	w.writeRefTx(genesisKey, &journal.RefTransactionRecord{
		Version:  journal.VersionPrefix,
		Stream:   fixtureRepoStream,
		Seq:      2,
		Type:     journal.RecordTypeRefUpdate,
		Segments: []string{},
		Updates: []journal.RefUpdate{
			{Ref: "refs/heads/feature", OldOID: c2, NewOID: journal.ZeroOID40},
		},
		Timestamp: "2026-08-31T00:04:00Z",
	})

	// seq 3: force update — main moves to a commit that is not a descendant of its old
	// tip, and the record is signed by the rotated key that _meta seq 2 activated.
	w.writeRefTx(rotatedKey, &journal.RefTransactionRecord{
		Version:  journal.VersionPrefix,
		Stream:   fixtureRepoStream,
		Seq:      3,
		Type:     journal.RecordTypeRefUpdate,
		Segments: []string{segC3},
		Updates: []journal.RefUpdate{
			{Ref: "refs/heads/main", OldOID: c2, NewOID: c3},
		},
		Timestamp: "2026-08-31T00:07:00Z",
	})

	// --- Compaction: a snapshot consolidating everything through seq 1, published
	// before the marker that points at it. The segments and transactions it supersedes
	// stay in the fixture tree on purpose; readers must ignore them, not reject them.
	snapshot := repo.pack(c2)
	snapshotHash := journal.ComputeSegmentHash(snapshot)
	if err := journal.ValidateSnapshot(snapshot, snapshotHash); err != nil {
		t.Fatalf("generated snapshot is not a valid packfile: %v", err)
	}
	w.write(fmt.Sprintf("streams/%s/snapshots/%s.pack", fixtureRepoStream, snapshotHash), snapshot)

	marker := &journal.Marker{
		Version:   journal.VersionPrefix,
		Stream:    fixtureRepoStream,
		Sequence:  1,
		Snapshot:  snapshotHash,
		Timestamp: "2026-08-31T01:00:00Z",
	}
	markerBytes, err := journal.MarshalMarker(marker)
	if err != nil {
		t.Fatalf("failed to marshal marker: %v", err)
	}
	w.write(fmt.Sprintf("streams/%s/marker.json", fixtureRepoStream), markerBytes)

	// --- Ruling 2: a second repository stream under an opaque identifier, with its own
	// sequence counter starting at zero and no marker of its own.
	opaqueRepo := newGitRepo(t)
	o1 := opaqueRepo.commit("", "main.go", "package main\n", "initial import")
	segO1 := w.writeSegment(fixtureOpaqueStream, opaqueRepo.pack(o1))
	w.writeRefTx(genesisKey, &journal.RefTransactionRecord{
		Version:  journal.VersionPrefix,
		Stream:   fixtureOpaqueStream,
		Seq:      0,
		Type:     journal.RecordTypeRefUpdate,
		Segments: []string{segO1},
		Updates: []journal.RefUpdate{
			{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: o1},
			{Ref: "refs/tags/v1.0", OldOID: journal.ZeroOID40, NewOID: o1},
		},
		Timestamp: "2026-08-31T00:05:00Z",
	})

	// --- Ruling 5: the conditional-append target keys and the exact refusal wording.
	w.writeJSON("conditional_append.json", buildConditionalAppendFixture())
}

// conditionalAppendFixture pins the CAS precondition, the deterministic tx key
// derivation, and the single-line refusals of spec/journal/v1/README.md section 11.
type conditionalAppendFixture struct {
	Version        string                    `json:"version"`
	Description    string                    `json:"description"`
	ConditionalPut conditionalPutFixture     `json:"conditional_put"`
	TxKeys         []txKeyFixture            `json:"tx_keys"`
	Refusals       []fencingRefusableFixture `json:"refusals"`
}

type conditionalPutFixture struct {
	Header         string `json:"header"`
	Value          string `json:"value"`
	ConflictStatus int    `json:"conflict_status"`
	ConflictCode   string `json:"conflict_code"`
}

type txKeyFixture struct {
	Stream      journal.StreamID `json:"stream"`
	Seq         uint64           `json:"seq"`
	Key         string           `json:"key"`
	Description string           `json:"description"`
}

type fencingRefusableFixture struct {
	Case    string           `json:"case"`
	Stream  journal.StreamID `json:"stream,omitempty"`
	Seq     *uint64          `json:"seq,omitempty"`
	Message string           `json:"message"`
}

func buildConditionalAppendFixture() conditionalAppendFixture {
	seq3 := uint64(3)
	seq7 := uint64(7)
	return conditionalAppendFixture{
		Version:     journal.VersionPrefix,
		Description: "Conditional append targets and fencing refusals for journal format v1 (spec README section 11)",
		ConditionalPut: conditionalPutFixture{
			Header:         journal.HeaderIfNoneMatch,
			Value:          journal.IfNoneMatchWildcard,
			ConflictStatus: journal.StatusPreconditionFailed,
			ConflictCode:   "PreconditionFailed",
		},
		TxKeys: []txKeyFixture{
			{Stream: journal.MetaStreamID, Seq: 0, Key: journal.TxKey(journal.MetaStreamID, 0), Description: "Genesis record on the meta stream"},
			{Stream: journal.MetaStreamID, Seq: 3, Key: journal.TxKey(journal.MetaStreamID, 3), Description: "Meta stream counter runs independently of any repository stream"},
			{Stream: fixtureRepoStream, Seq: 0, Key: journal.TxKey(fixtureRepoStream, 0), Description: "First push into an empty repository"},
			{Stream: fixtureRepoStream, Seq: 3, Key: journal.TxKey(fixtureRepoStream, 3), Description: "Force update on a human-chosen stream identifier"},
			{Stream: fixtureOpaqueStream, Seq: 0, Key: journal.TxKey(fixtureOpaqueStream, 0), Description: "Opaque stream identifier restarts its own counter at zero"},
			{Stream: fixtureRepoStream, Seq: 42, Key: journal.TxKey(fixtureRepoStream, 42), Description: "Zero padding to twenty digits keeps lexicographic order numeric"},
			{Stream: fixtureRepoStream, Seq: ^uint64(0), Key: journal.TxKey(fixtureRepoStream, ^uint64(0)), Description: "Maximum unsigned 64-bit sequence still fits twenty digits"},
		},
		Refusals: []fencingRefusableFixture{
			{Case: "fenced_by_conflict_repo_stream", Stream: fixtureRepoStream, Seq: &seq3, Message: journal.RefuseStreamFenced(fixtureRepoStream, seq3).Error()},
			{Case: "permanently_fenced_repo_stream", Stream: fixtureRepoStream, Message: journal.RefusePermanentlyFenced(fixtureRepoStream).Error()},
			{Case: "fenced_by_conflict_meta_stream", Stream: journal.MetaStreamID, Seq: &seq7, Message: journal.RefuseStreamFenced(journal.MetaStreamID, seq7).Error()},
			{Case: "permanently_fenced_meta_stream", Stream: journal.MetaStreamID, Message: journal.RefusePermanentlyFenced(journal.MetaStreamID).Error()},
			{Case: "storage_provider_lacks_cas", Message: journal.RefuseCASNotSupported().Error()},
		},
	}
}
