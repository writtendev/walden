package journal_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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
// then commit the result — and if the pack digests moved, update the spec's examples
// too; see TestRegenerateFixtures. Signing keys, timestamps, and git object dates are
// all fixed, so the records reproduce byte for byte. Packfile bytes are produced by the
// local git binary; the committed packs came from git 2.50.1 — not the git 2.47.2 the
// container image pins, which these packs have nothing to do with — and a different git
// version may pack the same objects differently, which changes the content-addressed
// segment names but not their correctness.
//
// Objects are written at the object storage keys of spec section 9.2, rooted at
// fixtures/, so the fixture tree is bucket contents rather than a rearrangement.

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

// gitEnv is the environment every git subprocess here runs in: the caller's, with the whole
// GIT_* namespace stripped out and the handful this generator actually depends on put back.
//
// The scratch repositories are the unit of isolation. Each one must hold exactly the objects
// that were put into it, out of exactly the configuration set below, or the fixture bytes
// stop being a function of the fixture definition. An inherited GIT_OBJECT_DIRECTORY or
// GIT_ALTERNATE_OBJECT_DIRECTORIES collapses every scratch repository into one object
// database, so every pack inventory becomes the union of all of them and the gate fails on
// fixtures that are perfectly correct; GIT_DIR and GIT_WORK_TREE point git at somebody else's
// repository outright; GIT_CONFIG_COUNT smuggles in settings that GIT_CONFIG_GLOBAL does not
// cover. Stripping the namespace is one rule rather than a denylist that is always one
// variable short — and setting these to the empty string is not the same thing, because git
// reads an empty GIT_WORK_TREE as set and refuses to run at all.
//
// GIT_EXEC_PATH is the exception: it names the git installation rather than a repository, an
// object database or a preference, so a relocated install keeps working.
func gitEnv() []string {
	inherited := os.Environ()
	env := make([]string, 0, len(inherited)+6)
	for _, kv := range inherited {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "GIT_") && name != "GIT_EXEC_PATH" {
			continue
		}
		env = append(env, kv)
	}
	return append(env,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=walden fixtures",
		"GIT_AUTHOR_EMAIL=fixtures@walden.invalid",
		"GIT_COMMITTER_NAME=walden fixtures",
		"GIT_COMMITTER_EMAIL=fixtures@walden.invalid",
		"GIT_AUTHOR_DATE="+fixtureGitDate,
		"GIT_COMMITTER_DATE="+fixtureGitDate,
	)
}

// gitRepo is a throwaway bare repository. The generator mints real commits and real
// packfiles in one; the fixture tests replay the golden journal back into another.
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

// tryRun runs git and returns its stdout, or an error carrying stderr. Callers that ask
// git a question whose answer may legitimately be "no" — does this object exist, is this
// commit an ancestor of that one — use this rather than run.
func (r *gitRepo) tryRun(stdin []byte, args ...string) ([]byte, error) {
	r.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = r.dir
	cmd.Env = gitEnv()
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func (r *gitRepo) run(stdin []byte, args ...string) []byte {
	r.t.Helper()
	out, err := r.tryRun(stdin, args...)
	if err != nil {
		r.t.Fatalf("%v", err)
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

// packInventory is a packfile's git-version-independent identity: every object it carries,
// as "<oid> <type>", sorted. Two packs with the same inventory hold the same objects, however
// differently the git that wrote them chose to encode and delta them.
//
// The pack is admitted by `git index-pack`, not by `git unpack-objects`, and the difference
// is the whole point. unpack-objects forgives anything it can still read objects out of:
// fourteen bytes of junk appended after the trailer, for one, which it silently copies to
// its stdout and exits 0 on. Carried through resolvePack, that laundered a file that is not
// a clean packfile into the fixture tree with a self-consistent digest, filename and
// signature over it, and the whole suite stayed green. index-pack reads the pack as a whole
// object rather than as a source of objects, so it refuses that ("fatal: pack has junk at
// the end") and a truncated one with it, and the inventory this reports is therefore the
// inventory of a packfile git considers well-formed end to end.
//
// The pack is handed over as a file rather than on stdin, and that is not incidental: read
// from a pipe, git stops at the trailer and never learns that anything followed it, so the
// junk check does not run and the corrupt pack is accepted. Given a file it knows where the
// pack ends. Written under objects/pack, indexing it in place also puts its objects in the
// object database, which is what cat-file below reads.
//
// Not `--strict`: that additionally requires every link out of the pack to resolve, and a
// journal segment is incremental by construction — repo-alpha's second push carries a commit
// whose parent is in the first push's segment and nowhere in this scratch repository, so
// --strict rejects two of the five committed packs ("did not receive expected object"). The
// connectivity question --strict asks of one pack in isolation is the wrong question; it is
// asked correctly, of the whole replayed object database, by TestFixtureReplay's git fsck.
func packInventory(t *testing.T, pack []byte) string {
	t.Helper()
	r := newGitRepo(t)
	const inPlace = "objects/pack/pack-fixture.pack"
	path := filepath.Join(r.dir, filepath.FromSlash(inPlace))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("failed to create %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, pack, 0o644); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
	if _, err := r.tryRun(nil, "index-pack", inPlace); err != nil {
		t.Fatalf("not a packfile git accepts whole: %v", err)
	}
	out := r.run(nil, "cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype)")
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// fixtureWriter accumulates the object tree that will be written under fixtures/.
//
// Every journal object is written at the object storage key spec section 9.2 derives
// for it, rooted at fixtures/: the fixture tree is bucket contents, not a rearrangement
// of them, so key "v1/streams/repo-alpha/marker.json" lands at that path on disk.
//
// A writer with an empty against generates the tree from scratch, which is what
// TestRegenerateFixtures wants. A writer with against set generates the tree the committed
// fixtures under against are asserted to equal, which is what TestFixturesAreGenerated
// wants; the difference between the two is confined to resolvePack, and explained there.
type fixtureWriter struct {
	t       *testing.T
	root    string
	against string
	claimed map[string]bool
}

func newFixtureWriter(t *testing.T, root, against string) *fixtureWriter {
	return &fixtureWriter{t: t, root: root, against: against, claimed: make(map[string]bool)}
}

func (w *fixtureWriter) write(key string, data []byte) {
	w.t.Helper()
	path := filepath.Join(w.root, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		w.t.Fatalf("failed to create %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		w.t.Fatalf("failed to write %s: %v", path, err)
	}
}

// writeJSON writes an indented JSON document with a trailing newline.
func (w *fixtureWriter) writeJSON(key string, v any) {
	w.t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		w.t.Fatalf("failed to marshal %s: %v", key, err)
	}
	w.write(key, append(data, '\n'))
}

// resolvePack settles which bytes a packfile is stored as, and which digest names it.
//
// Generating, that is simply what the local git just produced, hashed. Asserting against a
// committed tree, it is the committed packfile under the same key prefix carrying exactly
// the objects this one carries — and the reason is that packfile bytes are not reproducible
// across git versions. Object encoding, delta selection and compression are all a matter of
// the packer's judgment, so the same commits packed by two gits give two byte streams, two
// SHA-256 digests, two filenames, and — since transaction records and marker.json name their
// packs by digest — two sets of JSON records. Regenerating the whole tree and comparing all
// of it would therefore fail on any machine whose git is not the 2.50.1 the committed packs
// came from, and a gate that fails for reasons unrelated to the change under review is a
// gate people learn to switch off.
//
// So the packs are pinned by an equality that does hold across versions — same objects, same
// types, nothing more and nothing less — and their bytes are then carried over from the
// committed tree, so that everything derived from them, the digests and every record naming
// one, is still compared byte for byte. What this deliberately cannot see is a repack: bytes
// that change while the object set does not, with the new digest threaded through the
// records. That is the exact shape of a legitimate git upgrade, and this test cannot tell
// the two apart. (git changing its default object format from SHA-1 would change the object
// IDs, not just the packing, and would fail here — correctly, since the whole tree would
// then need regenerating.)
//
// The equality is what a packfile git accepts holds, not what its bytes are, so it is only
// as strong as that acceptance: see packInventory, where the pack has to survive index-pack
// rather than merely yield objects to unpack-objects. A repack does not escape the suite
// entirely — TestSpecExamplesMatchFixtures notices, because two of the spec's examples quote
// pack digests — but that is a property of those examples rather than of this matching, and
// it is written down in both places rather than relied on quietly.
func (w *fixtureWriter) resolvePack(prefix string, pack []byte) (string, []byte) {
	w.t.Helper()
	if w.against == "" {
		return journal.ComputeSegmentHash(pack), pack
	}

	dir := filepath.Join(w.against, filepath.FromSlash(prefix))
	entries, err := os.ReadDir(dir)
	if err != nil {
		w.t.Fatalf("failed to read %s: %v", dir, err)
	}
	want := packInventory(w.t, pack)

	// Every candidate is considered before one is bound, rather than the first match being
	// taken. Two packs under one prefix can hold the same objects, and if one is named by
	// its own digest and the other is not, it is the self-consistent one that belongs to
	// this record. Binding whichever sorted first instead made a decoy named
	// 0000…0.pack abort the whole test on a hash mismatch in writeSegment, before the file
	// set walk ran — so the run said a segment was invalid and never named the stray file.
	// Choosing the self-named candidate leaves that walk to do its job and report it.
	var name string
	var data []byte
	for _, entry := range entries {
		// Anything that is not a packfile is not a candidate. It is also a stray, which
		// the file set assertion in TestFixturesAreGenerated reports far more clearly
		// than a failure to index it here would.
		if !strings.HasSuffix(entry.Name(), ".pack") || w.claimed[prefix+entry.Name()] {
			continue
		}
		candidate, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			w.t.Fatalf("failed to read %s/%s: %v", dir, entry.Name(), err)
		}
		if packInventory(w.t, candidate) != want {
			continue
		}
		selfNamed := entry.Name() == journal.ComputeSegmentHash(candidate)+".pack"
		if name == "" || selfNamed {
			name, data = entry.Name(), candidate
		}
		if selfNamed {
			break
		}
	}
	if name == "" {
		w.t.Fatalf("no unclaimed packfile under %s holds exactly the objects the generator packed:\n%s", prefix, want)
		return "", nil
	}
	w.claimed[prefix+name] = true
	return strings.TrimSuffix(name, ".pack"), data
}

// writeSegment writes a pack segment under its own SHA-256 and returns that hash.
//
// Generating, the hash is this pack's, so the check can only fail on a packfile git wrote and
// git will not read back. Asserting, the hash is a committed filename and the bytes are that
// file's, so it fails on exactly one thing: a committed pack whose name lies about its own
// digest.
//
// That is reported and the run continues, rather than aborting the test. A Fatalf here costs
// the caller the file-set walk in TestFixturesAreGenerated — the same pathology resolvePack
// avoids by preferring a self-named candidate: a run that says a segment is invalid and never
// names the stray file sitting beside it. For a name that is well formed and lying — 64 hex
// characters that are not this pack's digest — nothing after this call can be hurt by it: the
// pack goes into a temp tree under the name it already has, and that name travels into the
// records, where the byte comparison sees it. It may therefore add one derived record diff
// below the real failure, which is a fair price for the operator learning both facts in one
// run.
//
// A name that is not 64 hex characters at all is the sub-case this does not rescue, and the
// comment used to claim it did. That name travels into the record too, where ValidateHash
// rejects it — writeRefTx, SignRefTx, (*RefTransactionRecord).Validate — and writeRefTx does
// Fatalf, so the file-set walk never runs and a stray file beside the pack still goes unnamed.
// The refusal names the file exactly, and TestFixtureSegmentsAreContentAddressed asks the same
// question of the committed tree and reports the same file in the same run, so the fact
// survives; only this test's second half is lost.
func (w *fixtureWriter) writeSegment(stream journal.StreamID, pack []byte) string {
	w.t.Helper()
	hash, data := w.resolvePack(journal.SegmentPrefix(stream), pack)
	if err := journal.ValidateSegment(data, hash); err != nil {
		w.t.Errorf("segment for stream %s is not a valid packfile: %v", stream, err)
	}
	w.write(journal.SegmentKey(stream, hash), data)
	return hash
}

// writeSnapshot writes a consolidated snapshot pack under its own SHA-256 and returns that
// hash. Non-fatal for the reason given on writeSegment.
func (w *fixtureWriter) writeSnapshot(stream journal.StreamID, pack []byte) string {
	w.t.Helper()
	hash, data := w.resolvePack(journal.SnapshotPrefix(stream), pack)
	if err := journal.ValidateSnapshot(data, hash); err != nil {
		w.t.Errorf("snapshot for stream %s is not a valid packfile: %v", stream, err)
	}
	w.write(journal.SnapshotKey(stream, hash), data)
	return hash
}

// writeRefTx signs and writes a ref transaction record, returning nothing but failing on error.
func (w *fixtureWriter) writeRefTx(priv ed25519.PrivateKey, rec *journal.RefTransactionRecord) {
	w.t.Helper()
	if err := journal.SignRefTx(priv, rec); err != nil {
		w.t.Fatalf("failed to sign %s seq %d: %v", rec.Stream, rec.Seq, err)
	}
	w.writeJSON(journal.TxKey(rec.Stream, rec.Seq), rec)
}

// fixtureTokenHash is the storage hash of a raw built-in token, "sha256:<64-hex>", as
// spec/auth/v1 section 5.1 defines it. It is computed here from the raw token rather than
// copied in, so the hashes in the golden journal are real digests of real tokens for the
// same reason every other hash in the tree is.
//
// The raw tokens the two token_create records below are minted from are read out of
// spec/auth/v1/fixtures/builtin_tokens.json rather than typed here, so the two published
// fixture sets describe one instance rather than two unrelated ones, and the hash in the
// journal is the hash the token store would look up.
func fixtureTokenHash(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return journal.TokenHashPrefix + hex.EncodeToString(sum[:])
}

// writeToken validates and writes a token table mutation on the meta stream. Token records
// carry no signature, so their own Validate is the only gate between the generator and the
// fixture tree — which is why it is called here rather than left to the reading tests.
func (w *fixtureWriter) writeToken(seq journal.Seq, rec interface{ Validate() error }) {
	w.t.Helper()
	if err := rec.Validate(); err != nil {
		w.t.Fatalf("failed to validate _meta seq %d: %v", seq, err)
	}
	w.writeJSON(journal.TxKey(journal.MetaStreamID, seq), rec)
}

// TestRegenerateFixtures rewrites spec/journal/v1/fixtures from the generator.
//
// Regenerating is two obligations, not one. This test writes the fixture tree; if the pack
// bytes move — a different git packs the same objects differently — the digests move with
// them, and the spec's own examples quote two of those digests, so
// spec/journal/v1/README.md has to be updated by hand afterwards or
// TestSpecExamplesMatchFixtures stays red. That is deliberate: the examples are prose the
// author is answerable for, not output, and a regenerator that rewrote them would erase the
// one signal that says a repack happened. The obligation is stated at the regeneration
// instructions in fixtures/README.md and again in that test's failure message.
func TestRegenerateFixtures(t *testing.T) {
	if os.Getenv("WALDEN_REGENERATE_FIXTURES") == "" {
		t.Skip("set WALDEN_REGENERATE_FIXTURES=1 to rewrite spec/journal/v1/fixtures")
	}

	// Everything the generator owns goes, so that a file it no longer writes cannot survive
	// as a stray the gate then fails on until somebody deletes it by hand. That is the whole
	// tree except the one hand-written file, which is prose about the fixtures rather than
	// part of them.
	root := journalFixturesDir()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("failed to read the fixture tree: %v", err)
	}
	for _, entry := range entries {
		if entry.Name() == fixtureHandWritten {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
			t.Fatalf("failed to clear the fixture tree: %v", err)
		}
	}
	generateFixtures(newFixtureWriter(t, root, ""))
}

// generateFixtures emits the whole golden journal through w. It is the single definition of
// what the fixture tree holds: TestRegenerateFixtures runs it to write the tree, and
// TestFixturesAreGenerated runs it to assert that the committed tree is still what it writes.
func generateFixtures(w *fixtureWriter) {
	t := w.t
	t.Helper()

	genesisKey := fixtureKey(0x01)
	rotatedKey := fixtureKey(0x02)
	genesisPub := journal.FormatPublicKey(genesisKey.Public().(ed25519.PublicKey))
	rotatedPub := journal.FormatPublicKey(rotatedKey.Public().(ed25519.PublicKey))

	// --- Ruling 1: the signing identity is born with the journal and rotates inside it.
	// Written through journal.GenesisRecord, the published type, so that an encoder change
	// to it moves these bytes rather than passing unseen.
	w.writeJSON(journal.TxKey(journal.MetaStreamID, 0), &journal.GenesisRecord{
		Version:   journal.VersionPrefix,
		Stream:    journal.MetaStreamID,
		Seq:       0,
		Type:      journal.RecordTypeGenesis,
		PublicKey: genesisPub,
		Timestamp: "2026-08-31T00:00:00Z",
	})
	// The token table lives on the meta stream too: an admin token minted at seq 1, revoked
	// at seq 3, and the narrower token that replaces it at seq 4. Written through the
	// published types, like every other record here, so that an encoder change moves these
	// bytes rather than passing unseen. The two tokens are the ones spec/auth/v1 publishes
	// under these identifiers, read from that file so that the journal cannot come to
	// describe a different instance from the one the auth fixtures describe.
	adminToken := loadFixtureBuiltinToken(t, fixtureAdminTokenID)
	writerToken := loadFixtureBuiltinToken(t, fixtureWriterTokenID)

	w.writeToken(1, &journal.TokenCreateRecord{
		Version:   journal.VersionPrefix,
		Stream:    journal.MetaStreamID,
		Seq:       1,
		Type:      journal.RecordTypeTokenCreate,
		TokenID:   fixtureAdminTokenID,
		TokenHash: fixtureTokenHash(adminToken.RawToken),
		Scopes:    []string{"rwc:*"},
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
	w.writeJSON(journal.TxKey(journal.MetaStreamID, rotation.Seq), rotation)

	w.writeToken(3, &journal.TokenRevokeRecord{
		Version:   journal.VersionPrefix,
		Stream:    journal.MetaStreamID,
		Seq:       3,
		Type:      journal.RecordTypeTokenRevoke,
		TokenID:   fixtureAdminTokenID,
		TokenHash: fixtureTokenHash(adminToken.RawToken),
		Timestamp: "2026-08-31T00:08:00Z",
	})

	// A token carrying more than one scope, which is the case a single scope field cannot
	// hold: spec/auth/v1 section 3.4 opens "a token may carry one or more scopes", and this
	// is that sentence as bytes on the meta stream.
	w.writeToken(4, &journal.TokenCreateRecord{
		Version:   journal.VersionPrefix,
		Stream:    journal.MetaStreamID,
		Seq:       4,
		Type:      journal.RecordTypeTokenCreate,
		TokenID:   fixtureWriterTokenID,
		TokenHash: fixtureTokenHash(writerToken.RawToken),
		Scopes:    []string{"rw:blog-*", "r:docs"},
		Timestamp: "2026-08-31T00:09:00Z",
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
	snapshotHash := w.writeSnapshot(fixtureRepoStream, repo.pack(c2))

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
	w.write(journal.MarkerKey(fixtureRepoStream), markerBytes)

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

// txKeyFixture is one row of the append-target table: a stream, a sequence, and the key
// the two derive. The sequence is carried as a decimal string. This table exists to pin
// key derivation across the whole 64-bit range, and a JSON number cannot do that: a parser
// that reads numbers as IEEE doubles — JavaScript's, and every parser built on it — turns
// 18446744073709551615 into 18446744073709552000 and derives a key that does not match the
// one beside it, failing a conformant reader against a correct fixture. A string is read
// exactly by every conformant parser. Journal records encode their own `seq` the same way
// and for the same reason, so no sequence anywhere in the fixture tree is a JSON number.
//
// The row is held as a string rather than a journal.Seq so that the check on the other
// side — in TestFixtureConditionalAppend — reads the bytes the fixture carries and parses
// them itself, rather than through the decoder this change is here to pin.
type txKeyFixture struct {
	Stream      journal.StreamID `json:"stream"`
	Seq         string           `json:"seq"`
	Key         string           `json:"key"`
	Description string           `json:"description"`
}

// txKeyRow builds one append-target row from the sequence a writer would hold in hand.
func txKeyRow(stream journal.StreamID, seq journal.Seq, description string) txKeyFixture {
	return txKeyFixture{
		Stream:      stream,
		Seq:         seq.String(),
		Key:         journal.TxKey(stream, seq),
		Description: description,
	}
}

type fencingRefusableFixture struct {
	Case    string           `json:"case"`
	Stream  journal.StreamID `json:"stream,omitempty"`
	Seq     *journal.Seq     `json:"seq,omitempty"`
	Message string           `json:"message"`
}

func buildConditionalAppendFixture() conditionalAppendFixture {
	seq3 := journal.Seq(3)
	seq7 := journal.Seq(7)
	return conditionalAppendFixture{
		Version:     journal.VersionPrefix,
		Description: "Conditional append targets and fencing refusals for journal format v1 (spec README section 11)",
		ConditionalPut: conditionalPutFixture{
			Header:         journal.HeaderIfNoneMatch,
			Value:          journal.IfNoneMatchWildcard,
			ConflictStatus: journal.StatusPreconditionFailed,
			ConflictCode:   journal.CodePreconditionFailed,
		},
		TxKeys: []txKeyFixture{
			txKeyRow(journal.MetaStreamID, 0, "Genesis record on the meta stream"),
			txKeyRow(journal.MetaStreamID, 3, "Meta stream counter runs independently of any repository stream"),
			txKeyRow(fixtureRepoStream, 0, "First push into an empty repository"),
			txKeyRow(fixtureRepoStream, 3, "Force update on a human-chosen stream identifier"),
			txKeyRow(fixtureOpaqueStream, 0, "Opaque stream identifier restarts its own counter at zero"),
			txKeyRow(fixtureRepoStream, fixtureSeq42, "Zero padding to twenty digits keeps lexicographic order numeric"),
			txKeyRow(fixtureRepoStream, fixtureSeqMax, "Maximum unsigned 64-bit sequence still fits twenty digits, and is carried here as a string so that a parser reading JSON numbers as doubles derives this key rather than a rounded one"),
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
