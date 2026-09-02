package journal_test

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/journal"
)

// journalSpecDir returns the published journal format specification, spec/journal/v1.
func journalSpecDir() string {
	return filepath.Join("..", "..", "spec", "journal", "v1")
}

// journalFixturesDir returns the published golden journal under spec/journal/v1/fixtures.
func journalFixturesDir() string {
	return filepath.Join(journalSpecDir(), "fixtures")
}

// fixtureKeyPath maps an object storage key to the file that holds it. The fixture tree
// is bucket contents, so key "v1/streams/repo-alpha/marker.json" is that path under
// fixtures/ — which is why these tests address the golden journal through the same key
// derivation functions a reimplementation would use, and never through hand-built paths.
func fixtureKeyPath(key string) string {
	return filepath.Join(journalFixturesDir(), filepath.FromSlash(key))
}

// The golden journal is laid out as a real bucket would be, and these tests read it as
// a reader of the specification would, between them covering the whole replay path:
//
//	TestFixturesAreGenerated       regenerates the tree and asserts the committed one
//	                               against it, file set and bytes both
//	TestFixtureMetaStream          replays _meta from genesis and chains the rotation
//	TestFixtureRepoStreams         verifies every ref transaction's signature
//	TestFixtureReplay              resolves the packs: unpacks every referenced segment
//	                               into a scratch repository, reconstructs ref state,
//	                               and walks the section 7.5 marker path
//	TestFixtureConditionalAppend   pins the section 11 append targets and refusals
//	TestFixtureTokenTableReplay    rebuilds the token table from the meta stream alone, as
//	                               a restore onto an empty disk has to
//	TestFixtureSequencesSurviveDoubleParsers
//	                               reads every sequence in the tree the way a parser whose
//	                               numbers are doubles reads it, per section 1.1
//	TestSpecExamplesMatchFixtures  holds the spec's JSON examples to the fixtures they
//	                               claim to quote
//
// Timeline of the fixture journal:
//
//	_meta      seq 0  genesis, public key K0
//	_meta      seq 1  token_create tok_admin_01, one scope
//	repo-alpha seq 0  first push into an empty repository        signed K0
//	repo-alpha seq 1  fast-forward main, create feature          signed K0
//	repo-alpha seq 2  delete feature, no segments                signed K0
//	<opaque>   seq 0  first push on an opaque stream identifier  signed K0
//	_meta      seq 2  key_rotation K0 -> K1, signed by K0
//	repo-alpha seq 3  force update of main                       signed K1
//	_meta      seq 3  token_revoke tok_admin_01
//	_meta      seq 4  token_create tok_writer_02, two scopes
const (
	fixtureRepoStream   = "repo-alpha"
	fixtureOpaqueStream = "9f2c1d7a-4e6b-4a10-8c3f-2b5d81e0a7c4"

	// fixtureMetaHeadSeq is the last sequence on the meta stream of the golden journal.
	fixtureMetaHeadSeq = journal.Seq(4)

	// fixtureAdminToken and fixtureWriterToken are the raw built-in tokens the journal's two
	// token_create records mint, and the tokens spec/auth/v1/fixtures/builtin_tokens.json
	// publishes under tok_admin_01 and tok_writer_02. They are raw tokens in a published
	// fixture rather than secrets: a walden that ever hashes to one of these has been handed
	// the fixture on purpose.
	fixtureAdminToken  = "walden_sec_admin_0123456789abcdef"
	fixtureWriterToken = "walden_sec_writer_0123456789abcdef"

	// fixtureSeq42 and fixtureSeqMax are the two sequences the conditional-append table
	// pins beyond the journal's own coordinates: a small one that shows the zero padding
	// doing its work, and the largest a 64-bit counter can reach.
	fixtureSeq42  = journal.Seq(42)
	fixtureSeqMax = journal.Seq(^uint64(0))
)

// loadFixtureChain replays the _meta stream up to and including maxSeq and returns the chain.
func loadFixtureChain(t *testing.T, maxSeq journal.Seq) *journal.SigningChain {
	t.Helper()
	chain := journal.NewSigningChain()

	for seq := journal.Seq(0); seq <= maxSeq; seq++ {
		path := fixtureKeyPath(journal.TxKey(journal.MetaStreamID, seq))
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read meta fixture %s: %v", path, err)
		}
		var header struct {
			Version string           `json:"version"`
			Stream  journal.StreamID `json:"stream"`
			Seq     journal.Seq      `json:"seq"`
			Type    string           `json:"type"`
		}
		if err := json.Unmarshal(data, &header); err != nil {
			t.Fatalf("failed to parse meta fixture %s: %v", path, err)
		}
		if header.Version != journal.VersionPrefix {
			t.Errorf("meta fixture %s: version = %q, want %q", path, header.Version, journal.VersionPrefix)
		}
		if header.Stream != journal.MetaStreamID {
			t.Errorf("meta fixture %s: stream = %q, want %q", path, header.Stream, journal.MetaStreamID)
		}
		if header.Seq != seq {
			t.Errorf("meta fixture %s: seq = %d, want %d", path, header.Seq, seq)
		}

		switch header.Type {
		case journal.RecordTypeGenesis:
			var genesis journal.GenesisRecord
			if err := json.Unmarshal(data, &genesis); err != nil {
				t.Fatalf("failed to parse genesis fixture %s: %v", path, err)
			}
			if err := chain.ApplyGenesis(&genesis); err != nil {
				t.Fatalf("ApplyGenesis failed on %s: %v", path, err)
			}
		case journal.RecordTypeKeyRotation:
			var rotation journal.KeyRotationRecord
			if err := json.Unmarshal(data, &rotation); err != nil {
				t.Fatalf("failed to parse rotation fixture %s: %v", path, err)
			}
			if err := chain.ApplyRotation(&rotation); err != nil {
				t.Fatalf("ApplyRotation failed on %s: %v", path, err)
			}
			if chain.ActiveKey() != rotation.NewPublicKey {
				t.Errorf("%s: active key = %q, want %q", path, chain.ActiveKey(), rotation.NewPublicKey)
			}
		default:
			if err := chain.AdvanceMetaSeq(header.Seq); err != nil {
				t.Fatalf("AdvanceMetaSeq failed on %s: %v", path, err)
			}
		}
	}
	return chain
}

// TestFixtureMetaStream covers Ruling 1: the signing identity is born in the journal as
// the genesis record and rotates inside it, chained to and signed by the outgoing key.
func TestFixtureMetaStream(t *testing.T) {
	// The replays below stop at a named sequence, so a record appended past seq 3 is
	// invisible to them. It is not invisible to TestFixturesAreGenerated, which pins the
	// whole file set, so the stream's length is not asserted a second time here.
	chain := loadFixtureChain(t, 0)
	genesisKey := chain.ActiveKey()
	if genesisKey == "" {
		t.Fatal("genesis fixture did not establish an active key")
	}
	if _, err := journal.ParsePublicKey(genesisKey); err != nil {
		t.Fatalf("genesis public key is not a valid ed25519 key: %v", err)
	}

	// The rotation at seq 2 must chain to genesis and change the active key.
	rotated := loadFixtureChain(t, 3)
	if rotated.ActiveKey() == genesisKey {
		t.Error("key rotation fixture did not change the active signing key")
	}
	if rotated.LastMetaSeq() != 3 {
		t.Errorf("meta stream last seq = %d, want 3", rotated.LastMetaSeq())
	}

	// A rotation that does not chain to the active key is unusable, which is the whole
	// point of recording old_public_key.
	data, err := os.ReadFile(fixtureKeyPath(journal.TxKey(journal.MetaStreamID, 2)))
	if err != nil {
		t.Fatalf("failed to read rotation fixture: %v", err)
	}
	var rotation journal.KeyRotationRecord
	if err := json.Unmarshal(data, &rotation); err != nil {
		t.Fatalf("failed to parse rotation fixture: %v", err)
	}
	if err := journal.VerifyRotation(&rotation, rotation.NewPublicKey); err == nil {
		t.Error("expected rotation to be unchainable against the wrong active key")
	}
}

// fixtureStreamRecords reads every tx record of a stream in sequence order.
func fixtureStreamRecords(t *testing.T, stream journal.StreamID) []*journal.RefTransactionRecord {
	t.Helper()
	dir := fixtureKeyPath(journal.TxPrefix(stream))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	records := make([]*journal.RefTransactionRecord, 0, len(names))
	for i, name := range names {
		if !strings.HasSuffix(name, ".json") {
			t.Errorf("%s/%s: transaction keys must end in .json", stream, name)
			continue
		}
		seq, err := journal.ParseSeq(strings.TrimSuffix(name, ".json"))
		if err != nil {
			t.Errorf("%s/%s: transaction key is not a 20-digit sequence: %v", stream, name, err)
			continue
		}
		if seq != journal.Seq(i) {
			t.Errorf("%s/%s: sequence gap, expected %d", stream, name, i)
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("failed to read %s/%s: %v", stream, name, err)
		}
		var rec journal.RefTransactionRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			t.Fatalf("failed to parse %s/%s: %v", stream, name, err)
		}
		if rec.Seq != seq {
			t.Errorf("%s/%s: record seq = %d does not match its key", stream, name, rec.Seq)
		}
		if rec.Stream != stream {
			t.Errorf("%s/%s: record stream = %q does not match its prefix", stream, name, rec.Stream)
		}
		if err := rec.Validate(); err != nil {
			t.Errorf("%s/%s: Validate failed: %v", stream, name, err)
		}
		records = append(records, &rec)
	}
	return records
}

// checkFixtureSegments asserts that every segment a record references is present, is a
// real packfile, and is stored under the SHA-256 of its own bytes.
func checkFixtureSegments(t *testing.T, stream journal.StreamID, rec *journal.RefTransactionRecord) {
	t.Helper()
	for _, hash := range rec.Segments {
		path := fixtureKeyPath(journal.SegmentKey(stream, hash))
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s seq %d references missing segment %s: %v", stream, rec.Seq, hash, err)
			continue
		}
		if err := journal.ValidateSegment(data, hash); err != nil {
			t.Errorf("segment %s on stream %s is not a valid content-addressed packfile: %v", hash, stream, err)
		}
	}
}

// TestFixtureRepoStreams covers Ruling 3 (ref-transaction records: first push into an
// empty repository, a multi-ref update, a branch delete with no segments, and a force
// update) and Ruling 4 (content-addressed pack segments).
func TestFixtureRepoStreams(t *testing.T) {
	// repo-alpha records 0 through 2 predate the key rotation at _meta seq 2.
	preRotation := loadFixtureChain(t, 1)
	postRotation := loadFixtureChain(t, 3)

	alpha := fixtureStreamRecords(t, fixtureRepoStream)
	if len(alpha) != 4 {
		t.Fatalf("repo-alpha has %d transactions, want 4", len(alpha))
	}

	for i, rec := range alpha {
		chain := preRotation
		if i == 3 {
			chain = postRotation
		}
		if err := chain.VerifyRefTx(rec); err != nil {
			t.Errorf("repo-alpha seq %d failed signature verification: %v", rec.Seq, err)
		}
		checkFixtureSegments(t, fixtureRepoStream, rec)
	}

	// seq 0: first push into an empty repository creates the ref from the zero OID.
	if got := alpha[0].Updates[0].OldOID; got != journal.ZeroOID40 {
		t.Errorf("repo-alpha seq 0 old_oid = %q, want the zero OID", got)
	}
	if len(alpha[0].Segments) != 1 {
		t.Errorf("repo-alpha seq 0 carries %d segments, want 1", len(alpha[0].Segments))
	}

	// seq 1: one transaction moving two refs atomically.
	if len(alpha[1].Updates) != 2 {
		t.Errorf("repo-alpha seq 1 has %d updates, want 2", len(alpha[1].Updates))
	}

	// seq 2: a branch delete introduces no objects, so segments is empty.
	if len(alpha[2].Segments) != 0 {
		t.Errorf("repo-alpha seq 2 carries %d segments, want 0", len(alpha[2].Segments))
	}
	if got := alpha[2].Updates[0].NewOID; got != journal.ZeroOID40 {
		t.Errorf("repo-alpha seq 2 new_oid = %q, want the zero OID", got)
	}

	// seq 3: a force update replaces the tip with a commit that is not its descendant.
	// That the new tip is not a descendant is a claim about the commit graph, so it is
	// git that answers it, in TestFixtureReplay; here we only pin which ref moved.
	if alpha[3].Updates[0].Ref != "refs/heads/main" {
		t.Errorf("repo-alpha seq 3 updates %q, want refs/heads/main", alpha[3].Updates[0].Ref)
	}
	if alpha[3].Updates[0].OldOID != alpha[1].Updates[0].NewOID {
		t.Error("repo-alpha seq 3 does not force-update the tip left by seq 1")
	}

	// Ruling 2: an opaque stream identifier keeps its own counter, starting at zero.
	opaque := fixtureStreamRecords(t, fixtureOpaqueStream)
	if len(opaque) != 1 {
		t.Fatalf("opaque stream has %d transactions, want 1", len(opaque))
	}
	if opaque[0].Seq != 0 {
		t.Errorf("opaque stream first seq = %d, want 0", opaque[0].Seq)
	}
	if err := preRotation.VerifyRefTx(opaque[0]); err != nil {
		t.Errorf("opaque stream seq 0 failed signature verification: %v", err)
	}
	checkFixtureSegments(t, fixtureOpaqueStream, opaque[0])

	// The journal is agnostic about identifier shape: a human-chosen name and an opaque
	// identifier are both just stream IDs, and their counters do not interact.
	if err := journal.ValidateStreamID(fixtureOpaqueStream); err != nil {
		t.Errorf("opaque stream identifier rejected: %v", err)
	}
	if alpha[len(alpha)-1].Seq == opaque[len(opaque)-1].Seq {
		t.Error("expected the two repository streams to sit at different sequence numbers")
	}
}

// isZeroOID reports whether an object ID is the all-zero OID of a creation or deletion.
func isZeroOID(oid string) bool {
	return oid == journal.ZeroOID40 || oid == journal.ZeroOID64
}

// fixtureReplay is a scratch bare repository that the golden journal is replayed into.
//
// The records and the packfiles are separately well-formed — the digests are honest, the
// signatures verify, the packs parse — and none of that says the two agree. Only git can
// answer whether the object a transaction names is an object the packs it references
// actually carry, so this replays them and asks it.
type fixtureReplay struct {
	t    *testing.T
	git  *gitRepo
	refs map[string]string
}

func newFixtureReplay(t *testing.T) *fixtureReplay {
	t.Helper()
	return &fixtureReplay{t: t, git: newGitRepo(t), refs: make(map[string]string)}
}

// unpack applies one packfile from the fixture bucket to the scratch object database,
// as a reader applies a segment it has fetched and verified.
func (p *fixtureReplay) unpack(key string) {
	p.t.Helper()
	data, err := os.ReadFile(fixtureKeyPath(key))
	if err != nil {
		p.t.Fatalf("failed to read %s: %v", key, err)
	}
	if _, err := p.git.tryRun(data, "unpack-objects", "-q"); err != nil {
		p.t.Fatalf("%s is not a packfile git can unpack: %v", key, err)
	}
}

// requireCommittish asserts that the object database holds oid and that it is something
// a ref may point at. This is the assertion that catches a transaction naming an object no
// pack replayed so far has carried, and one naming an object of the wrong kind — git's
// empty tree dressed up as a commit, say. The object database is cumulative, so what it
// holds is everything the replay has unpacked up to this record, not this record's
// segments alone.
func (p *fixtureReplay) requireCommittish(rec *journal.RefTransactionRecord, ref, oid string) {
	p.t.Helper()
	out, err := p.git.tryRun(nil, "cat-file", "-t", oid)
	if err != nil {
		p.t.Errorf("%s seq %d: %s names %s, which is not in the object database at this point in the replay: %v", rec.Stream, rec.Seq, ref, oid, err)
		return
	}
	if typ := strings.TrimSpace(string(out)); typ != "commit" && typ != "tag" {
		p.t.Errorf("%s seq %d: %s names %s, which is a %s, not a commit or a tag", rec.Stream, rec.Seq, ref, oid, typ)
		return
	}
	if _, err := p.git.tryRun(nil, "rev-parse", "--verify", "--quiet", oid+"^{commit}"); err != nil {
		p.t.Errorf("%s seq %d: %s names %s, which does not resolve to a commit: %v", rec.Stream, rec.Seq, ref, oid, err)
	}
}

// apply replays one ref transaction: unpack the segments it references, resolve every
// object ID it names, then move the refs. trackRefs is false on the marker path, where
// the snapshot supplies the objects but the marker carries no ref state to check against.
func (p *fixtureReplay) apply(rec *journal.RefTransactionRecord, trackRefs bool) {
	p.t.Helper()
	for _, hash := range rec.Segments {
		p.unpack(journal.SegmentKey(rec.Stream, hash))
	}
	for _, u := range rec.Updates {
		if !isZeroOID(u.OldOID) {
			p.requireCommittish(rec, u.Ref+" old_oid", u.OldOID)
		}
		if !isZeroOID(u.NewOID) {
			p.requireCommittish(rec, u.Ref, u.NewOID)
		}
		if !trackRefs {
			continue
		}
		current, exists := p.refs[u.Ref]
		switch {
		case isZeroOID(u.OldOID) && exists:
			p.t.Errorf("%s seq %d: %s is created from the zero OID but already stands at %s", rec.Stream, rec.Seq, u.Ref, current)
		case !isZeroOID(u.OldOID) && !exists:
			p.t.Errorf("%s seq %d: %s moves from %s but does not exist yet", rec.Stream, rec.Seq, u.Ref, u.OldOID)
		case !isZeroOID(u.OldOID) && current != u.OldOID:
			p.t.Errorf("%s seq %d: %s moves from %s but stands at %s", rec.Stream, rec.Seq, u.Ref, u.OldOID, current)
		}
		if isZeroOID(u.NewOID) {
			delete(p.refs, u.Ref)
		} else {
			p.refs[u.Ref] = u.NewOID
		}
	}
}

// commitsAndTags lists every commit and tag object the replay has unpacked so far.
func (p *fixtureReplay) commitsAndTags() []string {
	p.t.Helper()
	out, err := p.git.tryRun(nil, "cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype)")
	if err != nil {
		p.t.Fatalf("failed to list the replayed object database: %v", err)
	}
	var oids []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		name, typ, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		if typ == "commit" || typ == "tag" {
			oids = append(oids, name)
		}
	}
	return oids
}

// fsck asks git whether the object database the replay assembled is sound: every object
// well-formed, and every link one of them makes resolvable.
//
// Every commit and tag in the database is named as a starting point, because git follows
// links only out of the tips it is given. A replay from the marker has no refs to give it,
// and a bare `git fsck` there walks nothing and passes an object database that is missing
// half its history. Naming the objects the database already holds asks the question
// without reconstructing ref state, which the marker does not carry.
func (p *fixtureReplay) fsck() {
	p.t.Helper()
	args := append([]string{"fsck", "--strict", "--no-progress", "--no-dangling"}, p.commitsAndTags()...)
	// fsck names the broken object on stdout, so the error alone does not say what is
	// wrong; whoever is reading this failure wants git's own words.
	out, err := p.git.tryRun(nil, args...)
	if err != nil {
		p.t.Errorf("git fsck rejects the replayed repository: %v\n%s", err, out)
	}
}

// publish writes the replayed ref state into the scratch repository and fscks it, which
// is what a materializing reader does last, before marking the repository ready.
func (p *fixtureReplay) publish() {
	p.t.Helper()
	for ref, oid := range p.refs {
		if _, err := p.git.tryRun(nil, "update-ref", ref, oid); err != nil {
			p.t.Fatalf("failed to set %s to %s: %v", ref, oid, err)
		}
	}
	p.fsck()
}

// TestFixtureReplay materializes the golden journal with the real git binary, both from
// sequence 0 and from the section 7.5 marker. Both paths assert that every object
// identifier the transactions name is present and is a commit, and both fsck the object
// database they leave behind; only the replay from sequence 0 reconstructs ref state and
// checks that the refs land where the journal says they land, because a marker carries a
// baseline sequence and a snapshot and no ref state to check against. A well-formed
// record pointing at an object its packs do not hold is exactly the defect these fixtures
// exist to rule out, and nothing short of resolving the packs can see it.
func TestFixtureReplay(t *testing.T) {
	t.Run("from_genesis", func(t *testing.T) {
		records := fixtureStreamRecords(t, fixtureRepoStream)
		alpha := newFixtureReplay(t)
		for _, rec := range records {
			alpha.apply(rec, true)
		}
		alpha.publish()

		// After the whole stream, main stands where seq 3 left it and the branch that
		// seq 2 deleted is gone.
		if got, want := alpha.refs["refs/heads/main"], records[3].Updates[0].NewOID; got != want {
			t.Errorf("replayed refs/heads/main = %q, want %q", got, want)
		}
		if len(alpha.refs) != 1 {
			t.Errorf("replayed repo-alpha holds %d refs, want only refs/heads/main: %v", len(alpha.refs), alpha.refs)
		}

		// seq 3 is a force update: its new tip is not a descendant of the tip it
		// replaces. That is a claim about the commit graph, so git answers it.
		force := records[3].Updates[0]
		if _, err := alpha.git.tryRun(nil, "merge-base", "--is-ancestor", force.OldOID, force.NewOID); err == nil {
			t.Errorf("repo-alpha seq 3 fast-forwards %s to %s; it is meant to be a force update", force.OldOID, force.NewOID)
		}
		if _, err := alpha.git.tryRun(nil, "merge-base", force.OldOID, force.NewOID); err != nil {
			t.Errorf("repo-alpha seq 3 rewrites onto unrelated history, not a shared base: %v", err)
		}

		// The opaque stream replays on its own, from its own sequence 0.
		opaque := newFixtureReplay(t)
		for _, rec := range fixtureStreamRecords(t, fixtureOpaqueStream) {
			opaque.apply(rec, true)
		}
		opaque.publish()
		if len(opaque.refs) != 2 {
			t.Errorf("replayed opaque stream holds %d refs, want a branch and a tag: %v", len(opaque.refs), opaque.refs)
		}
	})

	t.Run("from_marker", func(t *testing.T) {
		data, err := os.ReadFile(fixtureKeyPath(journal.MarkerKey(fixtureRepoStream)))
		if err != nil {
			t.Fatalf("failed to read marker fixture: %v", err)
		}
		marker, err := journal.ParseMarker(data)
		if err != nil {
			t.Fatalf("ParseMarker failed on the golden marker: %v", err)
		}

		// Section 7.5: apply the snapshot, set the baseline, resume at sequence + 1, and
		// ignore everything the snapshot supersedes rather than treating it as corruption.
		replay := newFixtureReplay(t)
		replay.unpack(journal.SnapshotKey(fixtureRepoStream, marker.Snapshot))

		resumed := 0
		for _, rec := range fixtureStreamRecords(t, fixtureRepoStream) {
			if rec.Seq <= marker.Sequence {
				continue
			}
			if want := marker.Sequence + 1 + journal.Seq(resumed); rec.Seq != want {
				t.Fatalf("replay from the marker hit sequence %d, want %d", rec.Seq, want)
			}
			resumed++
			// The marker carries a baseline sequence and a snapshot, and no ref state, so
			// this path resolves objects without a prior ref map to check them against.
			replay.apply(rec, false)
		}
		if resumed == 0 {
			t.Fatal("the marker leaves no transactions to replay, so this proves nothing")
		}
		// The marker path has no ref state to publish, but the snapshot and the segments
		// it resumed with leave an object database behind, and git answers for that one
		// the same way it answers for the replay from genesis.
		replay.fsck()
	})
}

// TestFixtureSegmentsAreContentAddressed covers Ruling 4: every pack segment and
// snapshot in the journal is stored under the SHA-256 of its own verbatim bytes.
//
// Which packs the tree holds is TestFixturesAreGenerated's business and is not re-counted
// here, and a packfile whose name lies about its own digest is caught there as well:
// resolvePack carries the committed bytes forward under the committed name, and writeSegment
// re-hashes them. What this test holds on its own is the same question asked of the committed
// tree directly — no git binary, no generator run, no dependence on the generator being right,
// so it still stands if writeSegment's re-hash is ever weakened, and it names the file and
// both digests rather than reporting a segment the generator could not resolve. It is also
// where the `^[0-9a-f]{64}\.pack$` key shape of fixtures README rules 6 and 7 is asserted as a
// rule, rather than inferred from a file set that agrees with itself.
func TestFixtureSegmentsAreContentAddressed(t *testing.T) {
	root := filepath.Join(journalFixturesDir(), journal.VersionPrefix, "streams")
	streams, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("failed to read %s: %v", root, err)
	}

	for _, stream := range streams {
		for _, kind := range []string{"segments", "snapshots"} {
			dir := filepath.Join(root, stream.Name(), kind)
			entries, err := os.ReadDir(dir)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				t.Fatalf("failed to read %s: %v", dir, err)
			}
			for _, entry := range entries {
				name := entry.Name()
				if !strings.HasSuffix(name, ".pack") {
					t.Errorf("%s/%s: pack keys must end in .pack", dir, name)
					continue
				}
				hash := strings.TrimSuffix(name, ".pack")
				if err := journal.ValidateHash(hash); err != nil {
					t.Errorf("%s/%s: key is not a 64-hex SHA-256 digest: %v", dir, name, err)
					continue
				}
				data, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Fatalf("failed to read %s/%s: %v", dir, name, err)
				}
				if computed := journal.ComputeSegmentHash(data); computed != hash {
					t.Errorf("%s/%s: content hash is %s, so the key lies about its contents", dir, name, computed)
				}
				if err := journal.ValidatePackfileHeader(data); err != nil {
					t.Errorf("%s/%s: not a real git packfile: %v", dir, name, err)
				}
			}
		}
	}
}

// TestFixtureMarkerAndSupersededHistory covers the compaction half of Ruling 4: a
// published marker whose snapshot exists, with the transactions and segments it
// supersedes retained in storage and ignored rather than treated as corruption.
func TestFixtureMarkerAndSupersededHistory(t *testing.T) {
	markerPath := fixtureKeyPath(journal.MarkerKey(fixtureRepoStream))
	data, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatalf("failed to read marker fixture: %v", err)
	}
	marker, err := journal.ParseMarker(data)
	if err != nil {
		t.Fatalf("ParseMarker failed on the golden marker: %v", err)
	}
	if marker.Stream != fixtureRepoStream {
		t.Errorf("marker stream = %q, want %q", marker.Stream, fixtureRepoStream)
	}

	marshaled, err := journal.MarshalMarker(marker)
	if err != nil {
		t.Fatalf("MarshalMarker failed: %v", err)
	}
	if string(marshaled) != string(data) {
		t.Errorf("marker.json is not in canonical form:\ngot:\n%s\nwant:\n%s", marshaled, data)
	}

	// Publish-last: the snapshot the marker names is already in storage.
	snapshotPath := fixtureKeyPath(journal.SnapshotKey(fixtureRepoStream, marker.Snapshot))
	snapshot, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatalf("marker names a snapshot that is not in storage: %v", err)
	}
	if err := journal.ValidateSnapshot(snapshot, marker.Snapshot); err != nil {
		t.Fatalf("ValidateSnapshot failed on the golden snapshot: %v", err)
	}

	// Superseded history is still on disk, and replay resumes at marker.sequence + 1.
	records := fixtureStreamRecords(t, fixtureRepoStream)
	if marker.Sequence == 0 || marker.Sequence >= journal.Seq(len(records)-1) {
		t.Fatalf("marker sequence %d does not leave both superseded and live transactions", marker.Sequence)
	}
	superseded := 0
	for _, rec := range records {
		if rec.Seq <= marker.Sequence {
			superseded++
			for _, hash := range rec.Segments {
				path := fixtureKeyPath(journal.SegmentKey(fixtureRepoStream, hash))
				if _, err := os.Stat(path); err != nil {
					t.Errorf("superseded segment %s was purged; compaction must retain it: %v", hash, err)
				}
			}
		}
	}
	if superseded == 0 {
		t.Error("expected the fixture journal to retain transactions the snapshot supersedes")
	}

	// The opaque stream has never been compacted: no marker means replay from seq 0.
	opaqueMarker := fixtureKeyPath(journal.MarkerKey(fixtureOpaqueStream))
	if _, err := os.Stat(opaqueMarker); !os.IsNotExist(err) {
		t.Errorf("expected the opaque stream to have no marker, stat returned %v", err)
	}
}

// TestFixtureConditionalAppend covers Ruling 5: the conditional-append precondition, the
// deterministic tx key derivation, and the exact single-line refusals of spec section 11.5.
func TestFixtureConditionalAppend(t *testing.T) {
	path := filepath.Join(journalFixturesDir(), "conditional_append.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}

	// The committed table must be byte for byte what the generator produces today, so it
	// cannot be hand-edited in place or left stale. That proves agreement with the
	// generator and nothing more, so every value it carries is pinned to a literal
	// somewhere else as well: the refusal wording and the conflict code in
	// fencing_test.go, the append targets in the loop below. Only the descriptions are
	// unpinned prose, and they are checked for being present and single-line.
	want, err := json.MarshalIndent(buildConditionalAppendFixture(), "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal the expected conditional append fixture: %v", err)
	}
	want = append(want, '\n')
	if !bytes.Equal(data, want) {
		t.Errorf("conditional_append.json is stale; regenerate it:\ngot:\n%s\nwant:\n%s", data, want)
	}
	var fixture struct {
		Version        string `json:"version"`
		ConditionalPut struct {
			Header         string `json:"header"`
			Value          string `json:"value"`
			ConflictStatus int    `json:"conflict_status"`
			ConflictCode   string `json:"conflict_code"`
		} `json:"conditional_put"`
		TxKeys []struct {
			Stream      journal.StreamID `json:"stream"`
			Seq         string           `json:"seq"`
			Key         string           `json:"key"`
			Description string           `json:"description"`
		} `json:"tx_keys"`
		Refusals []struct {
			Case    string           `json:"case"`
			Stream  journal.StreamID `json:"stream"`
			Seq     *journal.Seq     `json:"seq"`
			Message string           `json:"message"`
		} `json:"refusals"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("failed to parse %s: %v", path, err)
	}

	if fixture.Version != journal.VersionPrefix {
		t.Errorf("version = %q, want %q", fixture.Version, journal.VersionPrefix)
	}
	if fixture.ConditionalPut.Header != journal.HeaderIfNoneMatch {
		t.Errorf("conditional put header = %q, want %q", fixture.ConditionalPut.Header, journal.HeaderIfNoneMatch)
	}
	if fixture.ConditionalPut.Value != journal.IfNoneMatchWildcard {
		t.Errorf("conditional put value = %q, want %q", fixture.ConditionalPut.Value, journal.IfNoneMatchWildcard)
	}
	if fixture.ConditionalPut.ConflictStatus != journal.StatusPreconditionFailed {
		t.Errorf("conflict status = %d, want %d", fixture.ConditionalPut.ConflictStatus, journal.StatusPreconditionFailed)
	}
	if fixture.ConditionalPut.ConflictCode != journal.CodePreconditionFailed {
		t.Errorf("conflict code = %q, want %q", fixture.ConditionalPut.ConflictCode, journal.CodePreconditionFailed)
	}

	if len(fixture.TxKeys) == 0 {
		t.Fatal("expected conditional append key fixtures")
	}
	pinned := make(map[journal.Seq]bool, len(fixture.TxKeys))
	for _, tc := range fixture.TxKeys {
		// The sequence is a decimal string, so that the largest one survives a parser
		// that reads JSON numbers as doubles. Reject anything but its exact decimal
		// form: a rounded or reformatted sequence derives the wrong key, which is the
		// failure this row exists to keep a reimplementation from hitting.
		seq, err := strconv.ParseUint(tc.Seq, 10, 64)
		if err != nil {
			t.Errorf("tx key %q: seq %q is not a decimal uint64: %v", tc.Key, tc.Seq, err)
			continue
		}
		if canonical := strconv.FormatUint(seq, 10); canonical != tc.Seq {
			t.Errorf("tx key %q: seq %q is not the exact decimal form of %d", tc.Key, tc.Seq, seq)
		}
		if got := journal.TxKey(tc.Stream, journal.Seq(seq)); got != tc.Key {
			t.Errorf("TxKey(%q, %d) = %q, fixture says %q", tc.Stream, seq, got, tc.Key)
		}
		if strings.TrimSpace(tc.Description) == "" {
			t.Errorf("tx key %q carries no description", tc.Key)
		}
		if strings.ContainsAny(tc.Description, "\n\r") {
			t.Errorf("tx key %q description is not a single line: %q", tc.Key, tc.Description)
		}
		pinned[journal.Seq(seq)] = true
	}

	// Fixtures README rule 9 says the table reaches the ends of the range, so the two
	// sequences that carry that claim are named here rather than left to the generator.
	for _, seq := range []journal.Seq{0, fixtureSeq42, fixtureSeqMax} {
		if !pinned[seq] {
			t.Errorf("the append target table pins no key at sequence %d", seq)
		}
	}

	if len(fixture.Refusals) != 5 {
		t.Fatalf("expected the five section 11.5 refusals, got %d", len(fixture.Refusals))
	}
	for _, tc := range fixture.Refusals {
		var want string
		switch tc.Case {
		case "fenced_by_conflict_repo_stream", "fenced_by_conflict_meta_stream":
			if tc.Seq == nil {
				t.Errorf("refusal %q must name the conflicting sequence", tc.Case)
				continue
			}
			want = journal.RefuseStreamFenced(tc.Stream, *tc.Seq).Error()
		case "permanently_fenced_repo_stream", "permanently_fenced_meta_stream":
			want = journal.RefusePermanentlyFenced(tc.Stream).Error()
		case "storage_provider_lacks_cas":
			want = journal.RefuseCASNotSupported().Error()
		default:
			t.Errorf("unknown refusal case %q", tc.Case)
			continue
		}
		if tc.Message != want {
			t.Errorf("refusal %q:\n got: %s\nwant: %s", tc.Case, tc.Message, want)
		}
		if strings.ContainsAny(tc.Message, "\n\r") {
			t.Errorf("refusal %q is not a single line: %q", tc.Case, tc.Message)
		}
	}
}

// fixtureToken is one row of a token table rebuilt from the meta stream: the hash a bearer
// token is looked up by, what it may touch, and whether it still may.
type fixtureToken struct {
	hash    string
	scopes  []string
	revoked bool
}

// TestFixtureTokenTableReplay covers the promise ARCHITECTURE.md's Auth section makes for
// built-in tokens: they are "journaled to the meta stream, so restore restores your tokens
// too". A restore holds the journal and nothing else — the local token store died with the
// disk — so this rebuilds the table from the meta records alone and asserts that what comes
// back is a table a server could serve from: a hash to look a request up by, and the scopes
// to answer it with.
//
// It walks the whole stream rather than the records it expects, so a token record appended
// later is replayed here too, and a type nobody taught this loop about is reported rather
// than skipped.
func TestFixtureTokenTableReplay(t *testing.T) {
	dir := fixtureKeyPath(journal.TxPrefix(journal.MetaStreamID))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read the meta stream: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	chain := journal.NewSigningChain()
	table := make(map[string]*fixtureToken, len(names))

	for i, name := range names {
		seq := journal.Seq(i)
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read %s: %v", path, err)
		}
		var header struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(data, &header); err != nil {
			t.Fatalf("failed to parse %s: %v", path, err)
		}

		switch header.Type {
		case journal.RecordTypeGenesis:
			var genesis journal.GenesisRecord
			if err := json.Unmarshal(data, &genesis); err != nil {
				t.Fatalf("failed to parse %s: %v", path, err)
			}
			if err := chain.ApplyGenesis(&genesis); err != nil {
				t.Fatalf("ApplyGenesis failed on %s: %v", path, err)
			}
		case journal.RecordTypeKeyRotation:
			var rotation journal.KeyRotationRecord
			if err := json.Unmarshal(data, &rotation); err != nil {
				t.Fatalf("failed to parse %s: %v", path, err)
			}
			if err := chain.ApplyRotation(&rotation); err != nil {
				t.Fatalf("ApplyRotation failed on %s: %v", path, err)
			}
		case journal.RecordTypeTokenCreate:
			var rec journal.TokenCreateRecord
			if err := json.Unmarshal(data, &rec); err != nil {
				t.Fatalf("failed to parse %s: %v", path, err)
			}
			if err := rec.Validate(); err != nil {
				t.Fatalf("%s: Validate failed: %v", path, err)
			}
			if rec.Seq != seq {
				t.Errorf("%s: record seq = %d does not match its key", path, rec.Seq)
			}
			if _, exists := table[rec.TokenID]; exists {
				t.Errorf("%s: token create at seq %d reuses token id %s", path, rec.Seq, rec.TokenID)
			}
			table[rec.TokenID] = &fixtureToken{hash: rec.TokenHash, scopes: rec.Scopes}
			if err := chain.AdvanceMetaSeq(rec.Seq); err != nil {
				t.Fatalf("AdvanceMetaSeq failed on %s: %v", path, err)
			}
		case journal.RecordTypeTokenRevoke:
			var rec journal.TokenRevokeRecord
			if err := json.Unmarshal(data, &rec); err != nil {
				t.Fatalf("failed to parse %s: %v", path, err)
			}
			if err := rec.Validate(); err != nil {
				t.Fatalf("%s: Validate failed: %v", path, err)
			}
			if rec.Seq != seq {
				t.Errorf("%s: record seq = %d does not match its key", path, rec.Seq)
			}
			existing, exists := table[rec.TokenID]
			switch {
			case !exists:
				t.Errorf("%s: token revoke at seq %d names unknown token %s", path, rec.Seq, rec.TokenID)
			case existing.hash != rec.TokenHash:
				t.Errorf("%s: token revoke at seq %d disagrees with the hash recorded for token %s", path, rec.Seq, rec.TokenID)
			default:
				existing.revoked = true
			}
			if err := chain.AdvanceMetaSeq(rec.Seq); err != nil {
				t.Fatalf("AdvanceMetaSeq failed on %s: %v", path, err)
			}
		default:
			t.Errorf("%s: unknown meta record type %q", path, header.Type)
		}
	}

	if chain.LastMetaSeq() != fixtureMetaHeadSeq {
		t.Errorf("the meta replay ended at seq %d, want %d", chain.LastMetaSeq(), fixtureMetaHeadSeq)
	}
	if len(table) != 2 {
		t.Fatalf("the rebuilt token table holds %d tokens, want 2", len(table))
	}

	admin, ok := table["tok_admin_01"]
	if !ok {
		t.Fatal("the rebuilt token table lost tok_admin_01")
	}
	if !admin.revoked {
		t.Error("tok_admin_01 is revoked on the meta stream but came back live")
	}
	if got, want := admin.hash, fixtureTokenHash(fixtureAdminToken); got != want {
		t.Errorf("tok_admin_01 hash = %q, want the hash of its raw token %q", got, want)
	}

	// The two-scope case: a single scope field cannot carry this token at all, which is why
	// the record has an array. Both scopes survive the round trip, in the order written.
	writer, ok := table["tok_writer_02"]
	if !ok {
		t.Fatal("the rebuilt token table lost tok_writer_02")
	}
	if writer.revoked {
		t.Error("tok_writer_02 is never revoked on the meta stream but came back revoked")
	}
	if got, want := writer.hash, fixtureTokenHash(fixtureWriterToken); got != want {
		t.Errorf("tok_writer_02 hash = %q, want the hash of its raw token %q", got, want)
	}
	if got, want := strings.Join(writer.scopes, ","), "rw:blog-*,r:docs"; got != want {
		t.Errorf("tok_writer_02 scopes = %q, want %q", got, want)
	}
}

// fixtureSequences collects every value in a decoded JSON document that sits under a key
// named "seq" or "sequence", at any depth. The whole document is searched rather than the
// two or three places a sequence is expected, so a sequence added anywhere in the tree
// later is held to the same rule without anyone remembering to add it here.
func fixtureSequences(v any) []any {
	switch node := v.(type) {
	case map[string]any:
		var found []any
		for _, key := range []string{"seq", "sequence"} {
			if value, ok := node[key]; ok {
				found = append(found, value)
			}
		}
		for _, value := range node {
			found = append(found, fixtureSequences(value)...)
		}
		return found
	case []any:
		var found []any
		for _, value := range node {
			found = append(found, fixtureSequences(value)...)
		}
		return found
	}
	return nil
}

// TestFixtureSequencesSurviveDoubleParsers covers spec section 1.1: every sequence in the
// published tree is a JSON string holding its exact decimal form, so a reader whose JSON
// numbers are IEEE-754 doubles reads the sequence that was written rather than a rounded
// one that no longer names its own object key.
//
// The tree is decoded into `any`, which is Go's double-based reading of JSON — every number
// becomes a float64, exactly as JavaScript's JSON.parse produces — so this asks the question
// as the reimplementation most likely to be bitten by it would ask it, and it asks it of the
// committed bytes rather than of the encoder that wrote them. The maximum unsigned 64-bit
// sequence is required to be somewhere in the tree, because a rule about the top of the
// range proves nothing if nothing in the tree reaches it.
func TestFixtureSequencesSurviveDoubleParsers(t *testing.T) {
	root := journalFixturesDir()
	seen := make(map[journal.Seq]bool)

	for _, name := range fixtureTreeFiles(t, root) {
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("failed to read %s: %v", name, err)
		}
		var document any
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatalf("failed to parse %s: %v", name, err)
		}

		sequences := fixtureSequences(document)
		if len(sequences) == 0 {
			t.Errorf("%s carries no sequence at all, so it cannot be the journal object its key says it is", name)
		}
		for _, raw := range sequences {
			text, ok := raw.(string)
			if !ok {
				t.Errorf("%s: sequence %v is a JSON %T, not a string, so a reader whose numbers are doubles cannot read it exactly", name, raw, raw)
				continue
			}
			seq, err := journal.ParseSeqDecimal(text)
			if err != nil {
				t.Errorf("%s: sequence %q is not the exact decimal form of a 64-bit unsigned integer: %v", name, text, err)
				continue
			}
			seen[seq] = true

			// A transaction record names its own key, and the cross-check the spec asks a
			// reader to perform is the one this encoding exists to keep working.
			if !strings.Contains(name, "/tx/") {
				continue
			}
			fromKey, err := journal.ParseSeq(strings.TrimSuffix(filepath.Base(name), ".json"))
			if err != nil {
				t.Errorf("%s: transaction key is not a 20-digit sequence: %v", name, err)
				continue
			}
			if seq != fromKey {
				t.Errorf("%s: record sequence %d does not match the %d in its key", name, uint64(seq), uint64(fromKey))
			}
		}
	}

	if !seen[fixtureSeqMax] {
		t.Errorf("no sequence in the fixture tree reaches %d, so nothing here exercises the top of the range", uint64(fixtureSeqMax))
	}
}

// TestFixtureReimplementationGrant checks that the fixtures carry the unconditional
// reimplementation grant of spec/journal/v1/README.md section 13.
func TestFixtureReimplementationGrant(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(journalFixturesDir(), "README.md"))
	if err != nil {
		t.Fatalf("failed to read fixtures README: %v", err)
	}
	text := string(data)
	for _, phrase := range []string{"any language", "any purpose", "without asking"} {
		if !strings.Contains(text, phrase) {
			t.Errorf("fixtures README is missing the reimplementation grant phrase %q", phrase)
		}
	}
}

// fixtureTreeFiles lists every file under root, as slash-separated paths relative to it.
// Directories are not listed: git does not carry empty ones, so a directory can only reach
// the committed tree by way of a file inside it, which this sees.
func fixtureTreeFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk %s: %v", root, err)
	}
	sort.Strings(files)
	return files
}

// fixtureHandWritten is the one file under fixtures/ that the generator does not produce.
// It is prose about the tree rather than part of it, so it is named here and everything
// else has to be accounted for by the generator.
const fixtureHandWritten = "README.md"

// TestFixturesAreGenerated asserts that the committed golden journal is exactly what the
// generator writes today: the same files, no more and no fewer, and the same bytes in each.
//
// This is the gate that makes a format change visible in review. Editing a record, adding a
// field to one, adding a stream, dropping a file, or dropping something unrelated into the
// tree all fail here, and the only way to make the test pass again is to change the
// generator — which is a diff a reviewer reads — and regenerate.
//
// The one thing it does not compare on its own terms is packfile bytes: those come from the
// local git binary and are not reproducible across versions, so resolvePack matches each
// generated pack to the committed pack holding the same objects and carries the committed
// bytes forward. The reasoning, and what that costs, is documented there.
func TestFixturesAreGenerated(t *testing.T) {
	committed := journalFixturesDir()
	regenerated := t.TempDir()
	generateFixtures(newFixtureWriter(t, regenerated, committed))

	generated := fixtureTreeFiles(t, regenerated)
	expected := make(map[string]bool, len(generated)+1)
	for _, name := range generated {
		expected[name] = true
	}
	expected[fixtureHandWritten] = true

	present := make(map[string]bool)
	for _, name := range fixtureTreeFiles(t, committed) {
		present[name] = true
		if !expected[name] {
			t.Errorf("fixtures hold %s, which the generator does not write", name)
		}
	}
	if !present[fixtureHandWritten] {
		t.Errorf("fixtures do not hold %s", fixtureHandWritten)
	}

	for _, name := range generated {
		if !present[name] {
			t.Errorf("the generator writes %s, which the fixtures do not hold", name)
			continue
		}
		wantData, err := os.ReadFile(filepath.Join(regenerated, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("failed to read the regenerated %s: %v", name, err)
		}
		gotData, err := os.ReadFile(filepath.Join(committed, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("failed to read the committed %s: %v", name, err)
		}
		if bytes.Equal(gotData, wantData) {
			continue
		}
		if strings.HasSuffix(name, ".json") {
			t.Errorf("%s is not what the generator writes; regenerate the fixtures:\ngot:\n%s\nwant:\n%s", name, gotData, wantData)
			continue
		}
		t.Errorf("%s is not what the generator writes; regenerate the fixtures (%d bytes committed, %d generated)", name, len(gotData), len(wantData))
	}
}

// specJSONExamples is the number of JSON examples the format specification carries: the
// genesis record (section 3.1), a key rotation (4.1), two token creations and a revocation
// (4.3 and 4.4), a ref transaction (5.1), and the marker (7.2). Each quotes a fixture, and
// section 3.1 says so on all their behalf — "Every example record in this document is a real
// record from that journal". Asserted, so that an example cannot quietly leave the document
// either.
const specJSONExamples = 7

// specFixtureLink finds the fixture a spec example cites, in the prose between the end of
// the example and whatever comes next — the field table, the next example, the next section.
var specFixtureLink = regexp.MustCompile(`\]\((fixtures/[^)\s]+)\)`)

// stripQuote removes a markdown blockquote marker from a line, and reports whether there
// was one. CommonMark lets a fenced block sit inside a blockquote, and the block's content
// is then its lines with that marker taken off — so this is how such a block is read back
// out. It matters twice over: ">" is not JSON whitespace, so a quoted record example does
// not parse until the marker is gone.
func stripQuote(line string) (rest string, quoted bool) {
	trimmed := strings.TrimLeft(line, " \t")
	if !strings.HasPrefix(trimmed, ">") {
		return line, false
	}
	return strings.TrimPrefix(strings.TrimPrefix(trimmed, ">"), " "), true
}

// fenceOpener reports whether a line opens a fenced code block, and returns the fence marker
// and the info string. Both markdown fence characters count, at any indentation, inside a
// blockquote or out, because the question this test asks is which examples the document
// carries — and an example does not stop being one for being written ~~~json, or for sitting
// inside a list item, or for being quoted.
//
// The marker is the whole run of fence characters, not the first three. CommonMark allows a
// longer run, and a longer run demands an at-least-as-long closer, so the length belongs to
// the marker rather than being a detail to round off. Read as three characters, ````json
// carries the info string "`json" — a legal json example nothing would then check — and its
// legal closer stops being recognizable as one.
func fenceOpener(line string) (marker, info string, ok bool) {
	trimmed, _ := stripQuote(line)
	trimmed = strings.TrimLeft(trimmed, " \t")
	for _, c := range []byte{'`', '~'} {
		run := 0
		for run < len(trimmed) && trimmed[run] == c {
			run++
		}
		if run >= 3 {
			return trimmed[:run], strings.TrimSpace(trimmed[run:]), true
		}
	}
	return "", "", false
}

// fenceCloses reports whether a line closes a block opened with marker. CommonMark's closer
// is a run of at least as many of the same fence character as the opener, with nothing after
// it but whitespace — so a longer run closes a shorter fence, and an info string disqualifies
// a line from closing anything.
func fenceCloses(line, marker string) bool {
	trimmed, _ := stripQuote(line)
	trimmed = strings.TrimSpace(trimmed)
	if !strings.HasPrefix(trimmed, marker) {
		return false
	}
	return strings.Trim(trimmed, marker[:1]) == ""
}

// looksLikeJSONDocument reports whether a run of text is a JSON object. The spec's untagged
// blocks are refusal strings, key layouts and HTTP headers, none of which parse; text that
// does parse is a record example, whatever markdown is wrapped around it.
func looksLikeJSONDocument(block string) bool {
	trimmed := strings.TrimSpace(block)
	return strings.HasPrefix(trimmed, "{") && json.Valid([]byte(trimmed))
}

// jsonObjectEnd reports whether a JSON object begins on line i and, if so, the line it ends
// on. The object is the shortest run of lines from i that parses, and the run stops at a blank
// line, which no record example contains.
//
// Nothing about the markdown around it is consulted, and that is the point. The fence walk in
// TestSpecExamplesMatchFixtures can only see examples that are fences; a JSON example written
// as CommonMark's other code block — four-space indented — or tucked inside a blockquote is
// not a fence at all, so it would otherwise pass the document without ever being counted,
// linked or compared. This finds JSON by being JSON. Indentation is left alone because JSON
// ignores whitespace; the blockquote marker is taken off because JSON does not ignore ">".
func jsonObjectEnd(lines []string, i int) (int, bool) {
	if first, _ := stripQuote(lines[i]); !strings.HasPrefix(strings.TrimSpace(first), "{") {
		return 0, false
	}
	var b strings.Builder
	for end := i; end < len(lines); end++ {
		line, _ := stripQuote(lines[end])
		if strings.TrimSpace(line) == "" {
			return 0, false
		}
		b.WriteString(line)
		b.WriteByte('\n')
		if looksLikeJSONDocument(b.String()) {
			return end, true
		}
	}
	return 0, false
}

// TestSpecExamplesMatchFixtures holds every JSON example in spec/journal/v1/README.md to the
// fixture it links, byte for byte. The document claims the examples are real records from
// the golden journal, and that claim is worth exactly as much as its enforcement: the two
// agreed when they were written and agreed at review, which is how they will drift.
//
// The document is read twice. The first pass walks its fenced blocks and holds every ```json
// one to its fixture; the second sweeps everything the first did not claim and finds JSON by
// parsing it, so an example written as an indented code block, inside a blockquote, or under
// any other fence tag is caught rather than passing unseen. What neither pass covers is an
// example that is neither: not carried by a ```json fence, and not parseable as a JSON object
// from some line of its own through an unbroken run of lines, once one level of blockquote
// marker is off.
//
// Being incomplete is one way to land there — a fragment, a record with an ellipsis through
// it, one split by a blank line, one quoted twice over — but completeness is not the boundary,
// and reading only that list would suggest it is. A whole record escapes just as readily
// whenever the line its object opens on does not itself begin with "{" after one blockquote
// strip: inline in a prose sentence, on one line in a table cell, or prefixed line by line
// inside a ```diff fence. All of those are illustrations rather than records, and section
// 3.1's claim is about records.
//
// It is also, as things stand, the only test that sees a repack. TestFixturesAreGenerated
// matches packs by their object set and carries the committed bytes forward, so new pack
// bytes for the same objects pass it; but two of these four examples — the ref transaction
// of section 5.1 and the marker of section 7.2 — quote pack digests, and those move. That
// detection is a side effect of which records the spec chose to illustrate, not a property
// of this test, and it would disappear if either example were replaced with one that names
// no pack. It is written down here and in the gap list rather than relied on quietly.
func TestSpecExamplesMatchFixtures(t *testing.T) {
	specPath := filepath.Join(journalSpecDir(), "README.md")
	data, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", specPath, err)
	}
	lines := strings.Split(string(data), "\n")

	// carried marks every line a ```json fence accounts for. What is left over is swept
	// below for JSON the fence walk cannot see.
	carried := make([]bool, len(lines))
	examples := 0
	for i := 0; i < len(lines); i++ {
		marker, info, ok := fenceOpener(lines[i])
		if !ok {
			continue
		}
		_, quoted := stripQuote(lines[i])
		start := i + 1
		end := start
		for end < len(lines) && !fenceCloses(lines[end], marker) {
			end++
		}
		if end == len(lines) {
			t.Fatalf("%s:%d: unterminated fenced block", specPath, i+1)
		}
		body := make([]string, 0, end-start)
		for _, line := range lines[start:end] {
			if quoted {
				line, _ = stripQuote(line)
			}
			body = append(body, line)
		}
		block := strings.Join(body, "\n") + "\n"
		i = end

		// A block that is not tagged json is prose, a key layout, or a refusal string, and
		// none of this test's business. If it holds a JSON document anyway it is an example
		// wearing the wrong fence, and the sweep below is what says so.
		if info != "json" {
			continue
		}
		for j := start - 1; j <= end; j++ {
			carried[j] = true
		}
		example := block
		examples++

		link := ""
		for j := end + 1; j < len(lines); j++ {
			line := lines[j]
			if _, _, isFence := fenceOpener(line); isFence {
				break
			}
			if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "|") {
				break
			}
			if m := specFixtureLink.FindStringSubmatch(line); m != nil {
				link = m[1]
				break
			}
		}
		if link == "" {
			t.Errorf("%s:%d: this json example cites no fixture, so nothing holds it to one", specPath, start)
			continue
		}

		fixture, err := os.ReadFile(filepath.Join(journalSpecDir(), filepath.FromSlash(link)))
		if err != nil {
			t.Errorf("%s:%d: cites %s, which is not in the fixture tree: %v", specPath, start, link, err)
			continue
		}
		if string(fixture) != example {
			t.Errorf("%s:%d: the example and %s have drifted apart.\n"+
				"If you have just regenerated the fixtures, this is the second half of that job: the\n"+
				"examples are copied into the specification by hand, so paste the fixture over the\n"+
				"example and review the diff — a changed pack digest here means your git packs these\n"+
				"objects differently, which is a real change to a published artifact.\n"+
				"spec:\n%s\nfixture:\n%s", specPath, start, link, example, fixture)
		}
	}

	// Everything above reads fences, so everything above is blind to a JSON example that is
	// not one: an untagged or mis-tagged fence, four-space indentation, a block the document
	// quotes rather than fences. This sweeps what the fence walk did not claim and finds JSON
	// by parsing it, so no shape of markdown gets an example past the link check.
	//
	// The question widened on the way here, and a future author should know it was meant to.
	// The check this replaced asked whether a whole fence body was a JSON document; this asks
	// it of every unclaimed line, so JSON that is only part of a block fires too. The case
	// that will actually come up is an HTTP example carrying a record body — a natural
	// addition to section 11, which already fences one ```http request — and there is no way
	// to write it that this gate accepts: left as http it reports the message below, and
	// fenced json instead it must then cite a fixture, which a block holding a request line
	// and headers can never match byte for byte. That is the rule working, not failing: any
	// JSON object in this document is a record held to a fixture. An example of that shape
	// cannot be added without changing the rule.
	for i := 0; i < len(lines); i++ {
		if carried[i] {
			continue
		}
		end, ok := jsonObjectEnd(lines, i)
		if !ok {
			continue
		}
		t.Errorf("%s:%d: this JSON document is not inside a ```json fence, so nothing holds it to a fixture", specPath, i+1)
		i = end
	}

	if examples != specJSONExamples {
		t.Errorf("the specification carries %d json examples, want %d", examples, specJSONExamples)
	}
}
