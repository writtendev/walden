package journal_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/journal"
)

// journalFixturesDir returns the published golden journal under spec/journal/v1/fixtures.
func journalFixturesDir() string {
	return filepath.Join("..", "..", "spec", "journal", "v1", "fixtures")
}

// The golden journal is laid out as a real bucket would be, so these tests read it the
// way a reimplementation would: replay _meta from genesis, then replay each repository
// stream against the signing key that was active when its records were written.
//
// Timeline of the fixture journal:
//
//	_meta      seq 0  genesis, public key K0
//	_meta      seq 1  token_create
//	repo-alpha seq 0  first push into an empty repository        signed K0
//	repo-alpha seq 1  fast-forward main, create feature          signed K0
//	repo-alpha seq 2  delete feature, no segments                signed K0
//	<opaque>   seq 0  first push on an opaque stream identifier  signed K0
//	_meta      seq 2  key_rotation K0 -> K1, signed by K0
//	repo-alpha seq 3  force update of main                       signed K1
//	_meta      seq 3  token_revoke
const (
	fixtureRepoStream   = "repo-alpha"
	fixtureOpaqueStream = "9f2c1d7a-4e6b-4a10-8c3f-2b5d81e0a7c4"
)

// loadFixtureChain replays the _meta stream up to and including maxSeq and returns the chain.
func loadFixtureChain(t *testing.T, maxSeq uint64) *journal.SigningChain {
	t.Helper()
	dir := filepath.Join(journalFixturesDir(), "streams", string(journal.MetaStreamID), "tx")
	chain := journal.NewSigningChain()

	for seq := uint64(0); seq <= maxSeq; seq++ {
		path := filepath.Join(dir, journal.FormatSeq(seq)+".json")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read meta fixture %s: %v", path, err)
		}
		var header struct {
			Version string           `json:"version"`
			Stream  journal.StreamID `json:"stream"`
			Seq     uint64           `json:"seq"`
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
	data, err := os.ReadFile(filepath.Join(journalFixturesDir(), "streams", string(journal.MetaStreamID), "tx", journal.FormatSeq(2)+".json"))
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
	dir := filepath.Join(journalFixturesDir(), "streams", string(stream), "tx")
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
		if seq != uint64(i) {
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
		path := filepath.Join(journalFixturesDir(), "streams", string(stream), "segments", hash+".pack")
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
	if alpha[3].Updates[0].Ref != "refs/heads/main" {
		t.Errorf("repo-alpha seq 3 updates %q, want refs/heads/main", alpha[3].Updates[0].Ref)
	}
	if alpha[3].Updates[0].OldOID != alpha[1].Updates[0].NewOID {
		t.Error("repo-alpha seq 3 does not force-update the tip left by seq 1")
	}
	if alpha[3].Updates[0].NewOID == alpha[2].Updates[0].OldOID {
		t.Error("repo-alpha seq 3 is a fast-forward, not a force update")
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

// TestFixtureSegmentsAreContentAddressed covers Ruling 4: every pack segment and
// snapshot in the journal is stored under the SHA-256 of its own verbatim bytes.
func TestFixtureSegmentsAreContentAddressed(t *testing.T) {
	root := filepath.Join(journalFixturesDir(), "streams")
	streams, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("failed to read %s: %v", root, err)
	}

	packs := 0
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
				packs++
			}
		}
	}
	if packs == 0 {
		t.Fatal("expected the fixture journal to contain pack segments")
	}
}

// TestFixtureMarkerAndSupersededHistory covers the compaction half of Ruling 4: a
// published marker whose snapshot exists, with the transactions and segments it
// supersedes retained in storage and ignored rather than treated as corruption.
func TestFixtureMarkerAndSupersededHistory(t *testing.T) {
	markerPath := filepath.Join(journalFixturesDir(), "streams", fixtureRepoStream, "marker.json")
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
	snapshotPath := filepath.Join(journalFixturesDir(), "streams", fixtureRepoStream, "snapshots", marker.Snapshot+".pack")
	snapshot, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatalf("marker names a snapshot that is not in storage: %v", err)
	}
	if err := journal.ValidateSnapshot(snapshot, marker.Snapshot); err != nil {
		t.Fatalf("ValidateSnapshot failed on the golden snapshot: %v", err)
	}

	// Superseded history is still on disk, and replay resumes at marker.sequence + 1.
	records := fixtureStreamRecords(t, fixtureRepoStream)
	if marker.Sequence == 0 || marker.Sequence >= uint64(len(records))-1 {
		t.Fatalf("marker sequence %d does not leave both superseded and live transactions", marker.Sequence)
	}
	superseded := 0
	for _, rec := range records {
		if rec.Seq <= marker.Sequence {
			superseded++
			for _, hash := range rec.Segments {
				path := filepath.Join(journalFixturesDir(), "streams", fixtureRepoStream, "segments", hash+".pack")
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
	opaqueMarker := filepath.Join(journalFixturesDir(), "streams", fixtureOpaqueStream, "marker.json")
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
	var fixture struct {
		Version        string `json:"version"`
		ConditionalPut struct {
			Header         string `json:"header"`
			Value          string `json:"value"`
			ConflictStatus int    `json:"conflict_status"`
			ConflictCode   string `json:"conflict_code"`
		} `json:"conditional_put"`
		TxKeys []struct {
			Stream journal.StreamID `json:"stream"`
			Seq    uint64           `json:"seq"`
			Key    string           `json:"key"`
		} `json:"tx_keys"`
		Refusals []struct {
			Case    string           `json:"case"`
			Stream  journal.StreamID `json:"stream"`
			Seq     *uint64          `json:"seq"`
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

	if len(fixture.TxKeys) == 0 {
		t.Fatal("expected conditional append key fixtures")
	}
	for _, tc := range fixture.TxKeys {
		if got := journal.TxKey(tc.Stream, tc.Seq); got != tc.Key {
			t.Errorf("TxKey(%q, %d) = %q, fixture says %q", tc.Stream, tc.Seq, got, tc.Key)
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
