package journal_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/journal"
)

// fakeSource is an in-memory journal.ObjectSource backed by a plain map,
// populated from the golden fixture tree by reusing fixtureKeyPath (the
// same key derivation a real reimplementation would use). It exists so
// these tests can drive (*journal.Reader) directly, with no HTTP and no
// *store.Client in the loop; internal/store/reader_test.go is what proves
// *store.Client itself satisfies ObjectSource.
type fakeSource struct {
	objects map[string][]byte
}

// newFixtureSource walks the published golden journal
// (spec/journal/v1/fixtures) and loads every file into a fresh fakeSource,
// keyed exactly as journal.TxKey/MarkerKey/SnapshotKey/SegmentKey would
// derive it. Each call returns an independent copy, so a test that
// mutates or deletes an object never affects another test's source.
func newFixtureSource(t *testing.T) *fakeSource {
	t.Helper()
	root := journalFixturesDir()
	src := &fakeSource{objects: make(map[string][]byte)}
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
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		src.objects[filepath.ToSlash(rel)] = data
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk fixture tree %s: %v", root, err)
	}
	return src
}

func (s *fakeSource) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	data, ok := s.objects[key]
	if !ok {
		return nil, journal.ErrObjectNotFound
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// List matches store.(*Client).List's contract closely enough for these
// tests: keys under prefix, in ascending lexicographic order (section 10's
// guarantee, which the real store.Client also honors), strictly after
// startAfter, stopping and returning fn's own error the moment fn returns
// one.
func (s *fakeSource) List(ctx context.Context, prefix, startAfter string, fn func(key string) error) error {
	keys := make([]string, 0, len(s.objects))
	for k := range s.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		if startAfter != "" && k <= startAfter {
			continue
		}
		if err := fn(k); err != nil {
			return err
		}
	}
	return nil
}

func (s *fakeSource) set(key string, data []byte) { s.objects[key] = data }
func (s *fakeSource) delete(key string)           { delete(s.objects, key) }

// mutateField decodes data as a JSON object, sets field to value, and
// re-encodes it. Field order and indentation change, which none of
// ParseMarker/ParseRefTx care about; only the (now-stale) signature is
// what these tests are trying to exercise.
func mutateField(t *testing.T, data []byte, field string, value any) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("failed to unmarshal fixture JSON for mutation: %v", err)
	}
	doc[field] = value
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("failed to re-marshal mutated fixture JSON: %v", err)
	}
	return out
}

// dropField is mutateField's counterpart for a field ParseMarker/ParseRefTx
// require to be present.
func dropField(t *testing.T, data []byte, field string) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("failed to unmarshal fixture JSON for mutation: %v", err)
	}
	delete(doc, field)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("failed to re-marshal mutated fixture JSON: %v", err)
	}
	return out
}

// flipSignature decodes data as a JSON object and flips the last hex
// character of its "signature" field, producing a record or marker whose
// every other field is untouched but whose signature no longer verifies.
func flipSignature(t *testing.T, data []byte) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("failed to unmarshal fixture JSON for mutation: %v", err)
	}
	sig, ok := doc["signature"].(string)
	if !ok || sig == "" {
		t.Fatalf("fixture JSON has no non-empty signature field to flip")
	}
	b := []byte(sig)
	if b[len(b)-1] == '0' {
		b[len(b)-1] = '1'
	} else {
		b[len(b)-1] = '0'
	}
	doc["signature"] = string(b)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("failed to re-marshal mutated fixture JSON: %v", err)
	}
	return out
}

// TestReaderStreams covers the "Files" table's Streams contract: every
// repository stream the fixture tree holds, and never _meta.
func TestReaderStreams(t *testing.T) {
	r := journal.NewReader(newFixtureSource(t))

	streams, err := r.Streams(context.Background())
	if err != nil {
		t.Fatalf("Streams failed: %v", err)
	}

	want := []journal.StreamID{fixtureOpaqueStream, fixtureRepoStream}
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	if !reflect.DeepEqual(streams, want) {
		t.Errorf("Streams = %v, want %v", streams, want)
	}
	for _, s := range streams {
		if s == journal.MetaStreamID {
			t.Errorf("Streams returned %q", journal.MetaStreamID)
		}
	}
}

// TestPlanStreamMarkerPath covers repo-alpha's marker path: baseline
// sequence 3, exactly the marker's three refs, a snapshot step naming the
// marker's hash, and exactly one planned transaction (seq 4) with its
// segments in record order.
func TestPlanStreamMarkerPath(t *testing.T) {
	src := newFixtureSource(t)
	chain := loadFixtureChain(t, fixtureMetaHeadSeq)
	r := journal.NewReader(src)

	plan, err := r.PlanStream(context.Background(), chain, fixtureRepoStream)
	if err != nil {
		t.Fatalf("PlanStream failed: %v", err)
	}
	if plan.Stream != fixtureRepoStream {
		t.Errorf("Stream = %q, want %q", plan.Stream, fixtureRepoStream)
	}
	if plan.Baseline == nil || *plan.Baseline != 3 {
		t.Fatalf("Baseline = %v, want 3", plan.Baseline)
	}

	markerData, err := os.ReadFile(fixtureKeyPath(journal.MarkerKey(fixtureRepoStream)))
	if err != nil {
		t.Fatalf("failed to read marker fixture: %v", err)
	}
	marker, err := journal.ParseMarker(markerData)
	if err != nil {
		t.Fatalf("ParseMarker failed on the golden marker: %v", err)
	}

	if plan.Snapshot == nil {
		t.Fatal("Snapshot = nil, want a snapshot step")
	}
	if plan.Snapshot.SHA256 != marker.Snapshot {
		t.Errorf("Snapshot.SHA256 = %q, want %q", plan.Snapshot.SHA256, marker.Snapshot)
	}
	if want := journal.SnapshotKey(fixtureRepoStream, marker.Snapshot); plan.Snapshot.Key != want {
		t.Errorf("Snapshot.Key = %q, want %q", plan.Snapshot.Key, want)
	}

	if !reflect.DeepEqual(plan.Refs, marker.Refs) {
		t.Errorf("Refs = %+v, want exactly the marker's refs %+v", plan.Refs, marker.Refs)
	}

	if len(plan.Transactions) != 1 {
		t.Fatalf("Transactions has %d entries, want 1", len(plan.Transactions))
	}
	tx := plan.Transactions[0]
	if tx.Record.Seq != 4 {
		t.Errorf("Transactions[0].Record.Seq = %d, want 4", tx.Record.Seq)
	}
	if len(tx.Segments) != len(tx.Record.Segments) {
		t.Fatalf("Segments has %d entries, want %d (one per Record.Segments entry)", len(tx.Segments), len(tx.Record.Segments))
	}
	for i, seg := range tx.Segments {
		wantHash := tx.Record.Segments[i]
		if seg.SHA256 != wantHash {
			t.Errorf("Segments[%d].SHA256 = %q, want %q", i, seg.SHA256, wantHash)
		}
		if want := journal.SegmentKey(fixtureRepoStream, wantHash); seg.Key != want {
			t.Errorf("Segments[%d].Key = %q, want %q", i, seg.Key, want)
		}
	}
}

// TestPlanStreamNoMarkerPath covers the opaque stream, which carries no
// marker: baseline before sequence 0, no snapshot step, one transaction.
func TestPlanStreamNoMarkerPath(t *testing.T) {
	src := newFixtureSource(t)
	chain := loadFixtureChain(t, fixtureMetaHeadSeq)
	r := journal.NewReader(src)

	plan, err := r.PlanStream(context.Background(), chain, fixtureOpaqueStream)
	if err != nil {
		t.Fatalf("PlanStream failed: %v", err)
	}
	if plan.Baseline != nil {
		t.Errorf("Baseline = %v, want nil (no marker)", *plan.Baseline)
	}
	if plan.Snapshot != nil {
		t.Errorf("Snapshot = %+v, want nil (no marker)", plan.Snapshot)
	}
	if len(plan.Refs) != 0 {
		t.Errorf("Refs = %+v, want empty", plan.Refs)
	}
	if len(plan.Transactions) != 1 {
		t.Fatalf("Transactions has %d entries, want 1", len(plan.Transactions))
	}
	if plan.Transactions[0].Record.Seq != 0 {
		t.Errorf("Transactions[0].Record.Seq = %d, want 0", plan.Transactions[0].Record.Seq)
	}
}

// TestPlanStreamGenesisPathAgreesWithMarkerPath is the assertion this
// ticket lives or dies by: with marker.json removed, the plan for
// repo-alpha replays all five transactions and, folded onto an empty ref
// map, arrives at exactly the ref map the marker path arrives at when
// folded onto the marker's ref set. This is TestFixtureReplay's
// two-paths-agree assertion (fixtures_test.go) restated at the plan
// level.
func TestPlanStreamGenesisPathAgreesWithMarkerPath(t *testing.T) {
	fold := func(refs map[string]string, txs []*journal.PlannedTx) {
		for _, tx := range txs {
			for _, u := range tx.Record.Updates {
				if isZeroOID(u.NewOID) {
					delete(refs, u.Ref)
				} else {
					refs[u.Ref] = u.NewOID
				}
			}
		}
	}

	// Genesis path: no marker, so PlanStream must replay from sequence 0.
	genesisSrc := newFixtureSource(t)
	genesisSrc.delete(journal.MarkerKey(fixtureRepoStream))
	genesisChain := loadFixtureChain(t, fixtureMetaHeadSeq)
	genesisPlan, err := journal.NewReader(genesisSrc).PlanStream(context.Background(), genesisChain, fixtureRepoStream)
	if err != nil {
		t.Fatalf("PlanStream (genesis path) failed: %v", err)
	}
	if genesisPlan.Baseline != nil {
		t.Fatalf("Baseline = %v, want nil now that marker.json is gone", *genesisPlan.Baseline)
	}
	if len(genesisPlan.Transactions) != 5 {
		t.Fatalf("Transactions has %d entries, want 5 (all of repo-alpha's history)", len(genesisPlan.Transactions))
	}
	genesisRefs := make(map[string]string)
	fold(genesisRefs, genesisPlan.Transactions)
	if len(genesisRefs) == 0 {
		t.Fatal("genesis-path replay produced no refs, so this proves nothing")
	}

	// Marker path: the full tree, marker intact.
	markerSrc := newFixtureSource(t)
	markerChain := loadFixtureChain(t, fixtureMetaHeadSeq)
	markerPlan, err := journal.NewReader(markerSrc).PlanStream(context.Background(), markerChain, fixtureRepoStream)
	if err != nil {
		t.Fatalf("PlanStream (marker path) failed: %v", err)
	}
	if markerPlan.Baseline == nil || *markerPlan.Baseline != 3 {
		t.Fatalf("Baseline = %v, want 3", markerPlan.Baseline)
	}
	markerRefs := make(map[string]string)
	for _, ref := range markerPlan.Refs {
		markerRefs[ref.Ref] = ref.OID
	}
	fold(markerRefs, markerPlan.Transactions)

	if !reflect.DeepEqual(genesisRefs, markerRefs) {
		t.Errorf("genesis-path refs = %v\nmarker-path refs  = %v\nPlanStream must agree from both paths", genesisRefs, markerRefs)
	}
}

// TestPlanStreamRefusals drives one fault-injection case per section 8.1
// rule this ticket owns, each against its own fresh copy of the fixture
// tree, asserting the exact published line and that it is one line
// (strings.Count(err.Error(), "\n") == 0).
func TestPlanStreamRefusals(t *testing.T) {
	oneLine := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if strings.Count(err.Error(), "\n") != 0 {
			t.Errorf("refusal is not one line: %q", err.Error())
		}
	}

	t.Run("sequence gap (rule 4)", func(t *testing.T) {
		src := newFixtureSource(t)
		src.delete(journal.MarkerKey(fixtureRepoStream))
		src.delete(journal.TxKey(fixtureRepoStream, 2))
		chain := loadFixtureChain(t, fixtureMetaHeadSeq)

		plan, err := journal.NewReader(src).PlanStream(context.Background(), chain, fixtureRepoStream)
		if plan != nil {
			t.Errorf("plan = %+v, want nil (not a partial, four-transaction plan)", plan)
		}
		oneLine(t, err)
		if !errors.Is(err, journal.ErrSequenceGap) {
			t.Errorf("errors.Is(_, journal.ErrSequenceGap) = false, err = %v", err)
		}
		want := journal.RefuseSequenceGap(fixtureRepoStream, 2, 3)
		if err.Error() != want.Error() {
			t.Errorf("err = %q, want %q", err.Error(), want.Error())
		}
	})

	t.Run("ref transaction signature mismatch (rule 3)", func(t *testing.T) {
		src := newFixtureSource(t)
		key := journal.TxKey(fixtureRepoStream, 4)
		data, err := os.ReadFile(fixtureKeyPath(key))
		if err != nil {
			t.Fatalf("failed to read fixture: %v", err)
		}
		src.set(key, flipSignature(t, data))
		chain := loadFixtureChain(t, fixtureMetaHeadSeq)

		plan, err := journal.NewReader(src).PlanStream(context.Background(), chain, fixtureRepoStream)
		if plan != nil {
			t.Errorf("plan = %+v, want nil", plan)
		}
		oneLine(t, err)
		if !errors.Is(err, journal.ErrSignatureMismatch) {
			t.Errorf("errors.Is(_, journal.ErrSignatureMismatch) = false, err = %v", err)
		}
		want := journal.RefuseRefTxSignatureMismatch(fixtureRepoStream, 4)
		if err.Error() != want.Error() {
			t.Errorf("err = %q, want %q", err.Error(), want.Error())
		}
	})

	t.Run("marker signature mismatch (rule 16)", func(t *testing.T) {
		src := newFixtureSource(t)
		key := journal.MarkerKey(fixtureRepoStream)
		data, err := os.ReadFile(fixtureKeyPath(key))
		if err != nil {
			t.Fatalf("failed to read fixture: %v", err)
		}
		src.set(key, flipSignature(t, data))
		chain := loadFixtureChain(t, fixtureMetaHeadSeq)

		plan, err := journal.NewReader(src).PlanStream(context.Background(), chain, fixtureRepoStream)
		if plan != nil {
			t.Errorf("plan = %+v, want nil", plan)
		}
		oneLine(t, err)
		if !errors.Is(err, journal.ErrSignatureMismatch) {
			t.Errorf("errors.Is(_, journal.ErrSignatureMismatch) = false, err = %v", err)
		}
		want := journal.RefuseMarkerSignatureMismatch(fixtureRepoStream, 3)
		if err.Error() != want.Error() {
			t.Errorf("err = %q, want %q", err.Error(), want.Error())
		}
	})

	t.Run("marker names unknown key epoch (rule 17)", func(t *testing.T) {
		src := newFixtureSource(t)
		key := journal.MarkerKey(fixtureRepoStream)
		data, err := os.ReadFile(fixtureKeyPath(key))
		if err != nil {
			t.Fatalf("failed to read fixture: %v", err)
		}
		// The chain replayed to fixtureMetaHeadSeq holds two keys (epoch
		// 0, the genesis key, and epoch 1, after the one rotation): epoch
		// 2 names no key in it.
		src.set(key, mutateField(t, data, "key_epoch", "2"))
		chain := loadFixtureChain(t, fixtureMetaHeadSeq)

		plan, err := journal.NewReader(src).PlanStream(context.Background(), chain, fixtureRepoStream)
		if plan != nil {
			t.Errorf("plan = %+v, want nil", plan)
		}
		oneLine(t, err)
		if !errors.Is(err, journal.ErrUnknownKeyEpoch) {
			t.Errorf("errors.Is(_, journal.ErrUnknownKeyEpoch) = false, err = %v", err)
		}
		want := journal.RefuseMarkerUnknownKeyEpoch(fixtureRepoStream, 2)
		if err.Error() != want.Error() {
			t.Errorf("err = %q, want %q", err.Error(), want.Error())
		}
	})

	t.Run("key epoch regression (rule 15)", func(t *testing.T) {
		// repo-alpha's marker carries key_epoch_floor 1: seq 4, originally
		// signed at epoch 1, is rewritten to claim epoch 0. The chain's
		// regression check (VerifyRefTx, called after VerifyMarker has
		// already seeded the floor at 1) refuses this before it ever gets
		// to the now-stale signature, so the record is not re-signed.
		src := newFixtureSource(t)
		key := journal.TxKey(fixtureRepoStream, 4)
		data, err := os.ReadFile(fixtureKeyPath(key))
		if err != nil {
			t.Fatalf("failed to read fixture: %v", err)
		}
		src.set(key, mutateField(t, data, "key_epoch", "0"))
		chain := loadFixtureChain(t, fixtureMetaHeadSeq)

		plan, err := journal.NewReader(src).PlanStream(context.Background(), chain, fixtureRepoStream)
		if plan != nil {
			t.Errorf("plan = %+v, want nil", plan)
		}
		oneLine(t, err)
		if !errors.Is(err, journal.ErrKeyEpochRegression) {
			t.Errorf("errors.Is(_, journal.ErrKeyEpochRegression) = false, err = %v", err)
		}
		want := journal.RefuseKeyEpochRegression(fixtureRepoStream, 4, 0, 1)
		if err.Error() != want.Error() {
			t.Errorf("err = %q, want %q", err.Error(), want.Error())
		}
	})

	t.Run("unknown key epoch (rule 14)", func(t *testing.T) {
		// Same record, rewritten to name an epoch the chain has never
		// heard of at all; KeyAtEpoch fails before the regression check
		// or the signature is ever consulted, so again no re-signing.
		src := newFixtureSource(t)
		key := journal.TxKey(fixtureRepoStream, 4)
		data, err := os.ReadFile(fixtureKeyPath(key))
		if err != nil {
			t.Fatalf("failed to read fixture: %v", err)
		}
		src.set(key, mutateField(t, data, "key_epoch", "9"))
		chain := loadFixtureChain(t, fixtureMetaHeadSeq)

		plan, err := journal.NewReader(src).PlanStream(context.Background(), chain, fixtureRepoStream)
		if plan != nil {
			t.Errorf("plan = %+v, want nil", plan)
		}
		oneLine(t, err)
		if !errors.Is(err, journal.ErrUnknownKeyEpoch) {
			t.Errorf("errors.Is(_, journal.ErrUnknownKeyEpoch) = false, err = %v", err)
		}
		want := journal.RefuseUnknownKeyEpoch(fixtureRepoStream, 4, 9)
		if err.Error() != want.Error() {
			t.Errorf("err = %q, want %q", err.Error(), want.Error())
		}
	})

	t.Run("corrupt marker (section 7.6 rule 4 / 8.1 rule 5)", func(t *testing.T) {
		src := newFixtureSource(t)
		src.set(journal.MarkerKey(fixtureRepoStream), []byte("{not valid json"))
		chain := loadFixtureChain(t, fixtureMetaHeadSeq)

		plan, err := journal.NewReader(src).PlanStream(context.Background(), chain, fixtureRepoStream)
		if plan != nil {
			t.Errorf("plan = %+v, want nil", plan)
		}
		oneLine(t, err)
		if !errors.Is(err, journal.ErrCorruptMarker) {
			t.Errorf("errors.Is(_, journal.ErrCorruptMarker) = false, err = %v", err)
		}
		const wantPrefix = "refusal: replay failed: corrupt marker on stream repo-alpha ("
		const wantSuffix = ") (marker.json in object storage is malformed)"
		if !strings.HasPrefix(err.Error(), wantPrefix) || !strings.HasSuffix(err.Error(), wantSuffix) {
			t.Errorf("err = %q, want prefix %q and suffix %q", err.Error(), wantPrefix, wantSuffix)
		}
	})

	t.Run("invalid marker: missing required field", func(t *testing.T) {
		src := newFixtureSource(t)
		key := journal.MarkerKey(fixtureRepoStream)
		data, err := os.ReadFile(fixtureKeyPath(key))
		if err != nil {
			t.Fatalf("failed to read fixture: %v", err)
		}
		src.set(key, dropField(t, data, "key_epoch_floor"))
		chain := loadFixtureChain(t, fixtureMetaHeadSeq)

		plan, err := journal.NewReader(src).PlanStream(context.Background(), chain, fixtureRepoStream)
		if plan != nil {
			t.Errorf("plan = %+v, want nil", plan)
		}
		oneLine(t, err)
		if !errors.Is(err, journal.ErrInvalidMarker) {
			t.Errorf("errors.Is(_, journal.ErrInvalidMarker) = false, err = %v", err)
		}
		const wantPrefix = "refusal: replay failed: invalid marker on stream repo-alpha ("
		const wantSuffix = ") (marker.json in object storage is invalid)"
		if !strings.HasPrefix(err.Error(), wantPrefix) || !strings.HasSuffix(err.Error(), wantSuffix) {
			t.Errorf("err = %q, want prefix %q and suffix %q", err.Error(), wantPrefix, wantSuffix)
		}
		if !strings.Contains(err.Error(), "key_epoch_floor") {
			t.Errorf("err = %q, want it to name the missing field", err.Error())
		}
	})
}

// TestPlanStreamRejectsUnknownStream covers PlanStream's own stream-id
// validation, the same guard every other entry point in this package
// applies before touching storage.
func TestPlanStreamRejectsUnknownStream(t *testing.T) {
	src := newFixtureSource(t)
	chain := loadFixtureChain(t, fixtureMetaHeadSeq)
	_, err := journal.NewReader(src).PlanStream(context.Background(), chain, "not a valid stream id")
	if !errors.Is(err, journal.ErrInvalidStream) {
		t.Errorf("errors.Is(_, journal.ErrInvalidStream) = false, err = %v", err)
	}
}

// TestPlanStreamRefusesRecordSeqDisagreeingWithKey is round-1 review's
// first major finding on this file: a record is never checked against the
// key it was found at, so a misfiled record yields a wrong, signature-
// verified plan with a nil error. This reproduces it exactly as reported -
// marker.json removed and tx/00000000000000000002.json's bytes copied
// verbatim onto tx/00000000000000000003.json's key - and pins that
// PlanStream now refuses rather than silently replaying seq 2 a second
// time under seq 3's key and dropping repo-alpha's real seq-3 force-push.
func TestPlanStreamRefusesRecordSeqDisagreeingWithKey(t *testing.T) {
	src := newFixtureSource(t)
	src.delete(journal.MarkerKey(fixtureRepoStream))

	seq2Key := journal.TxKey(fixtureRepoStream, 2)
	seq2Data, err := os.ReadFile(fixtureKeyPath(seq2Key))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	seq3Key := journal.TxKey(fixtureRepoStream, 3)
	src.set(seq3Key, seq2Data)

	chain := loadFixtureChain(t, fixtureMetaHeadSeq)
	plan, err := journal.NewReader(src).PlanStream(context.Background(), chain, fixtureRepoStream)
	if plan != nil {
		t.Errorf("plan = %+v, want nil (not a 5-transaction plan that replays seq 2 twice)", plan)
	}
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if strings.Count(err.Error(), "\n") != 0 {
		t.Errorf("refusal is not one line: %q", err.Error())
	}
	if !errors.Is(err, journal.ErrRefTxKeySeqMismatch) {
		t.Errorf("errors.Is(_, journal.ErrRefTxKeySeqMismatch) = false, err = %v", err)
	}
	want := journal.RefuseRefTxKeySeqMismatch(fixtureRepoStream, 3, 2)
	if err.Error() != want.Error() {
		t.Errorf("err = %q, want %q", err.Error(), want.Error())
	}
}

// TestPlanStreamRefusesRecordFromAnotherStream is round-1 review's second
// major finding: rec.Stream is never checked against the stream being
// planned, so a genuine record from another stream, filed under this
// one's tx/ prefix, verifies (chain.VerifyRefTx builds its payload from
// the record's own Stream field) and is silently accepted - raising the
// chain's rule-15 epoch floor on the wrong stream in the process. This
// reproduces it exactly as reported: repo-alpha's marker and every tx/
// entry cleared, and the opaque stream's genuinely signed seq-0 record
// planted at repo-alpha/tx/00000000000000000000.json.
func TestPlanStreamRefusesRecordFromAnotherStream(t *testing.T) {
	src := newFixtureSource(t)
	src.delete(journal.MarkerKey(fixtureRepoStream))
	for seq := journal.Seq(0); seq <= 4; seq++ {
		src.delete(journal.TxKey(fixtureRepoStream, seq))
	}

	opaqueSeq0Key := journal.TxKey(fixtureOpaqueStream, 0)
	opaqueSeq0Data, err := os.ReadFile(fixtureKeyPath(opaqueSeq0Key))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	src.set(journal.TxKey(fixtureRepoStream, 0), opaqueSeq0Data)

	chain := loadFixtureChain(t, fixtureMetaHeadSeq)
	plan, err := journal.NewReader(src).PlanStream(context.Background(), chain, fixtureRepoStream)
	if plan != nil {
		t.Errorf("plan = %+v, want nil (not a 1-transaction plan planting another stream's ref update onto this one)", plan)
	}
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if strings.Count(err.Error(), "\n") != 0 {
		t.Errorf("refusal is not one line: %q", err.Error())
	}
	if !errors.Is(err, journal.ErrRefTxStreamMismatch) {
		t.Errorf("errors.Is(_, journal.ErrRefTxStreamMismatch) = false, err = %v", err)
	}
	want := journal.RefuseRefTxStreamMismatch(fixtureRepoStream, 0, fixtureOpaqueStream)
	if err.Error() != want.Error() {
		t.Errorf("err = %q, want %q", err.Error(), want.Error())
	}
}

// TestPlanStreamRefusesMalformedRecordBody is round-2 review's minor
// finding: a corrupt or malformed tx/<seq>.json record body was the one
// branch in this walk that did not locate its failure - ParseRefTx's raw,
// unlocated error propagated straight up, naming no stream, no seq, and no
// key, unlike every sibling refusal in this function (the malformed-key
// branch two lines above it, RefuseSequenceGap, RefuseRefTxSignatureMismatch,
// and this round's own RefuseRefTxKeySeqMismatch/RefuseRefTxStreamMismatch
// checks). This reproduces it with a tx/ object missing a required field -
// "signature" dropped from otherwise-untouched fixture bytes at seq 4 -
// and pins that PlanStream now refuses with a located, one-line
// RefuseRefTxMalformed line naming the object, rather than ParseRefTx's
// bare, unlocated error text.
func TestPlanStreamRefusesMalformedRecordBody(t *testing.T) {
	src := newFixtureSource(t)
	key := journal.TxKey(fixtureRepoStream, 4)
	data, err := os.ReadFile(fixtureKeyPath(key))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	mutated := dropField(t, data, "signature")
	src.set(key, mutated)

	chain := loadFixtureChain(t, fixtureMetaHeadSeq)
	plan, err := journal.NewReader(src).PlanStream(context.Background(), chain, fixtureRepoStream)
	if plan != nil {
		t.Errorf("plan = %+v, want nil (not a plan built from an unparseable record)", plan)
	}
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if strings.Count(err.Error(), "\n") != 0 {
		t.Errorf("refusal is not one line: %q", err.Error())
	}
	if !errors.Is(err, journal.ErrInvalidRefTx) {
		t.Errorf("errors.Is(_, journal.ErrInvalidRefTx) = false, err = %v", err)
	}
	if !strings.Contains(err.Error(), key) {
		t.Errorf("refusal does not name the malformed object's key %q: %q", key, err.Error())
	}
	if strings.Contains(err.Error(), "invalid ref transaction record: invalid ref transaction record") {
		t.Errorf("refusal still carries ParseRefTx's doubled ErrInvalidRefTx prefix: %q", err.Error())
	}

	_, perr := journal.ParseRefTx(mutated)
	if perr == nil {
		t.Fatal("expected ParseRefTx to fail on a record missing its signature field")
	}
	want := journal.RefuseRefTxMalformed(fixtureRepoStream, 4, perr)
	if err.Error() != want.Error() {
		t.Errorf("err = %q, want %q", err.Error(), want.Error())
	}
}
