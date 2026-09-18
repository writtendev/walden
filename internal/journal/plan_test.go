package journal_test

import (
	"testing"

	"github.com/writtendev/walden/internal/journal"
)

// TestPlanZeroValue pins the zero-value Plan's shape: no marker, no
// snapshot, no refs, no transactions — the same state PlanStream leaves a
// *Plan in in the "no marker" branch, and worth pinning on the type
// itself since a caller may build one by hand (a test fixture, say)
// without going through PlanStream at all.
func TestPlanZeroValue(t *testing.T) {
	var p journal.Plan
	if p.Baseline != nil {
		t.Errorf("zero-value Plan.Baseline = %v, want nil", p.Baseline)
	}
	if p.Snapshot != nil {
		t.Errorf("zero-value Plan.Snapshot = %+v, want nil", p.Snapshot)
	}
	if p.Refs != nil {
		t.Errorf("zero-value Plan.Refs = %+v, want nil", p.Refs)
	}
	if p.Transactions != nil {
		t.Errorf("zero-value Plan.Transactions = %+v, want nil", p.Transactions)
	}
}

// TestPlanBaselineDistinguishesAbsentFromSequenceZero is the reason
// Baseline is a *Seq rather than a Seq: a stream whose marker baseline
// genuinely is sequence 0 must read differently from a stream with no
// marker at all, and Seq alone (unsigned, no in-band "before zero" value)
// cannot tell the two apart.
func TestPlanBaselineDistinguishesAbsentFromSequenceZero(t *testing.T) {
	noMarker := journal.Plan{}
	if noMarker.Baseline != nil {
		t.Fatalf("Baseline = %v, want nil for a stream with no marker", noMarker.Baseline)
	}

	zero := journal.Seq(0)
	baselineZero := journal.Plan{Baseline: &zero}
	if baselineZero.Baseline == nil {
		t.Fatal("Baseline = nil, want a non-nil pointer to sequence 0")
	}
	if *baselineZero.Baseline != 0 {
		t.Errorf("*Baseline = %d, want 0", *baselineZero.Baseline)
	}
}

// TestPlannedTxSegmentStepsNameKeyAndHash covers plan.go's contract for
// PlannedTx.Segments: one SegmentStep per record segment, in record
// order, each naming the storage key to fetch and the SHA-256 its bytes
// must hash to — the two fields WALD-58's executor needs and nothing it
// has to re-derive.
func TestPlannedTxSegmentStepsNameKeyAndHash(t *testing.T) {
	const stream = journal.StreamID("repo-alpha")
	hashes := []string{
		"4a49646b96dbca4f1eb8699ef7cefdcae68fefc6ee7ae6305a3f25c7e1ef5638",
		"db89aeed94af475ae97ce5fe75618d404f017d23e0aa61ce1c7abd11707dbbab",
	}
	segments := make([]journal.SegmentStep, len(hashes))
	for i, h := range hashes {
		segments[i] = journal.SegmentStep{Key: journal.SegmentKey(stream, h), SHA256: h}
	}
	tx := &journal.PlannedTx{Segments: segments}

	for i, h := range hashes {
		if got := tx.Segments[i].SHA256; got != h {
			t.Errorf("Segments[%d].SHA256 = %q, want %q", i, got, h)
		}
		want := journal.SegmentKey(stream, h)
		if got := tx.Segments[i].Key; got != want {
			t.Errorf("Segments[%d].Key = %q, want %q", i, got, want)
		}
	}
}

// TestSnapshotStepNamesKeyAndHash mirrors
// TestPlannedTxSegmentStepsNameKeyAndHash for the one snapshot step a plan
// carries.
func TestSnapshotStepNamesKeyAndHash(t *testing.T) {
	const stream = journal.StreamID("repo-alpha")
	const hash = "cd04837137cbca78f87a66055eb1ec4a598842618fa6cdb126295c6cda9b6638"
	step := journal.SnapshotStep{Key: journal.SnapshotKey(stream, hash), SHA256: hash}

	if step.SHA256 != hash {
		t.Errorf("SHA256 = %q, want %q", step.SHA256, hash)
	}
	if want := journal.SnapshotKey(stream, hash); step.Key != want {
		t.Errorf("Key = %q, want %q", step.Key, want)
	}
}
