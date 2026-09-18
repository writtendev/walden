// This file defines the data (*Reader).PlanStream (reader.go) produces:
// an ordered, verified replay plan for one repository stream — spec
// section 8 step 3's output, and the boundary with WALD-58's executor.
// Nothing here fetches or hashes pack bytes; every step just names a
// storage key and the SHA-256 the bytes at that key must hash to, so the
// executor can stream and verify each one without this package ever
// holding a whole repository in memory.
package journal

// Plan is a verified, ordered replay plan for one repository stream:
// snapshot first (when the stream has a marker), then for each
// transaction, in sequence order, its segments before its ref updates —
// spec section 7.5 and section 8 step 3, in the order a materializer must
// apply them. Execution order is this struct's own field order: Snapshot,
// then Transactions in order, and within each PlannedTx its Segments
// before its Record's ref updates. Nothing in a Plan is a reference the
// consumer has to re-derive.
type Plan struct {
	// Stream is the stream this plan was built for.
	Stream StreamID

	// Baseline is the sequence the plan resumes replay after: the
	// marker's Sequence when Snapshot is set, or nil when the stream
	// carries no marker and replay begins at sequence 0 itself. It is a
	// *Seq, not a Seq, because Seq is unsigned and has no in-band value
	// for "before sequence 0" — the same absent-vs-zero discipline Seq's
	// own doc comment applies to JSON, applied here to the type instead.
	Baseline *Seq

	// Snapshot names the compaction snapshot pack to apply before any
	// transaction in Transactions, and the SHA-256 its bytes must hash
	// to. Nil when the stream carries no marker (spec section 7.5: "If
	// Marker Absent, ... Refs = {}").
	Snapshot *SnapshotStep

	// Refs is the ref set replay must start from before applying
	// Transactions: the marker's ref set exactly, with nothing merged
	// into it, when Snapshot is set; empty when it is not (spec section
	// 7.5 step 5 / step 3's "If Marker Absent" branch).
	Refs []MarkerRef

	// Transactions is every verified ref transaction after Baseline, in
	// ascending sequence order, with no gaps.
	Transactions []*PlannedTx
}

// PlannedTx is one verified ref transaction: its parsed, signature-checked
// record, plus one SegmentStep per segment it references, in the order the
// record itself lists them (spec section 5.1's segments array order).
type PlannedTx struct {
	// Record is the parsed, verified ref-transaction record. Its own
	// Updates field is the ref updates a materializer applies, after
	// fetching and verifying Segments — see Plan's doc comment for why
	// segments come first.
	Record *RefTransactionRecord

	// Segments is one step per hash in Record.Segments, in that same
	// order, naming the storage key to fetch and the SHA-256 the bytes
	// there must hash to.
	Segments []SegmentStep
}

// SnapshotStep names a compaction snapshot pack to fetch, by storage key,
// and the SHA-256 its bytes must hash to. Fetching and hashing it is
// WALD-58's job, not this package's: see reader.go's doc comment.
type SnapshotStep struct {
	Key    string
	SHA256 string
}

// SegmentStep names a pack segment to fetch, by storage key, and the
// SHA-256 its bytes must hash to. Fetching and hashing it is WALD-58's
// job, not this package's: see reader.go's doc comment.
type SegmentStep struct {
	Key    string
	SHA256 string
}
