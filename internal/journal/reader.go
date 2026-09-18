// This file is the read side of spec/journal/v1 section 8 step 3: turning
// one repository stream's storage listing into a verified, ordered Plan
// (plan.go) — snapshot, then each transaction's segments, then that
// transaction's ref updates, signatures verified from genesis forward
// against the *SigningChain the caller supplies. Steps 1-2 (replaying
// _meta into that chain) are WALD-31's, not this file's: PlanStream takes
// a chain as a parameter and never reads _meta itself.
//
// PlanStream deliberately does not fetch or hash pack bytes. Doing so
// would mean holding every referenced packfile in memory to compute its
// SHA-256 before the plan could even be returned - exactly what WALD-58's
// bounded-memory executor exists to avoid. A Plan only names keys and
// expected hashes; WALD-58 streams and verifies them as it applies each
// step.
package journal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/writtendev/walden/internal/refusal"
)

// streamsPrefix is the storage prefix every repository stream (and _meta)
// lives under (spec section 9.2). It deliberately does not reach the boot
// probe's v1/probe/<hex> key (section 9.2's closing note): a List scoped
// to this prefix never sees it.
const streamsPrefix = VersionPrefix + "/streams/"

// ObjectSource is the whole storage surface (*Reader) needs: TxLister's
// paginated List (declared in lease.go for WALD-29's (*Leases).Open, and
// not restated here - see the file comment there) plus Get, for fetching
// individual objects (marker.json, tx/<seq>.json). *store.Client satisfies
// this interface as it stands, with no import needed on either side: this
// package must not import store (store imports journal), so ObjectSource
// is declared here in terms of the method set alone.
type ObjectSource interface {
	TxLister
	Get(ctx context.Context, key string) (io.ReadCloser, error)
}

// Reader turns an ObjectSource's storage listing into verified replay
// plans. It holds no state of its own beyond the source it reads
// from - all per-replay state (the epoch floor a chain of VerifyRefTx
// calls advances) lives on the *SigningChain the caller passes to each
// PlanStream call, not on the Reader.
type Reader struct {
	src ObjectSource
}

// NewReader builds a Reader over src.
func NewReader(src ObjectSource) *Reader {
	return &Reader{src: src}
}

// Streams lists every repository stream the bucket holds: the distinct
// first path segment under v1/streams/, excluding _meta by name (spec
// section 9.1: it matches the same stream-id pattern a repository stream
// does, and section 8 step 2 already replays it in full, so step 3 - what
// this file implements - must not try to verify it as a ref-transaction
// stream and fail on the first record). A segment that does not itself
// validate as a stream ID is ignored rather than refused: Streams only
// discovers what to plan, and an unparseable stray key under v1/streams/
// is PlanStream's problem, if it is anyone's, not a reason to abort
// discovery of every other stream in the bucket.
func (r *Reader) Streams(ctx context.Context) ([]StreamID, error) {
	seen := make(map[StreamID]bool)
	var streams []StreamID

	err := r.src.List(ctx, streamsPrefix, "", func(key string) error {
		rest, ok := strings.CutPrefix(key, streamsPrefix)
		if !ok {
			return nil
		}
		idx := strings.IndexByte(rest, '/')
		if idx <= 0 {
			return nil
		}
		id := StreamID(rest[:idx])
		if id == MetaStreamID || seen[id] {
			return nil
		}
		if err := ValidateStreamID(id); err != nil {
			return nil
		}
		seen[id] = true
		streams = append(streams, id)
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(streams, func(i, j int) bool { return streams[i] < streams[j] })
	return streams, nil
}

// PlanStream resolves stream's replay marker (or starts at sequence 0),
// lists its tx/ transactions with start-after, asserts strictly
// contiguous sequences, and verifies every record's Ed25519 signature
// against the key its own key_epoch names in chain - spec section 7.5 and
// section 8 step 3, restated as a data structure instead of an in-place
// materialization.
//
// chain carries the state of one replay and is not safe for concurrent
// use: VerifyRefTx and VerifyMarker mutate its per-stream epoch floor, so
// planning several streams means planning them serially on one chain, one
// PlanStream call at a time, never from more than one goroutine.
func (r *Reader) PlanStream(ctx context.Context, chain *SigningChain, stream StreamID) (*Plan, error) {
	if err := ValidateStreamID(stream); err != nil {
		return nil, err
	}

	plan := &Plan{Stream: stream}

	markerBody, err := r.src.Get(ctx, MarkerKey(stream))
	switch {
	case err == nil:
		data, rerr := io.ReadAll(markerBody)
		closeErr := markerBody.Close()
		if rerr != nil {
			return nil, rerr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		marker, perr := ParseMarker(data)
		if perr != nil {
			switch {
			case errors.Is(perr, ErrCorruptMarker):
				return nil, RefuseCorruptMarker(stream, perr)
			case errors.Is(perr, ErrInvalidMarker):
				return nil, RefuseInvalidMarker(stream, perr)
			default:
				return nil, perr
			}
		}
		// spec section 7.5 step 2: "stream == <stream-id>" is asserted as
		// part of parsing the marker structure, before its signature is
		// even checked - a marker naming the wrong stream is invalid
		// regardless of whether it is genuinely signed.
		if marker.Stream != stream {
			return nil, RefuseInvalidMarker(stream, fmt.Errorf("%w: marker stream %q does not match stream %q", ErrInvalidMarker, marker.Stream, stream))
		}
		// Verify the marker's signature - and, on success, seed chain's
		// per-stream epoch floor from marker.key_epoch_floor - before
		// trusting any other field on it (section 7.5 step 3).
		if err := chain.VerifyMarker(marker); err != nil {
			return nil, err
		}
		baseline := marker.Sequence
		plan.Baseline = &baseline
		plan.Snapshot = &SnapshotStep{
			Key:    SnapshotKey(stream, marker.Snapshot),
			SHA256: marker.Snapshot,
		}
		// The marker's ref set exactly, with nothing merged into it: it
		// is authoritative, not a delta (section 7.2).
		plan.Refs = marker.Refs
	case errors.Is(err, ErrObjectNotFound):
		// Ordinary genesis path (section 7.5 step 2 "Marker Absent"):
		// Baseline stays nil, Snapshot stays nil, Refs stays empty.
	default:
		return nil, err
	}

	expected := Seq(0)
	startAfter := ""
	if plan.Baseline != nil {
		expected = *plan.Baseline + 1
		startAfter = TxKey(stream, *plan.Baseline)
	}

	// List returns fn's own error unchanged, the moment fn returns one
	// (store.(*Client).List's own contract, restated in TxLister's doc
	// comment in lease.go) - so every branch below already returns a
	// properly formed refusal or a propagated error, and err below is
	// exactly that value, nothing List itself adds on top.
	prefix := TxPrefix(stream)
	err = r.src.List(ctx, prefix, startAfter, func(key string) error {
		seq, perr := parseTxSeq(prefix, key)
		if perr != nil {
			return refusal.RefuseWithCause(
				"refusal: replay failed",
				fmt.Sprintf("transaction key %q under tx/ does not parse: %s", key, perr.Error()),
				fmt.Sprintf("remove the malformed object at key %q from the bucket", key),
				perr,
			)
		}
		if seq != expected {
			return RefuseSequenceGap(stream, expected, seq)
		}

		txBody, gerr := r.src.Get(ctx, key)
		if gerr != nil {
			return gerr
		}
		raw, rerr := io.ReadAll(txBody)
		closeErr := txBody.Close()
		if rerr != nil {
			return rerr
		}
		if closeErr != nil {
			return closeErr
		}

		rec, perr := ParseRefTx(raw)
		if perr != nil {
			// A malformed or corrupt record body - bad JSON, a missing
			// required field, a well-formed document that still fails
			// Validate() (wrong "type", say) - is located the same way
			// the malformed-key branch immediately above locates a key
			// that does not parse at all, rather than surfaced as
			// ParseRefTx's own unlocated error: see RefuseRefTxMalformed
			// (reftx.go) for why section 8.1 has no published wording for
			// this failure.
			return RefuseRefTxMalformed(stream, seq, perr)
		}

		// spec section 1.1 rule 3: "a record's sequence MUST still equal
		// the sequence in its key." rec.Seq comes from the record body -
		// what chain.VerifyRefTx signs over - and seq above is parsed
		// from the object key this record was read from; nothing before
		// this line ever compares the two. Without this check a record's
		// bytes copied onto a different key still verify (the signature
		// is self-consistent) and replay as if they were genuinely found
		// at that key.
		if rec.Seq != seq {
			return RefuseRefTxKeySeqMismatch(stream, seq, rec.Seq)
		}
		// The same binding, on the stream half of the (stream-id, seq)
		// coordinate this format replays by (section 8 step 3): mirrors
		// the marker.Stream != stream check above (section 7.5 step 2),
		// worded the same way, so a record genuinely signed for another
		// stream but filed under this one's tx/ prefix gets the same
		// class of refusal an operator already gets for the marker's
		// version of this problem. chain.VerifyRefTx cannot catch this
		// either - it builds its canonical payload from rec.Stream, so a
		// record signed for stream B verifies perfectly when read out of
		// stream A's tx/.
		if rec.Stream != stream {
			return RefuseRefTxStreamMismatch(stream, seq, rec.Stream)
		}

		if verr := chain.VerifyRefTx(rec); verr != nil {
			if errors.Is(verr, ErrSignatureMismatch) {
				return RefuseRefTxSignatureMismatch(stream, seq)
			}
			// RefuseUnknownKeyEpoch (rule 14) and RefuseKeyEpochRegression
			// (rule 15) are already one-line refusals in chain.VerifyRefTx's
			// own published wording; pass them through unchanged.
			return verr
		}

		segments := make([]SegmentStep, len(rec.Segments))
		for i, hash := range rec.Segments {
			segments[i] = SegmentStep{Key: SegmentKey(stream, hash), SHA256: hash}
		}
		plan.Transactions = append(plan.Transactions, &PlannedTx{Record: rec, Segments: segments})

		expected = seq + 1
		return nil
	})
	if err != nil {
		return nil, err
	}

	return plan, nil
}
