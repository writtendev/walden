package journal

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"

	"github.com/writtendev/walden/internal/refusal"
)

var (
	// ErrStreamFenced indicates that a stream is permanently fenced on this process instance.
	// It is unified with ErrFenced for contract consistency across the journal package.
	ErrStreamFenced = ErrFenced

	// ErrCASNotSupported indicates that the object storage provider lacks compare-and-swap (CAS) support.
	ErrCASNotSupported = errors.New("storage provider does not support compare-and-swap (CAS) conditional writes")

	// ErrPreconditionFailed indicates that an HTTP 412 Precondition Failed was received.
	ErrPreconditionFailed = errors.New("conditional write precondition failed (HTTP 412)")
)

const (
	// HeaderIfNoneMatch is the HTTP header key for conditional write preconditions.
	HeaderIfNoneMatch = "If-None-Match"

	// IfNoneMatchWildcard is the wildcard precondition value matching any existing entity.
	IfNoneMatchWildcard = "*"

	// StatusPreconditionFailed is the standard HTTP status code for conditional write conflict.
	StatusPreconditionFailed = http.StatusPreconditionFailed

	// codePreconditionFailed is the S3 error code returned alongside HTTP 412 on a
	// conditional write conflict, as required of every supported provider in the
	// support matrix of spec/journal/v1/README.md section 11.2. It is unexported
	// because nothing outside this package reads it: what is published is the code
	// itself, in the specification and in conditional_append.json.
	codePreconditionFailed = "PreconditionFailed"
)

// RefuseStreamFenced returns a single-line operator-facing refusal when a writer is fenced out by a conflict.
func RefuseStreamFenced(stream StreamID, seq uint64) error {
	if stream == MetaStreamID {
		return refusal.RefuseWithCause(
			"refusal: meta operation failed",
			fmt.Sprintf("stream %s fenced by concurrent writer at seq %d", stream, seq),
			"instance is fenced for this stream; restart or check active writer",
			ErrFenced,
		)
	}
	return refusal.RefuseWithCause(
		"refusal: push failed",
		fmt.Sprintf("stream %s fenced by concurrent writer at seq %d", stream, seq),
		"instance is fenced for this stream; restart or check active writer",
		ErrFenced,
	)
}

// RefusePermanentlyFenced returns a single-line operator-facing refusal when a write is attempted on a fenced stream.
func RefusePermanentlyFenced(stream StreamID) error {
	if stream == MetaStreamID {
		return refusal.RefuseWithCause(
			"refusal: meta operation failed",
			fmt.Sprintf("stream %s is permanently fenced on this instance", stream),
			"restart walden process to re-materialize from journal",
			ErrFenced,
		)
	}
	return refusal.RefuseWithCause(
		"refusal: push failed",
		fmt.Sprintf("stream %s is permanently fenced on this instance", stream),
		"restart walden process to re-materialize from journal",
		ErrFenced,
	)
}

// RefuseCASNotSupported returns a single-line operator-facing refusal when the storage provider does not support CAS.
func RefuseCASNotSupported() error {
	return refusal.RefuseWithCause(
		"refusal: journal append failed",
		"storage provider does not support compare-and-swap (CAS) conditional writes",
		"verify bucket provider compatibility in spec",
		ErrCASNotSupported,
	)
}

// Fencer tracks single-writer per-stream fencing state in-memory on a walden instance.
// When a writer receives HTTP 412 Precondition Failed during a conditional write to tx/<seq>.json,
// the stream permanently transitions to fenced on this instance.
// Fencing is strictly isolated per stream: fencing stream A leaves stream B and _meta unaffected.
type Fencer struct {
	mu     sync.RWMutex
	fenced map[StreamID]uint64
}

// NewFencer creates an empty Fencer tracker.
func NewFencer() *Fencer {
	return &Fencer{
		fenced: make(map[StreamID]uint64),
	}
}

// IsFenced returns true if the stream is currently fenced on this instance.
func (f *Fencer) IsFenced(stream StreamID) bool {
	if f == nil {
		return false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, ok := f.fenced[stream]
	return ok
}

// FenceStream permanently marks a stream as fenced on this instance at the given sequence.
func (f *Fencer) FenceStream(stream StreamID, seq uint64) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.fenced[stream]; !exists {
		f.fenced[stream] = seq
	}
}

// FencedSeq returns the sequence number that caused the stream to be fenced, if fenced.
func (f *Fencer) FencedSeq(stream StreamID) (uint64, bool) {
	if f == nil {
		return 0, false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	seq, ok := f.fenced[stream]
	return seq, ok
}

// FencedStreams returns a sorted list of all stream IDs currently fenced on this instance.
func (f *Fencer) FencedStreams() []StreamID {
	if f == nil {
		return nil
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	streams := make([]StreamID, 0, len(f.fenced))
	for s := range f.fenced {
		streams = append(streams, s)
	}
	sort.Slice(streams, func(i, j int) bool {
		return streams[i] < streams[j]
	})
	return streams
}

// CheckWritable verifies that the stream is not fenced. If fenced, it returns RefusePermanentlyFenced.
func (f *Fencer) CheckWritable(stream StreamID) error {
	if f.IsFenced(stream) {
		return RefusePermanentlyFenced(stream)
	}
	return nil
}

// HandleConflict transitions the stream to fenced at sequence seq and returns RefuseStreamFenced.
func (f *Fencer) HandleConflict(stream StreamID, seq uint64) error {
	f.FenceStream(stream, seq)
	return RefuseStreamFenced(stream, seq)
}

// Reset clears all fenced streams. Used primarily in test suites.
func (f *Fencer) Reset() {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fenced = make(map[StreamID]uint64)
}
