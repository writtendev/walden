// Package journal implements walden's append-only write-ahead log in object storage.
// Per ARCHITECTURE.md: "The journal is the design. Everything else is plumbing around it."
package journal

import (
	"context"
	"errors"
)

var (
	ErrFenced         = errors.New("fenced: stale writer condition failed")
	ErrStreamNotFound = errors.New("journal stream not found")
)

// StreamID uniquely identifies a journal stream (e.g. a repository or meta stream).
type StreamID string

// MetaStreamID is the reserved stream ID for configuration and token state.
const MetaStreamID StreamID = "_meta"

// RefUpdate represents a single ref transition (e.g., refs/heads/main: OldOID -> NewOID).
type RefUpdate struct {
	RefName string
	OldOID  string
	NewOID  string
}

// Journal represents the write-ahead append-only log interface.
type Journal interface {
	// AppendRefTx conditionally appends a ref transaction to the specified stream.
	AppendRefTx(ctx context.Context, stream StreamID, expectedSeq uint64, updates []RefUpdate) (uint64, error)
}
