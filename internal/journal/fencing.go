package journal

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/writtendev/walden/internal/refusal"
)

var (
	// ErrStreamFenced indicates that a stream is permanently fenced on this process instance.
	ErrStreamFenced = errors.New("stream is permanently fenced on this instance")

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
)

// RefuseStreamFenced returns a single-line operator-facing refusal when a writer is fenced out by a conflict.
func RefuseStreamFenced(stream StreamID, seq uint64) error {
	if stream == MetaStreamID {
		return refusal.Refuse(
			"refusal: meta operation failed",
			fmt.Sprintf("stream %s fenced by concurrent writer at seq %d", stream, seq),
			"instance is fenced for this stream; restart or check active writer",
		)
	}
	return refusal.Refuse(
		"refusal: push failed",
		fmt.Sprintf("stream %s fenced by concurrent writer at seq %d", stream, seq),
		"instance is fenced for this stream; restart or check active writer",
	)
}

// RefusePermanentlyFenced returns a single-line operator-facing refusal when a write is attempted on a fenced stream.
func RefusePermanentlyFenced(stream StreamID) error {
	if stream == MetaStreamID {
		return refusal.Refuse(
			"refusal: meta operation failed",
			fmt.Sprintf("stream %s is permanently fenced on this instance", stream),
			"restart walden process to re-materialize from journal",
		)
	}
	return refusal.Refuse(
		"refusal: push failed",
		fmt.Sprintf("stream %s is permanently fenced on this instance", stream),
		"restart walden process to re-materialize from journal",
	)
}

// RefuseCASNotSupported returns a single-line operator-facing refusal when the storage provider does not support CAS.
func RefuseCASNotSupported() error {
	return refusal.Refuse(
		"refusal: journal append failed",
		"storage provider does not support compare-and-swap (CAS) conditional writes",
		"verify bucket provider compatibility in spec",
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

// ProviderStatus indicates the level of CAS support by an S3-compatible storage provider.
type ProviderStatus string

const (
	// ProviderSupported indicates full native support for conditional PUT and HTTP 412 rejection.
	ProviderSupported ProviderStatus = "Supported"

	// ProviderUnsupported indicates lack of atomic conditional PUT evaluation (incompatible).
	ProviderUnsupported ProviderStatus = "Unsupported"

	// ProviderConditional indicates that support depends on proxy/gateway configuration or version.
	ProviderConditional ProviderStatus = "Conditional"
)

// ProviderInfo documents the CAS capabilities and configuration of a storage provider.
type ProviderInfo struct {
	Name           string         `json:"name"`
	Aliases        []string       `json:"aliases,omitempty"`
	Header         string         `json:"header"`
	ConflictStatus int            `json:"conflict_status"`
	Status         ProviderStatus `json:"status"`
	Notes          string         `json:"notes"`
}

// ProviderSupportMatrix contains the verified CAS support specifications across major providers.
var ProviderSupportMatrix = []ProviderInfo{
	{
		Name:           "AWS S3",
		Aliases:        []string{"S3", "Amazon S3", "aws"},
		Header:         "If-None-Match: *",
		ConflictStatus: http.StatusPreconditionFailed,
		Status:         ProviderSupported,
		Notes:          "Native conditional PUT support launched in August 2024. Strong read-after-write consistency and atomic evaluation across all standard AWS regions.",
	},
	{
		Name:           "Cloudflare R2",
		Aliases:        []string{"R2", "Cloudflare"},
		Header:         "If-None-Match: *",
		ConflictStatus: http.StatusPreconditionFailed,
		Status:         ProviderSupported,
		Notes:          "Full native support for S3 conditional operations (If-None-Match: *) on object PUT with atomic 412 rejection.",
	},
	{
		Name:           "Google Cloud Storage",
		Aliases:        []string{"GCS", "Google Cloud", "gcs"},
		Header:         "If-None-Match: *",
		ConflictStatus: http.StatusPreconditionFailed,
		Status:         ProviderSupported,
		Notes:          "Supported via GCS S3 XML API. GCS evaluates If-None-Match: * against object generation 0, returning 412 on conflict.",
	},
	{
		Name:           "MinIO",
		Aliases:        []string{"minio"},
		Header:         "If-None-Match: *",
		ConflictStatus: http.StatusPreconditionFailed,
		Status:         ProviderSupported,
		Notes:          "Supported in modern releases (RELEASE.2023+). Atomic precondition checking is coordinated across distributed erasure sets.",
	},
	{
		Name:           "Ceph RGW",
		Aliases:        []string{"Ceph", "RGW", "RadosGW"},
		Header:         "If-None-Match: *",
		ConflictStatus: http.StatusPreconditionFailed,
		Status:         ProviderSupported,
		Notes:          "Supported in Ceph Quincy (v17.2+), Reef (v18.2+), and Squid (v19.2+). Earlier releases (e.g. Pacific, Nautilus) lack S3 conditional write support.",
	},
	{
		Name:           "Backblaze B2",
		Aliases:        []string{"B2", "Backblaze"},
		Header:         "If-None-Match: *",
		ConflictStatus: http.StatusPreconditionFailed,
		Status:         ProviderSupported,
		Notes:          "Supported on S3-compatible endpoints for conditional object PUT.",
	},
	{
		Name:           "Garage S3",
		Aliases:        []string{"Garage", "garage-s3"},
		Header:         "If-None-Match: *",
		ConflictStatus: http.StatusPreconditionFailed,
		Status:         ProviderSupported,
		Notes:          "Supported in modern Garage releases (v0.9+) with distributed CAS coordination.",
	},
	{
		Name:           "Wasabi",
		Aliases:        []string{"wasabi-cloud"},
		Header:         "If-None-Match: *",
		ConflictStatus: 0,
		Status:         ProviderUnsupported,
		Notes:          "Does not reliably evaluate If-None-Match: * atomically on object PUT; may overwrite existing objects without returning 412. Incompatible with walden v1.",
	},
	{
		Name:           "Azure Blob Storage",
		Aliases:        []string{"Azure", "Azure Blob", "azure-blob"},
		Header:         "If-None-Match: *",
		ConflictStatus: http.StatusPreconditionFailed,
		Status:         ProviderConditional,
		Notes:          "Native Azure Blob REST API supports conditional writes. S3 gateway proxies must faithfully translate If-None-Match: * to Azure headers and propagate 412 status.",
	},
}

// LookupProvider returns provider support info matching provider name (case-insensitive exact or substring match against name and aliases).
func LookupProvider(name string) (ProviderInfo, bool) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return ProviderInfo{}, false
	}
	// 1. Exact match against Name or Aliases
	for _, p := range ProviderSupportMatrix {
		if strings.EqualFold(p.Name, trimmed) {
			return p, true
		}
		for _, alias := range p.Aliases {
			if strings.EqualFold(alias, trimmed) {
				return p, true
			}
		}
	}
	// 2. Case-insensitive substring match
	lower := strings.ToLower(trimmed)
	for _, p := range ProviderSupportMatrix {
		if strings.Contains(strings.ToLower(p.Name), lower) {
			return p, true
		}
		for _, alias := range p.Aliases {
			if strings.Contains(strings.ToLower(alias), lower) {
				return p, true
			}
		}
	}
	return ProviderInfo{}, false
}

// ValidateProviderCAS validates that a named provider supports CAS conditional writes.
func ValidateProviderCAS(name string) error {
	info, ok := LookupProvider(name)
	if !ok {
		// Unknown provider cannot be verified to support CAS
		return RefuseCASNotSupported()
	}
	if info.Status == ProviderUnsupported {
		return RefuseCASNotSupported()
	}
	return nil
}
