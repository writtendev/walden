// This file adds walden's write path for pack segments (WALD-26,
// spec/journal/v1 section 6): one method that validates a packfile's
// framing, derives its SHA-256 content address, and PUTs the bytes
// verbatim and unconditionally to
// "v1/streams/<stream-id>/segments/<sha256>.pack" with the Content-Type and
// sidecar metadata headers section 6.5 requires.
//
// The append lives here, in store, rather than in journal: store already
// imports journal for every format helper this needs (hashing, header
// validation, key derivation, metadata), and the reverse import would be a
// cycle. (*Client).ProbeCAS in probe.go is the existing precedent for a
// spec section implemented store-side out of journal helpers.
package store

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
)

// AppendSegment validates pack (size bytes long, readable via ReadAt),
// derives its SHA-256 content address, and PUTs it verbatim and
// unconditionally to "v1/streams/<stream>/segments/<sha256>.pack"
// (spec/journal/v1 section 6.3), returning the 64-hex lowercase digest the
// caller's ref transaction will reference (WALD-27's input).
//
// The write is unconditional - no If-None-Match - per section 6.4: a
// repeated append of identical bytes must be a no-op success, never a
// conflict, since a crash between this call landing and the ref
// transaction that references it being acknowledged means the client
// simply retries the whole push and AppendSegment runs again. This is why
// nothing in client.go changes: c.do already retries an unconditional PUT
// like Put, and classify's existing rules apply unmodified.
//
// Every refusal below happens before any network call, in the order a
// caller's mistake is cheapest to catch: an invalid stream ID, then a
// packfile too short or with a bad header, then a computed byte count that
// disagrees with size (a short ReaderAt). journal.ErrInvalidStream and
// journal.ErrInvalidPackfile stay the stable sentinels errors.Is matches -
// AppendSegment introduces no new sentinel. It also does not reuse
// internal/journal/segment.go's RefuseMissingSegment and friends: those
// are reader-side ("refusal: replay failed", section 6.7), and section 6
// publishes no write-path refusal string for this to restate, so the
// refusal below states one in the refusal.Refusal shape instead, matching
// internal/journal/fencing.go's "refusal: push failed" convention for a
// write-path refusal.
func (c *Client) AppendSegment(ctx context.Context, stream journal.StreamID, pack io.ReaderAt, size int64) (string, error) {
	if err := journal.ValidateStreamID(stream); err != nil {
		return "", refuseAppendSegment(err)
	}

	if size < journal.PackfileMinSize {
		return "", refuseAppendSegment(fmt.Errorf("%w: size %d is less than minimum packfile size of %d bytes", journal.ErrInvalidPackfile, size, journal.PackfileMinSize))
	}

	var hdr [journal.PackfileMinSize]byte
	if n, err := pack.ReadAt(hdr[:], 0); n < len(hdr) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return "", refuseAppendSegment(fmt.Errorf("%w: could not read %d-byte header: %w", journal.ErrInvalidPackfile, len(hdr), err))
	}
	if err := journal.ValidatePackfileHeader(hdr[:]); err != nil {
		return "", refuseAppendSegment(err)
	}

	// The header bytes are read a second time here, as part of the whole
	// pack: ComputeSegmentHashFromReader hashes byte 0 through size, and
	// the digest and the byte count it proves reading both come from this
	// one pass, so the key AppendSegment derives and the bytes it uploads
	// can never disagree.
	hash, n, err := journal.ComputeSegmentHashFromReader(io.NewSectionReader(pack, 0, size))
	if err != nil {
		return "", refuseAppendSegment(fmt.Errorf("%w: %w", journal.ErrInvalidPackfile, err))
	}
	if n != size {
		return "", refuseAppendSegment(fmt.Errorf("%w: declared size %d but reader returned %d bytes", journal.ErrInvalidPackfile, size, n))
	}

	key := journal.SegmentKey(stream, hash)
	meta := journal.SegmentMetadata(stream, hash)
	header := http.Header{
		"Content-Type":           {journal.SegmentContentType()},
		journal.MetaHeaderStream: {meta[journal.MetaHeaderStream]},
		journal.MetaHeaderHash:   {meta[journal.MetaHeaderHash]},
	}

	resp, err := c.do(ctx, objectRequest{
		method: http.MethodPut,
		key:    key,
		body:   pack,
		size:   size,
		header: header,
	})
	if err != nil {
		return "", err
	}
	closeBody(resp)
	return hash, nil
}

// refuseAppendSegment wraps cause - a journal.ErrInvalidStream or
// journal.ErrInvalidPackfile raised while validating the caller's input,
// before any network call - in walden's one-line operator-facing refusal
// shape. cause.Error() is already a single, human-readable line (from
// journal.ValidateStreamID or journal.ValidatePackfileHeader, or built
// alongside this func for the two checks AppendSegment makes itself), so
// it is used as-is for why rather than restated.
func refuseAppendSegment(cause error) error {
	return refusal.RefuseWithCause("refusal: push failed", cause.Error(), "", cause)
}
