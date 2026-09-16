// This file lists journal keys through S3's ListObjectsV2 continuation
// protocol (spec/journal/v1 §7.5, §12): one page at a time - at most 1000
// keys, the provider default, with no max-keys knob - calling the caller's
// fn for every key on a page before requesting the next, so a listing of
// any size holds at most one decoded page in memory. Every page goes
// through (*Client).do, WALD-20's signed request/bounded-retry helper (see
// client.go's file comment); List adds no sending, signing, or retry code
// of its own.
package store

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/writtendev/walden/internal/refusal"
)

// ErrListInconsistent marks a listing that broke the ListObjectsV2
// pagination contract: truncated with no continuation token, a
// continuation token that did not advance (or repeated one already seen),
// a key that is not strictly greater than the one before it (within a
// page or across pages), a returned key outside the requested prefix, or
// a key longer than S3 itself allows. spec/journal/v1 §10 promises
// listing order is replay order, and WALD-34's ordered replay depends on
// that holding, so a provider that breaks the contract gets a one-line
// refusal here rather than a spinning loop or a misordered listing handed
// upstream.
var ErrListInconsistent = errors.New("object storage listing is inconsistent")

const (
	// maxListPageBody bounds how much of a ListObjectsV2 page response
	// List will decode. S3's own defaults return at most 1000 keys of at
	// most 1024 bytes each - call it a few hundred bytes of XML overhead
	// per entry - so a page that needs more than this to decode indicates
	// a misbehaving provider, not a legitimate page; the ticket's one-page
	// memory bound should not depend entirely on the provider honoring
	// that default. Same spirit as maxErrorBody in client.go: a fixed
	// cap, not a knob.
	maxListPageBody = 8 << 20 // 8 MiB

	// maxKeyLength is S3's own limit on an object key. Checked
	// independently of maxListPageBody, since a single oversized key can
	// fit under the page-body cap and still not be a real S3 key.
	maxKeyLength = 1024

	// maxListPages bounds how many continuation tokens List will
	// remember and how many pages it will request before refusing. A
	// provider that alternates between a small set of tokens on empty
	// truncated pages would otherwise spin forever; tracking every token
	// already seen (see the seenTokens set below) catches a repeat
	// immediately, and this cap is the backstop for a provider that never
	// repeats but also never finishes. At 1000 keys per page that is 100
	// million keys, well beyond any journal walden expects to hold.
	maxListPages = 100_000
)

// listObjectsV2Result is the subset of one ListObjectsV2 page List needs.
// XMLName pins the root element: without it, encoding/xml happily decodes
// any other 2xx XML body (a service-root response from a misrouted
// request, say) as a zero-key, non-truncated page, and List would return
// success having silently listed nothing.
type listObjectsV2Result struct {
	XMLName               xml.Name `xml:"ListBucketResult"`
	IsTruncated           bool     `xml:"IsTruncated"`
	NextContinuationToken string   `xml:"NextContinuationToken"`
	Contents              []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
}

// List calls fn once for every key under prefix, journal-relative and in
// ascending order, exactly as Get expects a key. startAfter, when
// non-empty, is sent on the first request only - S3 ignores it once a
// continuation token is present - which is how spec/journal/v1 §7.5 and
// §12 both resume a tx/ listing from the last materialized sequence.
//
// A page is decoded whole before fn is called for any of its keys (a page
// is provider-bounded, so this is not the whole-key-set buffering the
// ticket forbids), but no further request is sent until fn has returned
// for every key already read. If fn returns an error, List returns it
// immediately and requests no further pages; the caller can resume later
// with startAfter set to the last key it processed.
func (c *Client) List(ctx context.Context, prefix, startAfter string, fn func(key string) error) error {
	fullPrefix := c.journalKey(prefix)

	var token, lastKey string
	haveLastKey := false
	seenTokens := make(map[string]struct{})

	for pages := 0; ; pages++ {
		if err := ctx.Err(); err != nil {
			return c.refuseList(prefix, fmt.Errorf("%w: %w", ErrStorageUnavailable, err))
		}
		if pages >= maxListPages {
			return c.refuseList(prefix, fmt.Errorf("%w: exceeded %d pages without completing", ErrListInconsistent, maxListPages))
		}

		query := url.Values{
			"list-type": {"2"},
			"prefix":    {fullPrefix},
		}
		if token == "" {
			if startAfter != "" {
				query.Set("start-after", c.journalKey(startAfter))
			}
		} else {
			query.Set("continuation-token", token)
		}

		resp, err := c.do(ctx, objectRequest{method: http.MethodGet, query: query})
		if err != nil {
			// do names the failed request "GET " - the key is always
			// empty for a listing - so the operator sees neither the verb
			// nor the prefix that was actually being listed. Rebuild the
			// refusal with List's own "LIST <prefix>" naming, keeping
			// do's why/fix text (already free of credentials) and the
			// original cause chain so errors.Is(_, ErrStorageUnavailable)
			// and friends still hold.
			var ref *refusal.Refusal
			if errors.As(err, &ref) {
				return refusal.RefuseWithCause("LIST "+prefix, ref.Why, ref.Fix, ref.Err)
			}
			return err
		}

		var page listObjectsV2Result
		decodeErr := xml.NewDecoder(io.LimitReader(resp.Body, maxListPageBody+1)).Decode(&page)
		closeErr := resp.Body.Close()
		switch {
		case decodeErr != nil:
			// do already committed to a 2xx response; a truncated or
			// malformed body past that point is not retried locally
			// (WALD-20's helper only covers the status line), the same way
			// getBody treats a stream error after Get's do call. The
			// caller resumes with startAfter, exactly as a Get caller
			// simply calls Get again. A page over maxListPageBody decodes
			// the same way: the limited reader ends the body early, so
			// the XML never closes and this is where it is caught.
			return c.refuseList(prefix, fmt.Errorf("%w: %s", ErrStorageUnavailable, decodeErr.Error()))
		case closeErr != nil:
			return c.refuseList(prefix, fmt.Errorf("%w: %s", ErrStorageUnavailable, closeErr.Error()))
		}

		for _, item := range page.Contents {
			if len(item.Key) > maxKeyLength {
				return c.refuseList(prefix, fmt.Errorf("%w: key length %d exceeds %d bytes", ErrListInconsistent, len(item.Key), maxKeyLength))
			}
			if !strings.HasPrefix(item.Key, fullPrefix) {
				return c.refuseList(prefix, fmt.Errorf("%w: key %q does not start with prefix %q", ErrListInconsistent, item.Key, fullPrefix))
			}
			if haveLastKey && item.Key <= lastKey {
				return c.refuseList(prefix, fmt.Errorf("%w: key %q is not strictly greater than %q", ErrListInconsistent, item.Key, lastKey))
			}
			lastKey, haveLastKey = item.Key, true

			if err := fn(c.journalRelativeKey(item.Key)); err != nil {
				return err
			}
		}

		if !page.IsTruncated {
			return nil
		}
		_, alreadySeen := seenTokens[page.NextContinuationToken]
		switch {
		case page.NextContinuationToken == "":
			return c.refuseList(prefix, fmt.Errorf("%w: truncated with no continuation token", ErrListInconsistent))
		case page.NextContinuationToken == token:
			return c.refuseList(prefix, fmt.Errorf("%w: continuation token did not advance", ErrListInconsistent))
		case alreadySeen:
			// Not the immediately preceding token (caught above), but one
			// from an earlier page - a provider cycling through a small
			// set of tokens on truncated, empty-Contents pages would
			// otherwise pass both the previous-token check and the
			// ordering check (there are no keys to be out of order) and
			// spin forever.
			return c.refuseList(prefix, fmt.Errorf("%w: continuation token %q repeats one already seen", ErrListInconsistent, page.NextContinuationToken))
		}
		token = page.NextContinuationToken
		seenTokens[token] = struct{}{}
	}
}

// journalKey joins the journal's key prefix onto a journal-relative key,
// the same convention Put, Get, and objectURL use: an empty prefix leaves
// key unchanged. An empty key (List's own prefix argument, when the
// caller lists the whole journal) yields the journal prefix followed by
// "/", never the bare prefix: List uses this both as the S3 prefix= value
// and, via fullPrefix in List above, as the boundary a returned key must
// start with, and a bare prefix like "v1" would also match a sibling
// journal named "v1-staging" sharing the same bucket.
func (c *Client) journalKey(key string) string {
	switch {
	case c.journal.Prefix == "":
		return key
	case key == "":
		return c.journal.Prefix + "/"
	default:
		return c.journal.Prefix + "/" + key
	}
}

// journalRelativeKey strips the journal's key prefix from a full key
// ListObjectsV2 returned, so a key List hands to fn can go straight into
// Get, the same as a key Put was given.
func (c *Client) journalRelativeKey(key string) string {
	if c.journal.Prefix == "" {
		return key
	}
	return strings.TrimPrefix(key, c.journal.Prefix+"/")
}

// refuseList builds the one-line refusal for a failed or inconsistent
// listing, naming the journal-relative prefix that was being listed.
func (c *Client) refuseList(prefix string, cause error) error {
	fix := "check bucket, region and credentials"
	switch {
	case errors.Is(cause, ErrStorageUnavailable):
		fix = "pushes succeed when storage returns"
	case errors.Is(cause, ErrListInconsistent):
		fix = "the object storage provider is not honoring the ListObjectsV2 contract"
	}
	return refusal.RefuseWithCause("LIST "+prefix, cause.Error(), fix, cause)
}
