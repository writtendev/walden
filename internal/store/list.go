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
	"net/http"
	"net/url"
	"strings"

	"github.com/writtendev/walden/internal/refusal"
)

// ErrListInconsistent marks a listing that broke the ListObjectsV2
// pagination contract: truncated with no continuation token, a
// continuation token that did not advance, a key that is not strictly
// greater than the one before it (within a page or across pages), or a
// returned key outside the requested prefix. spec/journal/v1 §10 promises
// listing order is replay order, and WALD-34's ordered replay depends on
// that holding, so a provider that breaks the contract gets a one-line
// refusal here rather than a spinning loop or a misordered listing handed
// upstream.
var ErrListInconsistent = errors.New("object storage listing is inconsistent")

// listObjectsV2Result is the subset of one ListObjectsV2 page List needs.
type listObjectsV2Result struct {
	IsTruncated           bool   `xml:"IsTruncated"`
	NextContinuationToken string `xml:"NextContinuationToken"`
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

	for {
		if err := ctx.Err(); err != nil {
			return c.refuseList(prefix, fmt.Errorf("%w: %w", ErrStorageUnavailable, err))
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
			return err
		}

		var page listObjectsV2Result
		decodeErr := xml.NewDecoder(resp.Body).Decode(&page)
		closeErr := resp.Body.Close()
		switch {
		case decodeErr != nil:
			// do already committed to a 2xx response; a truncated or
			// malformed body past that point is not retried locally
			// (WALD-20's helper only covers the status line), the same way
			// getBody treats a stream error after Get's do call. The
			// caller resumes with startAfter, exactly as a Get caller
			// simply calls Get again.
			return c.refuseList(prefix, fmt.Errorf("%w: %s", ErrStorageUnavailable, decodeErr.Error()))
		case closeErr != nil:
			return c.refuseList(prefix, fmt.Errorf("%w: %s", ErrStorageUnavailable, closeErr.Error()))
		}

		for _, item := range page.Contents {
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
		switch {
		case page.NextContinuationToken == "":
			return c.refuseList(prefix, fmt.Errorf("%w: truncated with no continuation token", ErrListInconsistent))
		case page.NextContinuationToken == token:
			return c.refuseList(prefix, fmt.Errorf("%w: continuation token did not advance", ErrListInconsistent))
		}
		token = page.NextContinuationToken
	}
}

// journalKey joins the journal's key prefix onto a journal-relative key,
// the same convention Put, Get, and objectURL use: an empty prefix leaves
// key unchanged, and an empty key (List's own prefix argument, when the
// caller lists the whole journal) yields the bare journal prefix.
func (c *Client) journalKey(key string) string {
	switch {
	case c.journal.Prefix == "":
		return key
	case key == "":
		return c.journal.Prefix
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
