// This file sends walden's first signed requests to object storage: Put
// and Get. Both go through one unexported retry loop, (*Client).do, which
// signs every attempt with the WALD-19 SigV4 signer (sigv4.go), stops
// after maxAttempts with jittered backoff, stops early when ctx is done,
// and sorts every failure under one of the three sentinels below. WALD-21
// (LIST) and WALD-22 (conditional PUT) plug into do and classify rather
// than adding their own send paths; see WALD-20's plan for the full
// design this follows.
package store

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/writtendev/walden/internal/refusal"
)

// Errors returned by Client. Each is returned wrapped in a
// *refusal.Refusal, so what a caller sees through errors.Is is stable and
// what an operator sees printed is one line.
var (
	// ErrStorageUnavailable marks a transient failure: retries were
	// exhausted, or ctx ended first. The caller can simply try again.
	ErrStorageUnavailable = errors.New("object storage unavailable")
	// ErrStorageRefused marks a permanent failure: retrying will not help.
	ErrStorageRefused = errors.New("object storage refused request")
	// ErrObjectNotFound marks a GET against a key that does not exist.
	ErrObjectNotFound = errors.New("object not found")
)

const (
	// maxAttempts counts the first attempt. Not a knob: walden's five
	// knobs don't include tuning this, so there is no flag or env var.
	maxAttempts = 4

	// chunkSize is the aws-chunked frame size for a streaming PUT over
	// plain http, matching the AWS example and above S3's 8 KiB minimum.
	chunkSize = 64 << 10

	// maxErrorBody bounds how much of a failure response body walden
	// reads: enough for the S3 <Code> element, never the whole thing.
	maxErrorBody = 64 << 10

	// Transport timeouts on the *http.Client NewClient builds, so a dead
	// endpoint cannot hang a caller that forgot a context deadline. There
	// is no overall http.Client.Timeout: a large pack upload has no
	// universal time limit, so the caller's ctx bounds total time.
	dialTimeout           = 10 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	responseHeaderTimeout = 30 * time.Second
)

// backoffBase and backoffCap set the full-jitter retry schedule: a random
// duration in [0, min(backoffCap, backoffBase*2^(attempt-1))]. They are
// package vars rather than consts only so export_test.go's
// SetBackoffForTest can shrink them for a test; production code never
// changes them, and this is not a sixth knob - there is no flag or env
// var that reaches them.
var (
	backoffBase = 100 * time.Millisecond
	backoffCap  = 1 * time.Second
)

// Client sends signed requests to the object storage backing a Journal.
type Client struct {
	journal *Journal
	http    *http.Client
	now     func() time.Time
}

// NewClient builds a Client for j.
func NewClient(j *Journal) *Client {
	return &Client{
		journal: j,
		http: &http.Client{
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: dialTimeout}).DialContext,
				TLSHandshakeTimeout:   tlsHandshakeTimeout,
				ResponseHeaderTimeout: responseHeaderTimeout,
			},
			// A PUT answered with a 3xx would otherwise be replayed by
			// net/http as a bodyless GET to Location: if that GET comes
			// back 2xx, classify would see success and Put would return
			// nil having written nothing - an acknowledged push that
			// never reached the journal. A GET redirected cross-host
			// would also carry X-Amz-Security-Token to whatever Location
			// names, since net/http only strips Authorization on
			// cross-host redirects, not custom headers. Every 3xx must
			// instead reach classify as a response, never be followed.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		now: time.Now,
	}
}

// Put uploads body (size bytes long) to key, journal-relative; the client
// joins Journal.Prefix onto it, so callers never see the prefix. An
// unconditional PUT to a fixed key is idempotent (spec/journal/v1 §6.4),
// so it is retried like a GET. Each retry rereads body from the start
// through a fresh io.NewSectionReader, so the client never buffers the
// whole body: body only needs to support ReadAt, which both *os.File (a
// pack on disk) and *bytes.Reader (a tx record) already do.
func (c *Client) Put(ctx context.Context, key string, body io.ReaderAt, size int64) error {
	resp, err := c.do(ctx, objectRequest{method: http.MethodPut, key: key, body: body, size: size})
	if err != nil {
		return err
	}
	closeBody(resp)
	return nil
}

// Get retrieves key, journal-relative, and retries until it has a 2xx
// response, then returns the body as it streams; the caller must Close
// it. A read error after that point is not retried - it is instead
// wrapped as ErrStorageUnavailable, and the caller can simply Get again.
func (c *Client) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	r := objectRequest{method: http.MethodGet, key: key}
	resp, err := c.do(ctx, r)
	if err != nil {
		return nil, err
	}
	return &getBody{ReadCloser: resp.Body, r: r}, nil
}

// getBody wraps a GET's streamed response body so a read error after do
// already committed to a 2xx response - a connection reset mid-stream,
// say - surfaces as ErrStorageUnavailable instead of a bare transport
// error. It is never retried internally: the caller simply Gets again.
type getBody struct {
	io.ReadCloser
	r objectRequest
}

func (b *getBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && err != io.EOF {
		return n, refusal.RefuseWithCause(
			b.r.method+" "+b.r.key,
			err.Error(),
			fixFor(ErrStorageUnavailable),
			ErrStorageUnavailable,
		)
	}
	return n, err
}

// objectRequest is the shared seam WALD-21 (LIST) and WALD-22 (conditional
// PUT) extend: WALD-21 fills in query, WALD-22 fills in header. key is
// journal-relative; "" addresses the bucket root, which only LIST uses.
type objectRequest struct {
	method string
	key    string
	query  url.Values
	header http.Header
	body   io.ReaderAt // nil for no body
	size   int64
}

// do sends r, signing and retrying under the rules described atop this
// file, and returns a 2xx response whose body the caller owns, or a
// classified *refusal.Refusal. It is the only place that sends a request.
func (c *Client) do(ctx context.Context, r objectRequest) (*http.Response, error) {
	var lastCause error
	for attempts := 1; attempts <= maxAttempts; attempts++ {
		if err := ctx.Err(); err != nil {
			return nil, c.refuse(r, attempts-1, fmt.Errorf("%w: %w", ErrStorageUnavailable, err))
		}

		resp, sendErr := c.send(ctx, r, c.now())
		retry, cause := classify(resp, sendErr)

		if !retry {
			if cause == nil {
				return resp, nil
			}
			closeBody(resp)
			return nil, c.refuse(r, attempts, cause)
		}

		closeBody(resp)
		lastCause = cause

		if attempts == maxAttempts {
			break
		}

		wait := backoff(attempts)
		if d, ok := ctx.Deadline(); ok && time.Until(d) < wait {
			// ctx will end before the planned wake-up. Stop now rather
			// than sleep into the deadline: report the real cause (a 503,
			// say) instead of letting it be replaced by a context error
			// once ctx.Done fires mid-sleep.
			return nil, c.refuse(r, attempts, lastCause)
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, c.refuse(r, attempts, fmt.Errorf("%w: %w", ErrStorageUnavailable, ctx.Err()))
		case <-timer.C:
		}
	}
	return nil, c.refuse(r, maxAttempts, lastCause)
}

// send builds and signs one attempt at r and sends it. Each attempt gets a
// freshly built request and is signed again with now.
func (c *Client) send(ctx context.Context, r objectRequest, now time.Time) (*http.Response, error) {
	u := c.objectURL(r.key)
	if len(r.query) > 0 {
		q := u.Query()
		for k, vals := range r.query {
			for _, v := range vals {
				q.Add(k, v)
			}
		}
		u.RawQuery = q.Encode()
	}

	req := &http.Request{
		Method:     r.method,
		URL:        u,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header, len(r.header)+4),
		Host:       u.Host,
	}
	for k, v := range r.header {
		req.Header[k] = append([]string(nil), v...)
	}

	creds := c.journal.Credentials
	region := c.journal.Region

	switch {
	case r.body == nil:
		signV4(req, creds, region, "s3", emptySHA256, now)
	case u.Scheme == "https":
		// TLS already protects the bytes, and UNSIGNED-PAYLOAD is the path
		// every provider in the support matrix accepts; aws-chunked is
		// not (GCS's XML API, for example). This has not been verified
		// against every provider walden supports - see WALD-20's plan.
		req.ContentLength = r.size
		if r.size == 0 {
			// For client requests, Go treats ContentLength == 0 with a
			// non-nil Body as "length unknown" and sends
			// Transfer-Encoding: chunked instead of Content-Length: 0.
			// S3 answers a chunked, Content-Length-less PUT with 411
			// MissingContentLength. http.NoBody makes Go send
			// Content-Length: 0 with no body and no chunking.
			req.Body = http.NoBody
		} else {
			section := io.NewSectionReader(r.body, 0, r.size)
			req.Body = io.NopCloser(section)
		}
		signV4(req, creds, region, "s3", unsignedPayload, now)
	default:
		// Plain http has no transport integrity, so the body is signed
		// here via aws-chunked streaming.
		section := io.NewSectionReader(r.body, 0, r.size)
		req.Header.Set("Content-Encoding", "aws-chunked")
		req.Header.Set("X-Amz-Decoded-Content-Length", strconv.FormatInt(r.size, 10))
		// Both the header and req.ContentLength are set to the same
		// value: Go's transport sends req.ContentLength and ignores the
		// header copy, so if the two drift apart the signature (which
		// covers the header) no longer matches the bytes sent.
		n := chunkedLength(r.size, chunkSize)
		req.Header["Content-Length"] = []string{strconv.FormatInt(n, 10)}
		req.ContentLength = n
		seed := signV4(req, creds, region, "s3", streamingPayload, now)
		dateStamp := now.UTC().Format(dateFormat)
		scope := scopeString(dateStamp, region, "s3")
		key := signingKey(creds.SecretAccessKey, dateStamp, region, "s3")
		req.Body = io.NopCloser(newChunkedBody(section, chunkSize, key, scope, now, seed))
	}

	return c.http.Do(req.WithContext(ctx))
}

// objectURL builds the URL for key against c.journal's endpoint, bucket,
// and prefix, in whichever addressing style the journal resolved to. key
// is journal-relative; objectURL joins Journal.Prefix onto it. An empty
// key addresses the bucket root, which only WALD-21's LIST uses.
func (c *Client) objectURL(key string) *url.URL {
	j := c.journal

	// Journal.Endpoint is always "scheme://host[:port]", with no path and
	// no query - ParseJournalURL builds it that way - so this never fails.
	endpoint, _ := url.Parse(j.Endpoint)

	var segs []string
	if j.Prefix != "" {
		segs = append(segs, j.Prefix)
	}
	if key != "" {
		segs = append(segs, key)
	}
	joined := strings.Join(segs, "/")

	u := &url.URL{Scheme: endpoint.Scheme}
	var path string
	if j.PathStyle {
		u.Host = endpoint.Host
		path = "/" + j.Bucket
		if joined != "" {
			path += "/" + joined
		}
	} else {
		u.Host = j.Bucket + "." + endpoint.Host
		path = "/" + joined
	}
	// Set Path to the decoded path and RawPath to its single, byte-exact
	// encoding, so the bytes on the wire are the same bytes canonicalRequest
	// signs instead of whatever URL.EscapedPath would otherwise choose.
	u.Path = path
	u.RawPath = uriEncode(path, false)
	return u
}

// classify decides whether a response or send error is worth retrying and
// which sentinel it sorts under. resp is non-nil exactly when err is nil.
// A nil cause with retry false means success: the caller owns resp.
//
// Retried: transient transport errors (see retryableTransportError), 408,
// 429, 500, 502, 503, 504, and 400 with S3 Code "RequestTimeout". An
// unconditional PUT to a fixed key and a GET are both idempotent, so
// retrying them is safe.
//
// Permanent: every other status, including 301 (wrong region), other 400s,
// 403, 404 (NoSuchBucket, on a PUT), and 501. A 404 with S3 Code
// "NoSuchKey" is ErrObjectNotFound rather than ErrStorageRefused.
//
// A send error (resp == nil) is retried only when it is one of the
// transport errors named above or ctx ending; everything else - an
// untrusted TLS certificate, a caller ReaderAt shorter than size, a
// malformed request - is permanent, since retrying it can never succeed.
func classify(resp *http.Response, err error) (retry bool, cause error) {
	if err != nil {
		if retryableTransportError(err) {
			return true, fmt.Errorf("%w: %w", ErrStorageUnavailable, err)
		}
		return false, fmt.Errorf("%w: %s", ErrStorageRefused, err.Error())
	}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return false, nil
	case isRetryableStatus(resp.StatusCode):
		return true, fmt.Errorf("%w: %s", ErrStorageUnavailable, statusDetail(resp))
	case resp.StatusCode == http.StatusBadRequest:
		code := s3Code(resp)
		if code == "RequestTimeout" {
			return true, fmt.Errorf("%w: %d %s", ErrStorageUnavailable, resp.StatusCode, code)
		}
		return false, fmt.Errorf("%w: %d %s", ErrStorageRefused, resp.StatusCode, code)
	case resp.StatusCode == http.StatusNotFound:
		code := s3Code(resp)
		if code == "NoSuchKey" {
			return false, fmt.Errorf("%w: %d %s", ErrObjectNotFound, resp.StatusCode, code)
		}
		return false, fmt.Errorf("%w: %d %s", ErrStorageRefused, resp.StatusCode, code)
	default:
		return false, fmt.Errorf("%w: %s", ErrStorageRefused, statusDetail(resp))
	}
}

func isRetryableStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// retryableTransportError reports whether err - a failure to send a
// request or read its response, before any status line arrived - is worth
// retrying: ctx ending, a per-attempt transport timeout, a connection reset
// or refused, or an EOF. Those are the transient cases named in WALD-20's
// plan. Anything else (an untrusted TLS certificate, a caller ReaderAt
// shorter than the declared size, a malformed request) is permanent: no
// number of retries changes the outcome, so classify must not guess
// "storage is down" and tell the operator to wait.
func retryableTransportError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	return false
}

// statusDetail names a retryable non-2xx response for the why line: the
// status and S3 Code together when the body parses, otherwise the status
// line alone.
func statusDetail(resp *http.Response) string {
	code := s3Code(resp)
	if code == "" {
		return resp.Status
	}
	return fmt.Sprintf("%d %s", resp.StatusCode, code)
}

// s3Code reads at most maxErrorBody bytes of resp's body and returns the
// S3 <Code> element, or "" if the body is absent or does not parse.
// Walden reads only Code and never repeats the body text, so a refusal
// can never quote storage-provider-supplied prose back at an operator.
func s3Code(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	var parsed struct {
		Code string `xml:"Code"`
	}
	_ = xml.Unmarshal(body, &parsed)
	return parsed.Code
}

// closeBody drains a bounded amount of resp's body and closes it, so the
// underlying connection can be reused. resp may be nil (a transport error
// never produced one) or already fully read by s3Code.
func closeBody(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
	resp.Body.Close()
}

// refuse builds the one-line *refusal.Refusal for a failed request: verb,
// journal-relative key, and cause (already naming the status/Code or
// transport error) in why, with the attempt count appended only when cause
// traces to ErrStorageUnavailable - a permanent refusal never retries, so
// there is nothing to count.
func (c *Client) refuse(r objectRequest, attempts int, cause error) error {
	what := r.method + " " + r.key
	why := cause.Error()
	if errors.Is(cause, ErrStorageUnavailable) {
		why = fmt.Sprintf("%s after %d attempt%s", why, attempts, plural(attempts))
	}
	return refusal.RefuseWithCause(what, why, fixFor(cause), cause)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func fixFor(cause error) string {
	switch {
	case errors.Is(cause, ErrObjectNotFound):
		return ""
	case errors.Is(cause, ErrStorageUnavailable):
		return "pushes succeed when storage returns"
	default:
		return "check bucket, region and credentials"
	}
}

// backoff returns a full-jitter wait before the attempt after attempt: a
// random duration in [0, min(backoffCap, backoffBase*2^(attempt-1))].
func backoff(attempt int) time.Duration {
	max := backoffCap
	if scaled := backoffBase * time.Duration(uint64(1)<<uint(attempt-1)); scaled > 0 && scaled < max {
		max = scaled
	}
	if max <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(max) + 1))
}
