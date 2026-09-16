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
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/writtendev/walden/internal/journal"
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
	// ErrPrecondition marks a conditional write's target key already
	// existing (412): the same identity as journal.ErrPreconditionFailed,
	// so one sentinel exists, not two (the same pattern as
	// journal.ErrStreamFenced = ErrFenced). It means "you have been
	// fenced" - the opposite of ErrStorageUnavailable's "try again" - and
	// PutIfAbsent never retries it.
	ErrPrecondition = journal.ErrPreconditionFailed
	// ErrOutcomeUnknown marks a conditional write whose outcome could not
	// be proven either way: the attempt may or may not have been applied.
	// It deliberately does not wrap ErrStorageUnavailable, whose contract
	// is "the caller can simply try again" - that is exactly wrong here,
	// because a resend risks a 412 caused by this writer's own earlier,
	// unacknowledged attempt. See classify and PutIfAbsent.
	ErrOutcomeUnknown = errors.New("object storage write outcome unknown")
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

	// idleConnTimeout caps how long a pooled connection sits idle before
	// this client closes it first. Set comfortably below the keep-alive
	// timeouts object storage providers typically run (60s or more), it
	// shrinks the window in which a connection this client still
	// considers idle-and-reusable is, at that same moment, being closed
	// by the server for the same reason - see retryableTransportError for
	// how the request that loses that race is still recovered rather
	// than shrinking the window to zero, which isn't possible from the
	// client side.
	idleConnTimeout = 30 * time.Second
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
				IdleConnTimeout:       idleConnTimeout,
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

// PutIfAbsent uploads body (size bytes long) to key, journal-relative,
// conditioned on key not already existing: it sends If-None-Match: *
// (journal.HeaderIfNoneMatch, journal.IfNoneMatchWildcard) rather than a
// literal header. A 412 comes back as ErrPrecondition and is never
// retried - it is definitive proof the key already exists (spec/journal/v1
// section 11.4.2). Unlike Put, a retryable failure is resent only when
// this attempt is proven not to have been applied; otherwise PutIfAbsent
// stops at once with ErrOutcomeUnknown rather than risk a resend whose own
// 412 would be caused by this writer's earlier attempt. See classify and
// this package's WALD-22 plan for the full rule.
func (c *Client) PutIfAbsent(ctx context.Context, key string, body io.ReaderAt, size int64) error {
	header := http.Header{journal.HeaderIfNoneMatch: []string{journal.IfNoneMatchWildcard}}
	resp, err := c.do(ctx, objectRequest{
		method:      http.MethodPut,
		key:         key,
		body:        body,
		size:        size,
		header:      header,
		conditional: true,
	})
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
			fmt.Errorf("%w: %w", ErrStorageUnavailable, err),
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
	// conditional marks a request whose classify rule differs from an
	// idempotent Put/Get: a retryable cause is resent only when this
	// attempt is proven not to have been applied (see classify). It is
	// explicit rather than inferred from header, matching this package's
	// WALD-22 plan.
	conditional bool
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

		resp, wrote, sendErr := c.send(ctx, r, c.now())
		retry, cause := classify(r, resp, sendErr, wrote)

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
// freshly built request and is signed again with now. The returned bool,
// wrote, reports whether the request was fully written to the connection
// before a send error or response arrived (httptrace.ClientTrace's
// WroteRequest, recording info.Err == nil) - classify's only use for it is
// deciding, for a conditional request, whether a transport error proves
// the attempt was not applied. send deliberately never sets req.GetBody or
// an Idempotency-Key header: either one would let net/http silently replay
// a request on its own, which would defeat the "proven unapplied" rule
// PutIfAbsent depends on (WALD-22's plan).
//
// wrote is read through a channel, not a plain captured variable: for a
// request with a body, net/http's Transport writes the request and reads
// the response in two different goroutines, and WroteRequest is called
// from the write goroutine. When the response arrives before the write
// goroutine finishes (RoundTrip's own select races the two), RoundTrip can
// return before WroteRequest has run, and a plain shared bool would be a
// genuine data race between that goroutine and this one - caught by
// go test -race, not a false positive. A buffered channel makes the
// hand-off safe either way. Whenever err != nil because the write itself
// failed, net/http always signals WroteRequest before propagating that
// error (Request.write's deferred call happens-before the write-error
// channel send inside persistConn.writeLoop), so the non-blocking receive
// below reliably has a value by then; it is only "no value yet" for a
// send that never reached the write path at all (a dial failure, where
// nothing was ever written) or one whose outcome this func does not use
// wrote for anyway (a successful response). Either way, send must never
// block waiting for it - a custom or future RoundTripper that does not
// invoke httptrace hooks at all must not hang this call forever.
func (c *Client) send(ctx context.Context, r objectRequest, now time.Time) (resp *http.Response, wrote bool, err error) {
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

	wroteCh := make(chan bool, 1)
	trace := &httptrace.ClientTrace{
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			wroteCh <- info.Err == nil
		},
	}
	resp, err = c.http.Do(req.WithContext(httptrace.WithClientTrace(ctx, trace)))
	select {
	case wrote = <-wroteCh:
	default:
		// No signal yet: either WroteRequest will never fire for this
		// attempt (see the comment above send), or resp is non-nil and
		// classify never consults wrote for a successful response.
		wrote = false
	}
	return resp, wrote, err
}

// objectURL builds the URL for key against c.journal's endpoint, bucket,
// and prefix, in whichever addressing style the journal resolved to. key
// is journal-relative; objectURL joins Journal.Prefix onto it. An empty
// key addresses the bucket root - regardless of Journal.Prefix, which
// plays no part in a bucket-root request - which only WALD-21's LIST
// uses: LIST scopes to the journal through its prefix= query parameter,
// never through the path.
func (c *Client) objectURL(key string) *url.URL {
	j := c.journal

	// Journal.Endpoint is always "scheme://host[:port]", with no path and
	// no query - ParseJournalURL builds it that way - so this never fails.
	endpoint, _ := url.Parse(j.Endpoint)

	var segs []string
	if key != "" {
		if j.Prefix != "" {
			segs = append(segs, j.Prefix)
		}
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
// A nil cause with retry false means success: the caller owns resp. wrote
// is send's httptrace signal, consulted only when r.conditional.
//
// Retried, for r.conditional == false (Put, Get - both idempotent, so
// retrying is always safe): transient transport errors (see
// retryableTransportError), 408, 429, 500, 502, 503, 504, and 400 with S3
// Code "RequestTimeout". A 409 with Code "ConditionalRequestConflict" is
// also retried, though only a conditional request can provoke it in
// practice.
//
// Permanent: every other status, including 301 (wrong region), other 400s
// and 409s, 403, 404 (NoSuchBucket, on a PUT), and 501. A 404 with S3 Code
// "NoSuchKey" is ErrObjectNotFound rather than ErrStorageRefused. A 412 is
// always ErrPrecondition, decided by status code alone: the body is never
// consulted, so an empty or garbage body still yields ErrPrecondition, and
// the case is global rather than gated on r.conditional (spec/journal/v1
// section 11.4.2 - a 412 can only occur for a conditional request in
// practice, but the mapping from status code is unconditional too).
//
// A send error (resp == nil) is retried only when it is one of the
// transport errors named above or ctx ending; everything else - an
// untrusted TLS certificate, a caller ReaderAt shorter than size, a
// malformed request - is permanent, since retrying it can never succeed.
// That is the r.conditional == false story in full; r.conditional == true
// changes it, below.
//
// For r.conditional == true (PutIfAbsent), wrote is checked before either
// of the two paragraphs above ever gets a say: once wrote == true, the
// request reached storage, so no failure past that point - retryable or
// not, a status or a send error, a cause classify can name or one it
// cannot even parse - is retried. It becomes (false, ErrOutcomeUnknown)
// instead: resending risks a 412 caused by this writer's own earlier,
// unacknowledged attempt. This covers every send error with wrote == true,
// not only the ones retryableTransportError recognizes - a malformed
// status line, a malformed header, a reply that is not HTTP at all, or a
// TLS alert while reading the response are all sorted the same way a
// connection reset or EOF is, because none of them prove the write did
// not land. With wrote == false (the request never fully reached
// storage), or a status storage returns only for a request it rejected
// before evaluating the write (408, 429, 503, 400 RequestTimeout, 409
// ConditionalRequestConflict), the attempt is proven unapplied and the
// normal retry rule above applies unchanged. ErrOutcomeUnknown wraps the
// raw cause (the transport error, or the status and Code), never the
// ErrStorageUnavailable-wrapped one, so it does not itself match
// ErrStorageUnavailable and errors.Is(err, context.Canceled) and friends
// still see through it. Outcome: at most one attempt is ever ambiguous,
// and it is always the last one, so any 412 PutIfAbsent does see is
// definitive proof of a concurrent writer, never of itself.
func classify(r objectRequest, resp *http.Response, err error, wrote bool) (retry bool, cause error) {
	if err != nil {
		// wrote is checked before retryableTransportError, not after: for a
		// conditional request, wrote == true already means the request
		// reached storage, so ANY failure past that point - however
		// retryableTransportError would otherwise sort it - can no longer
		// be treated as proof the write was not applied. That includes a
		// response classify cannot even parse (a malformed status line, a
		// malformed header, a reply that is not HTTP at all) or a TLS
		// alert while reading the response, none of which
		// retryableTransportError recognizes as transient, so an earlier
		// version of this function sorted them under ErrStorageRefused
		// first - telling the caller the write had definitely failed and
		// was safe to redo, exactly backwards when storage may have
		// already applied it: the resend's own 412 would then be
		// misreported as a concurrent writer (spec/journal/v1 section 11.4
		// item 6).
		if r.conditional && wrote {
			return false, fmt.Errorf("%w: %w", ErrOutcomeUnknown, err)
		}
		if !retryableTransportError(err) {
			return false, fmt.Errorf("%w: %s", ErrStorageRefused, err.Error())
		}
		return true, fmt.Errorf("%w: %w", ErrStorageUnavailable, err)
	}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return false, nil
	case resp.StatusCode == http.StatusPreconditionFailed:
		return false, fmt.Errorf("%w: %s", ErrPrecondition, statusDetail(resp))
	case isRetryableStatus(resp.StatusCode):
		detail := statusDetail(resp)
		if r.conditional && !provenUnappliedStatus(resp.StatusCode) {
			return false, fmt.Errorf("%w: %s", ErrOutcomeUnknown, detail)
		}
		return true, fmt.Errorf("%w: %s", ErrStorageUnavailable, detail)
	case resp.StatusCode == http.StatusBadRequest:
		code := s3Code(resp)
		if code == "RequestTimeout" {
			return true, fmt.Errorf("%w: %d %s", ErrStorageUnavailable, resp.StatusCode, code)
		}
		return false, fmt.Errorf("%w: %d %s", ErrStorageRefused, resp.StatusCode, code)
	case resp.StatusCode == http.StatusConflict:
		code := s3Code(resp)
		if code == "ConditionalRequestConflict" {
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

// provenUnappliedStatus reports whether status is a retryable status that
// storage returns only for a request it rejected before evaluating the
// write, so the attempt provably did not land: 408, 429, and 503. The
// other statuses isRetryableStatus retries - 500, 502, 504 - can be
// returned after storage received and evaluated a request whose response
// never reached this client, so they do not qualify.
func provenUnappliedStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return true
	default:
		return false
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
// retrying: ctx ending, a per-attempt transport timeout, an EOF, a
// connection-level failure (reset, refused, broken pipe, or a
// locally-observed close mid read/write), or the server closing a pooled
// connection just as this client reused it from idle. The OS spells the
// connection-level case's specific errno differently by platform and by
// which side of the connection noticed first - ECONNRESET, EPIPE, and
// net.ErrClosed have all been observed for the same underlying "the
// connection died" event from WALD-20's plan - so this checks for a
// *net.OpError (the type net/http wraps every one of those in) rather than
// enumerating every spelling.
//
// Not every *net.OpError is connection-level, though, and three permanent
// cases are excluded before that check fires: a DNS name that does not
// exist (*net.DNSError with IsNotFound - a typo in the journal URL, or
// virtual-hosted addressing against a bucket with no wildcard DNS), a port
// number that cannot exist (*net.AddrError), and a TLS alert (crypto/tls
// wraps both the alert it received and the alert it sent as a
// *net.OpError, with Op "remote error" and "local error" respectively - an
// unsupported protocol version, a required client certificate, and so on).
// None of those three can ever succeed on retry.
//
// Anything that is not a *net.OpError at all (an untrusted TLS
// certificate - a *tls.CertificateVerificationError - a caller ReaderAt
// shorter than the declared size, a malformed request) is permanent for
// the same reason: no number of retries changes the outcome, so classify
// must not guess "storage is down" and tell the operator to wait.
//
// serverClosedIdleConn is checked separately, before the *net.OpError
// check: it is net/http's own errServerClosedIdle, which is not a
// *net.OpError, a net.Error, or an EOF - see that function's comment for
// why matching it needs its own case.
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
	if serverClosedIdleConn(err) {
		return true
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return false
	}
	var addrErr *net.AddrError
	if errors.As(err, &addrErr) {
		return false
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Op == "remote error" || opErr.Op == "local error" {
			return false
		}
		return true
	}
	return false
}

// errServerClosedIdleText is the exact message of net/http's unexported
// errServerClosedIdle sentinel (net/http/transport.go): the error a
// *http.Transport hands back, undecorated, when it reuses a pooled idle
// connection for a request that races the server closing that same
// connection for its own keep-alive timeout (or sends an unsolicited 408
// on it) - persistConn.readLoopPeekFailLocked detects the close and
// persistConn.roundTrip returns the sentinel as-is ("Don't decorate", says
// that code). net/http will not replay the request itself when it has a
// body and no GetBody (persistConn.shouldRetryRequest requires
// req.isReplayable()); WALD-20 deliberately never sets GetBody - see
// send's PUT branches - because WALD-22's conditional PUT needs net/http
// to never replay a request on its own, so walden's own retry loop must
// recognize this case instead.
//
// There is no exported sentinel to compare against with errors.Is:
// errServerClosedIdle is an unexported package-level value, so identity
// comparison is unavailable outside net/http, and a locally constructed
// errors.New with the same text would still not compare equal to it (an
// error without an Is method falls back to ==, and two errors.New calls
// never share a pointer). The message has been stable since the sentinel
// was added for https://github.com/golang/go/issues/19943 in Go 1.11, and
// net/http still returns it "undecorated" per the comment above, so
// matching that exact text at the end of the unwrap chain - after
// (*http.Client).do wraps whatever the transport returns in a *url.Error -
// is the most stable option available from outside the package.
const errServerClosedIdleText = "http: server closed idle connection"

// serverClosedIdleConn reports whether err, or anything it wraps, is
// net/http's errServerClosedIdle.
func serverClosedIdleConn(err error) bool {
	for err != nil {
		if err.Error() == errServerClosedIdleText {
			return true
		}
		err = errors.Unwrap(err)
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
// transport error) in why, with the attempt count appended when cause
// traces to ErrStorageUnavailable or ErrOutcomeUnknown - the two causes
// that record how many attempts were made before stopping. Every other
// cause is permanent from the first attempt, so there is nothing to count.
func (c *Client) refuse(r objectRequest, attempts int, cause error) error {
	what := r.method + " " + r.key
	why := cause.Error()
	if errors.Is(cause, ErrStorageUnavailable) || errors.Is(cause, ErrOutcomeUnknown) {
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
	case errors.Is(cause, ErrPrecondition), errors.Is(cause, ErrOutcomeUnknown):
		// The journal layer supplies the operator-facing fix for both: a
		// fenced writer's remedy is "restart to re-materialize", which
		// store has no business stating on the journal package's behalf.
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
