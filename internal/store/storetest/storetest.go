// Package storetest is an in-memory, S3-speaking fake of the object storage
// the journal lives in: PUT, conditional PUT (If-None-Match: *), GET, and
// ListObjectsV2, running as a real http.Handler on an httptest.Server. It
// exists so store.Client (sigv4, aws-chunked, retry/classify — see
// client.go's file comment) can be pointed at something that behaves like
// object storage, including on purpose behaving badly: a Rule table fires
// injected faults — latency, 5xx bursts, dropped connections, truncated
// bodies, a rival write that forces a real 412 — at chosen call counts, so
// a durability test exercises the real client against real HTTP framing
// rather than a mock that only knows what the author remembered to model.
//
// This package imports only the standard library, deliberately not even
// internal/journal for its If-None-Match header name or wildcard value: it
// models S3 on the wire, not walden, and reusing walden's own constants
// would let a wrong constant pass on both sides of a test. Because nothing
// internal is imported, store_test, internal/journal, and cmd/walden tests
// can all import it with no import cycle.
//
// Wire in through the fields store.Journal already has:
//
//	fake := storetest.New(t)
//	j := &store.Journal{
//		Endpoint:    fake.URL(),
//		Bucket:      fake.Bucket(),
//		Prefix:      "v1",
//		PathStyle:   true,
//		Region:      "us-east-1",
//		Credentials: store.Credentials{AccessKeyID: "x", SecretAccessKey: "y"},
//	}
//	c := store.NewClient(j)
//
// not through store's own export_test.go helpers, which are unexported
// outside package store. A consumer never needs DNS or TLS trust: the fake
// only ever speaks plain http on 127.0.0.1.
//
// Signatures are not verified — that is sigv4_test.go's and client_test.go's
// job — but an Authorization header is required, so a request signed by
// nothing at all still fails the way a real, wrong request would.
//
// Semantics this fake enforces (spec/journal/v1 §6.4, §9.2, §10, §11.1):
//
//   - PUT with no condition overwrites and returns 200.
//   - PUT with If-None-Match: * check-and-creates under one mutex: 412
//     PreconditionFailed if the key exists (bytes left untouched), 200 and a
//     new object otherwise. Any other conditional header (If-Match, or
//     If-None-Match with a value other than "*") returns 501 NotImplemented;
//     walden never sends one, so refusing is safer than silently ignoring it.
//   - A short or malformed body — one that does not add up to the declared
//     Content-Length, or X-Amz-Decoded-Content-Length for an aws-chunked
//     body — stores nothing and answers 400 IncompleteBody.
//   - GET returns 200 with the bytes, or 404 NoSuchKey.
//   - ListObjectsV2 requires list-type=2. It honours prefix, start-after
//     (ignored once a continuation token is present), and an opaque
//     continuation-token, in strict ascending key order. Fake.PageSize caps
//     a page (1000 by default, S3's own default) so a test can exercise
//     pagination without seeding a thousand keys.
//   - Any other method or query — a DELETE probe, an unrecognised list
//     query — returns 501 NotImplemented, so a missing capability fails
//     loudly rather than silently passing.
//
// "Partial write" never means a half-stored object: real S3 PUT is atomic,
// and a fake that stored a prefix of a write would not enforce "the same
// conditional semantics as the real thing". A partial write is modelled as
// the connection being cut after N body bytes with nothing stored (Fault.
// TruncateBody on PUT); the GET analogue sends the object's headers and N
// bytes of its body before the cut, to exercise the client's mid-stream
// read failure.
//
// Latency does not cancel a write: after Fault.Delay this fake evaluates
// the request whether or not the caller is still waiting, the same as real
// storage would. A precondition fault (Fault.Rival) writes rival bytes to
// the key and then evaluates the request normally, so any 412 it produces
// is the real check firing against real state, never a status invented out
// of thin air — the fake never answers 412 for a key that is absent.
package storetest

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Op names the four request shapes this fake understands.
type Op int

const (
	// OpPut is an unconditional PUT.
	OpPut Op = iota
	// OpPutIfAbsent is a PUT carrying If-None-Match: *.
	OpPutIfAbsent
	// OpGet is a GET of one object.
	OpGet
	// OpList is a ListObjectsV2 request (list-type=2) against the bucket
	// root.
	OpList
)

// String renders o the way a test failure or Calls() dump wants to read it.
func (o Op) String() string {
	switch o {
	case OpPut:
		return "PUT"
	case OpPutIfAbsent:
		return "PUT(If-None-Match: *)"
	case OpGet:
		return "GET"
	case OpList:
		return "LIST"
	default:
		return fmt.Sprintf("Op(%d)", int(o))
	}
}

// Fault is what a Rule does once it fires. Every field is independent
// except where noted; a zero Fault matches but changes nothing, which is
// never useful, so a real Rule sets at least one.
type Fault struct {
	// Delay sleeps before the request is evaluated. It never holds the
	// fake's state lock, so concurrent, unrelated requests are unaffected.
	Delay time.Duration

	// Rival, when non-nil, is stored at the key before the request is
	// otherwise evaluated normally. For OpPutIfAbsent this produces a real
	// 412: the fake never fabricates one for a key it has not actually
	// written.
	Rival []byte

	// Land applies the write — the request's own body — before the fault
	// response is sent. It is only meaningful alongside Status or Drop: it
	// answers "did the write actually happen before storage lied about
	// it," which is exactly the ambiguity PutIfAbsent's ErrOutcomeUnknown
	// exists for.
	Land bool

	// Status, when non-zero, replaces the normal response with this status
	// and an S3 XML body naming Code.
	Status int
	// Code is the S3 <Code> element accompanying Status.
	Code string

	// Drop hijacks and closes the connection with no response at all,
	// after the request body (if any) has been fully read — so the client
	// sees exactly what a severed connection after a complete request
	// looks like, never a truncated write.
	Drop bool

	// TruncateBody models a cut mid-transfer. For a PUT it reads N raw
	// body bytes off the wire and then drops the connection; nothing is
	// stored. For a GET it sends normal headers, N bytes of the object,
	// and then drops the connection.
	TruncateBody int

	// IgnoreCondition treats If-None-Match: * as though it were absent —
	// the non-CAS provider case — so a PutIfAbsent overwrites silently
	// instead of check-and-creating.
	IgnoreCondition bool
}

// Rule fires Fault for the calls it targets.
type Rule struct {
	// Op is the request shape this rule watches. There is no wildcard;
	// name the Op explicitly.
	Op Op
	// Key is the exact full (bucket-relative) key to match, or "" to match
	// any key. For OpList, Key is matched against the request's prefix=
	// query value instead of an object key.
	Key string
	// Call is the 1-based index, among requests matching Op and Key, that
	// this rule starts firing on. Retries count as calls: a client's
	// second attempt at the same key is call 2.
	Call int
	// Count is the burst length: Call through Call+Count-1 all fire. 0 and
	// 1 both mean a single call.
	Count int
	// Fault is what happens on a firing call.
	Fault Fault
}

// Call is one request the fake logged, in arrival order.
type Call struct {
	// N is the 1-based arrival index across every request the fake has
	// dispatched, regardless of Op or Key.
	N int
	// Op is the request shape.
	Op Op
	// Key is the request's full (bucket-relative) key, or, for OpList, the
	// requested prefix.
	Key string
	// Faulted reports whether a Rule matched this call.
	Faulted bool
	// Landed reports whether the call actually changed or read state: a
	// PUT that stored bytes, a GET that returned an existing object's
	// bytes. A precondition failure, a dropped connection, or a fault
	// response with Land unset all leave Landed false.
	Landed bool
	// Status is the HTTP status sent, or 0 if the connection was dropped
	// with no response.
	Status int
}

// ruleState pairs a Rule with its own independent call counter: "Call" in
// the doc comment above counts calls matching that rule's own Op and Key,
// not calls matching any other rule.
type ruleState struct {
	rule    Rule
	matched int
}

// Fake is an in-memory, S3-speaking object store with fault injection. The
// zero value is not usable; construct one with New.
type Fake struct {
	// PageSize caps how many keys ListObjectsV2 returns on one page. Zero
	// means the S3 default of 1000. This is test-only state for cheaply
	// exercising pagination, never a walden knob.
	PageSize int

	srv    *httptest.Server
	bucket string

	mu      sync.Mutex
	objects map[string][]byte
	rules   []*ruleState
	calls   []Call
	seq     int
}

// New starts a Fake on an httptest.Server. t.Cleanup closes it.
func New(t testing.TB) *Fake {
	t.Helper()
	f := &Fake{
		bucket:  "walden-fake-bucket",
		objects: make(map[string][]byte),
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

// URL returns the fake's base URL, e.g. "http://127.0.0.1:port". The fake
// speaks path-style addressing only.
func (f *Fake) URL() string { return f.srv.URL }

// Bucket returns the fake's one fixed bucket name. A request naming any
// other bucket sees 404 NoSuchBucket.
func (f *Fake) Bucket() string { return f.bucket }

// Object returns a copy of the bytes stored at key (the full, bucket-
// relative key — including whatever prefix a Journal was given), and
// whether the key exists.
func (f *Fake) Object(key string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.objects[key]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), b...), true
}

// SetObject seeds key with b, for a test that wants existing state before
// the client under test ever sends a request.
func (f *Fake) SetObject(key string, b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = append([]byte(nil), b...)
}

// Keys returns every stored key in ascending order.
func (f *Fake) Keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	keys := make([]string, 0, len(f.objects))
	for k := range f.objects {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Calls returns the call log, in arrival order.
func (f *Fake) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Call(nil), f.calls...)
}

// Inject adds r to the fault rule table. Rules are evaluated in the order
// they were injected; the first whose Op, Key, and Call/Count window match
// a given request is the one that fires for it.
func (f *Fake) Inject(r Rule) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = append(f.rules, &ruleState{rule: r})
}

// matchRule advances the arrival counter and every rule whose Op and Key
// match this request, and returns the first fault whose Call/Count window
// the resulting count falls in (nil if none), plus this call's arrival
// index. It holds the state lock only long enough to do the bookkeeping —
// never across Fault.Delay or any I/O — so "a rule's call counter and the
// call log sit under the same lock as the objects" without that lock ever
// serializing unrelated concurrent requests behind a sleep.
func (f *Fake) matchRule(op Op, key string) (fault *Fault, n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	n = f.seq
	for _, rs := range f.rules {
		if rs.rule.Op != op {
			continue
		}
		if rs.rule.Key != "" && rs.rule.Key != key {
			continue
		}
		rs.matched++
		count := rs.rule.Count
		if count <= 0 {
			count = 1
		}
		if fault == nil && rs.matched >= rs.rule.Call && rs.matched < rs.rule.Call+count {
			fCopy := rs.rule.Fault
			fault = &fCopy
		}
	}
	return fault, n
}

// logCall appends one entry to the call log.
func (f *Fake) logCall(n int, op Op, key string, faulted, landed bool, status int) {
	f.mu.Lock()
	f.calls = append(f.calls, Call{N: n, Op: op, Key: key, Faulted: faulted, Landed: landed, Status: status})
	f.mu.Unlock()
}

// handle dispatches every request the fake receives.
func (f *Fake) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" {
		writeS3Error(w, http.StatusForbidden, "AccessDenied", "no Authorization header")
		return
	}
	bucket, key, ok := parsePath(r.URL.Path)
	if !ok || bucket != f.bucket {
		writeS3Error(w, http.StatusNotFound, "NoSuchBucket", "the specified bucket does not exist")
		return
	}

	switch {
	case r.Method == http.MethodPut && key != "":
		f.handlePut(w, r, key)
	case r.Method == http.MethodGet && key != "":
		f.handleGet(w, r, key)
	case r.Method == http.MethodGet && key == "" && r.URL.Query().Get("list-type") == "2":
		f.handleList(w, r)
	default:
		writeS3Error(w, http.StatusNotImplemented, "NotImplemented", "unsupported method or query")
	}
}

// parsePath splits a path-style request path "/bucket[/key...]" into its
// bucket and key. An empty path (bare "/") is never valid.
func parsePath(p string) (bucket, key string, ok bool) {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return "", "", false
	}
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return p[:i], p[i+1:], true
	}
	return p, "", true
}

// handlePut serves an unconditional PUT or a PutIfAbsent (If-None-Match:
// *) to key.
func (f *Fake) handlePut(w http.ResponseWriter, r *http.Request, key string) {
	if r.Header.Get("If-Match") != "" {
		writeS3Error(w, http.StatusNotImplemented, "NotImplemented", "If-Match is not supported")
		return
	}
	var op Op
	conditional := false
	switch r.Header.Get("If-None-Match") {
	case "":
		op = OpPut
	case "*":
		op = OpPutIfAbsent
		conditional = true
	default:
		writeS3Error(w, http.StatusNotImplemented, "NotImplemented", "If-None-Match is only supported as '*'")
		return
	}

	fault, n := f.matchRule(op, key)

	// TruncateBody is evaluated before the body is read at all: reading
	// exactly N bytes and then dropping the connection is what "cut
	// mid-transfer" means, and reading the full body first would defeat
	// that.
	if fault != nil && fault.TruncateBody > 0 {
		io.CopyN(io.Discard, r.Body, int64(fault.TruncateBody))
		f.logCall(n, op, key, true, false, 0)
		hijackDrop(w)
		return
	}

	body, err := readPutBody(r)
	if err != nil {
		f.logCall(n, op, key, fault != nil, false, http.StatusBadRequest)
		writeS3Error(w, http.StatusBadRequest, "IncompleteBody", err.Error())
		return
	}

	if fault != nil && fault.Delay > 0 {
		time.Sleep(fault.Delay)
	}
	if fault != nil && fault.Rival != nil {
		f.mu.Lock()
		f.objects[key] = append([]byte(nil), fault.Rival...)
		f.mu.Unlock()
	}

	if fault != nil && (fault.Status != 0 || fault.Drop) {
		landed := false
		if fault.Land {
			f.mu.Lock()
			f.objects[key] = append([]byte(nil), body...)
			f.mu.Unlock()
			landed = true
		}
		if fault.Drop {
			f.logCall(n, op, key, true, landed, 0)
			hijackDrop(w)
			return
		}
		f.logCall(n, op, key, true, landed, fault.Status)
		writeS3Error(w, fault.Status, fault.Code, "injected fault")
		return
	}

	ignoreCondition := fault != nil && fault.IgnoreCondition
	f.mu.Lock()
	_, exists := f.objects[key]
	if conditional && exists && !ignoreCondition {
		f.mu.Unlock()
		f.logCall(n, op, key, fault != nil, false, http.StatusPreconditionFailed)
		writeS3Error(w, http.StatusPreconditionFailed, "PreconditionFailed", "At least one of the pre-conditions you specified did not hold")
		return
	}
	f.objects[key] = append([]byte(nil), body...)
	f.mu.Unlock()
	f.logCall(n, op, key, fault != nil, true, http.StatusOK)
	w.WriteHeader(http.StatusOK)
}

// handleGet serves a GET of one object.
func (f *Fake) handleGet(w http.ResponseWriter, r *http.Request, key string) {
	fault, n := f.matchRule(OpGet, key)

	if fault != nil && fault.Delay > 0 {
		time.Sleep(fault.Delay)
	}
	if fault != nil && fault.Rival != nil {
		f.mu.Lock()
		f.objects[key] = append([]byte(nil), fault.Rival...)
		f.mu.Unlock()
	}

	if fault != nil && (fault.Status != 0 || fault.Drop) {
		if fault.Drop {
			f.logCall(n, OpGet, key, true, false, 0)
			hijackDrop(w)
			return
		}
		f.logCall(n, OpGet, key, true, false, fault.Status)
		writeS3Error(w, fault.Status, fault.Code, "injected fault")
		return
	}

	f.mu.Lock()
	obj, exists := f.objects[key]
	f.mu.Unlock()

	if !exists {
		f.logCall(n, OpGet, key, fault != nil, false, http.StatusNotFound)
		writeS3Error(w, http.StatusNotFound, "NoSuchKey", "the specified key does not exist")
		return
	}

	if fault != nil && fault.TruncateBody > 0 {
		f.logCall(n, OpGet, key, true, true, http.StatusOK)
		cut := fault.TruncateBody
		if cut > len(obj) {
			cut = len(obj)
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(obj)))
		w.WriteHeader(http.StatusOK)
		w.Write(obj[:cut])
		hijackDrop(w)
		return
	}

	f.logCall(n, OpGet, key, fault != nil, true, http.StatusOK)
	w.Header().Set("Content-Length", strconv.Itoa(len(obj)))
	w.WriteHeader(http.StatusOK)
	w.Write(obj)
}

// handleList serves a ListObjectsV2 request against the bucket root.
func (f *Fake) handleList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	prefix := q.Get("prefix")
	startAfter := q.Get("start-after")
	token := q.Get("continuation-token")

	fault, n := f.matchRule(OpList, prefix)

	if fault != nil && fault.Delay > 0 {
		time.Sleep(fault.Delay)
	}

	if fault != nil && (fault.Status != 0 || fault.Drop) {
		if fault.Drop {
			f.logCall(n, OpList, prefix, true, false, 0)
			hijackDrop(w)
			return
		}
		f.logCall(n, OpList, prefix, true, false, fault.Status)
		writeS3Error(w, fault.Status, fault.Code, "injected fault")
		return
	}

	f.mu.Lock()
	pageSize := f.PageSize
	keys := make([]string, 0, len(f.objects))
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	f.mu.Unlock()
	sort.Strings(keys)
	if pageSize <= 0 {
		pageSize = 1000
	}

	after := startAfter
	if token != "" {
		after = token
	}
	start := sort.Search(len(keys), func(i int) bool { return keys[i] > after })
	end := start + pageSize
	if end > len(keys) {
		end = len(keys)
	}
	page := keys[start:end]
	truncated := end < len(keys)
	next := ""
	if truncated {
		next = page[len(page)-1]
	}

	f.logCall(n, OpList, prefix, fault != nil, true, http.StatusOK)
	writeListResult(w, f.bucket, prefix, page, truncated, next)
}

// hijackDrop closes the underlying connection with no further response.
// Every caller has already read (or deliberately not read) whatever body
// it cares about before calling this, so the drop always lands at a clean
// framing boundary from the fake's own point of view — what the client
// makes of a connection closing there is exactly what this package exists
// to let a test observe.
func hijackDrop(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	conn.Close()
}

// readPutBody reads and validates a PUT body, decoding Content-Encoding:
// aws-chunked when present. It returns an error - never the raw bytes
// received so far - when the decoded length does not match what the
// request declared: per spec/journal/v1, S3 PUT is atomic, so a fake that
// stored a short body would not model that.
func readPutBody(r *http.Request) ([]byte, error) {
	if r.Header.Get("Content-Encoding") == "aws-chunked" {
		declared, err := strconv.ParseInt(r.Header.Get("X-Amz-Decoded-Content-Length"), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("missing or invalid X-Amz-Decoded-Content-Length")
		}
		data, err := decodeAWSChunked(r.Body)
		if err != nil {
			return nil, err
		}
		if int64(len(data)) != declared {
			return nil, fmt.Errorf("decoded body is %d bytes, X-Amz-Decoded-Content-Length declared %d", len(data), declared)
		}
		return data, nil
	}

	declared := r.ContentLength
	if declared < 0 {
		return nil, fmt.Errorf("missing Content-Length")
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, declared+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != declared {
		return nil, fmt.Errorf("body is %d bytes, Content-Length declared %d", len(data), declared)
	}
	return data, nil
}

// decodeAWSChunked reads the aws-chunked framing newChunkedBody (sigv4.go)
// writes — hex(len);chunk-signature=<sig>\r\n<data>\r\n, ending with a
// zero-length final chunk — and returns the concatenated chunk data.
// Signatures are not checked; see the package comment for why.
func decodeAWSChunked(r io.Reader) ([]byte, error) {
	br := bufio.NewReader(r)
	var out bytes.Buffer
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("aws-chunked: reading chunk header: %w", err)
		}
		sizeField := strings.TrimRight(line, "\r\n")
		if i := strings.IndexByte(sizeField, ';'); i >= 0 {
			sizeField = sizeField[:i]
		}
		size, err := strconv.ParseInt(sizeField, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("aws-chunked: invalid chunk size %q: %w", sizeField, err)
		}
		if size == 0 {
			if _, err := br.ReadString('\n'); err != nil && err != io.EOF {
				return nil, fmt.Errorf("aws-chunked: reading final chunk terminator: %w", err)
			}
			return out.Bytes(), nil
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, fmt.Errorf("aws-chunked: reading chunk data: %w", err)
		}
		out.Write(buf)
		if _, err := br.ReadString('\n'); err != nil {
			return nil, fmt.Errorf("aws-chunked: reading chunk terminator: %w", err)
		}
	}
}

// s3Error is the minimal S3 XML error body: the fake's Client only ever
// reads <Code>, so nothing else is worth modelling.
type s3Error struct {
	XMLName xml.Name `xml:"Error"`
	Code    string   `xml:"Code"`
	Message string   `xml:"Message"`
}

func writeS3Error(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	body, _ := xml.Marshal(s3Error{Code: code, Message: message})
	w.Write([]byte(xml.Header))
	w.Write(body)
}

// listContent is one <Contents> entry of a ListObjectsV2 page.
type listContent struct {
	Key string `xml:"Key"`
}

// listBucketResult is the ListObjectsV2 response body, holding only the
// fields store.Client's List (list.go) decodes plus enough surrounding
// structure to look like a real page.
type listBucketResult struct {
	XMLName               xml.Name      `xml:"ListBucketResult"`
	Name                  string        `xml:"Name"`
	Prefix                string        `xml:"Prefix"`
	KeyCount              int           `xml:"KeyCount"`
	MaxKeys               int           `xml:"MaxKeys"`
	IsTruncated           bool          `xml:"IsTruncated"`
	NextContinuationToken string        `xml:"NextContinuationToken,omitempty"`
	Contents              []listContent `xml:"Contents"`
}

func writeListResult(w http.ResponseWriter, bucket, prefix string, keys []string, truncated bool, next string) {
	result := listBucketResult{
		Name:                  bucket,
		Prefix:                prefix,
		KeyCount:              len(keys),
		MaxKeys:               1000,
		IsTruncated:           truncated,
		NextContinuationToken: next,
	}
	for _, k := range keys {
		result.Contents = append(result.Contents, listContent{Key: k})
	}
	body, _ := xml.Marshal(result)
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(xml.Header))
	w.Write(body)
}
