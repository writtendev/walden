// Package storetest is an in-memory, S3-speaking fake of the object storage
// the journal lives in: PUT, conditional PUT (If-None-Match: *), GET,
// ListObjectsV2, and DELETE, running as a real http.Handler on an
// httptest.Server. It exists so store.Client (sigv4, aws-chunked, retry/
// classify — see
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
//     body — stores nothing and answers 400 IncompleteBody. An aws-chunked
//     PUT sent with no Content-Length at all stores nothing and answers 411
//     MissingContentLength instead, matching real S3.
//   - GET returns 200 with the bytes, or 404 NoSuchKey.
//   - ListObjectsV2 requires list-type=2. It honours prefix, start-after
//     (ignored once a continuation token is present), and a continuation
//     token that is genuinely opaque: the fake mints it and is the only
//     thing that can resolve it back to a key, so anything else — garbage,
//     or a client fabricating one out of a key it saw in a page — answers
//     400 InvalidArgument rather than being accepted at face value. Results
//     are in strict ascending key order. Fake.PageSize caps a page (1000 by
//     default, S3's own default) so a test can exercise pagination without
//     seeding a thousand keys.
//   - DELETE removes the key unconditionally and returns 204, whether or
//     not the key existed (idempotent, matching real S3 and
//     store.Client.Delete's contract). WALD-23 added this for the boot
//     probe's cleanup; it is otherwise unconditional and carries no
//     precondition handling of its own.
//   - Any other method or query — an unrecognised list query, an object
//     PUT carrying a query string — returns 501 NotImplemented, so a
//     missing capability fails loudly rather than silently passing.
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
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	// OpDelete is an unconditional DELETE of one object.
	OpDelete
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
	case OpDelete:
		return "DELETE"
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
	// second attempt at the same key is call 2. Call must be >= 1: a zero
	// Call would never match any request's 1-based count and so would
	// silently never fire, which Inject refuses rather than accept.
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
	tokens  map[string]string
}

// New starts a Fake on an httptest.Server. t.Cleanup closes it.
func New(t testing.TB) *Fake {
	t.Helper()
	f := &Fake{
		bucket:  "walden-fake-bucket",
		objects: make(map[string][]byte),
		tokens:  make(map[string]string),
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
//
// Inject panics if r.Call <= 0. Such a rule can never match a request's
// 1-based arrival count, so it would silently never fire - exactly the
// false confidence (a test that believes it injected a fault when it
// injected nothing) this package exists to prevent.
func (f *Fake) Inject(r Rule) {
	if r.Call <= 0 {
		panic(fmt.Sprintf("storetest: Inject: Rule.Call must be >= 1, got %d (Op %v, Key %q); a zero Call would never fire", r.Call, r.Op, r.Key))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = append(f.rules, &ruleState{rule: r})
}

// matchRule advances the arrival counter and every rule whose Op and Key
// match this request, and returns the first fault whose Call/Count window
// the resulting count falls in (nil if none), plus this call's arrival
// index. It also appends this call's entry to the call log immediately,
// in arrival order, with Faulted already known but Landed/Status still
// zero - updateCall fills those in once the request has actually been
// resolved, which can happen well after arrival (Fault.Delay, a slow
// body). Recording at arrival rather than completion is what makes
// Calls() "in arrival order" true under concurrency, not just when
// requests happen to complete in the order they arrived.
//
// It holds the state lock only long enough to do the bookkeeping - never
// across Fault.Delay or any I/O - so "a rule's call counter and the call
// log sit under the same lock as the objects" without that lock ever
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
	f.calls = append(f.calls, Call{N: n, Op: op, Key: key, Faulted: fault != nil})
	return fault, n
}

// updateCall fills in the Landed and Status fields of the call log entry
// matchRule already recorded for arrival index n, once the request has
// actually been resolved. n is 1-based and calls are only ever appended,
// never removed or reordered, so n-1 is always a valid, stable index into
// f.calls regardless of how many later calls have arrived since.
func (f *Fake) updateCall(n int, landed bool, status int) {
	f.mu.Lock()
	f.calls[n-1].Landed = landed
	f.calls[n-1].Status = status
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
	case r.Method == http.MethodPut && key != "" && r.URL.RawQuery == "":
		f.handlePut(w, r, key)
	case r.Method == http.MethodGet && key != "" && r.URL.RawQuery == "":
		f.handleGet(w, r, key)
	case r.Method == http.MethodGet && key == "" && isListQuery(r.URL.Query()):
		f.handleList(w, r)
	case r.Method == http.MethodDelete && key != "" && r.URL.RawQuery == "":
		f.handleDelete(w, r, key)
	default:
		writeS3Error(w, http.StatusNotImplemented, "NotImplemented", "unsupported method or query")
	}
}

// listQueryParams are the only query keys ListObjectsV2 requests ever
// carry in this fake: what store.Client's List (list.go) actually sends.
// walden never asks for a delimiter, max-keys, or encoding-type, so this
// fake does not model them; a request naming one gets 501, the same as
// any other unsupported sub-resource or parameter, rather than a
// silently-accepted response real S3 would answer differently.
var listQueryParams = map[string]bool{
	"list-type":          true,
	"prefix":             true,
	"start-after":        true,
	"continuation-token": true,
}

// isListQuery reports whether q is exactly a ListObjectsV2 request this
// fake understands: list-type=2 and nothing outside listQueryParams. A PUT
// or GET against an object key never carries a query string at all here
// (walden's client never sends one, so ?acl, ?tagging, and the like all
// fall through to the unsupported-method-or-query default and get 501).
func isListQuery(q url.Values) bool {
	if q.Get("list-type") != "2" {
		return false
	}
	for k := range q {
		if !listQueryParams[k] {
			return false
		}
	}
	return true
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
		f.updateCall(n, false, 0)
		hijackDrop(w)
		return
	}

	body, err := readPutBody(r)
	if err != nil {
		status := http.StatusBadRequest
		code := "IncompleteBody"
		if pbErr, ok := err.(*putBodyError); ok {
			status = pbErr.status
			code = pbErr.code
		}
		f.updateCall(n, false, status)
		writeS3Error(w, status, code, err.Error())
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

	ignoreCondition := fault != nil && fault.IgnoreCondition

	if fault != nil && (fault.Status != 0 || fault.Drop) {
		// Land means "the write actually happens, under the same
		// condition a normal request would enforce, before the fault
		// response lies about the result" - never an unconditional
		// overwrite. A conditional PUT against an existing key (and no
		// IgnoreCondition) must leave that key untouched even when Land
		// is set, exactly as a real CAS provider would: the condition is
		// evaluated first, and only a passing condition lands anything.
		landed := false
		if fault.Land {
			f.mu.Lock()
			_, exists := f.objects[key]
			if !(conditional && exists && !ignoreCondition) {
				f.objects[key] = append([]byte(nil), body...)
				landed = true
			}
			f.mu.Unlock()
		}
		if fault.Drop {
			f.updateCall(n, landed, 0)
			hijackDrop(w)
			return
		}
		f.updateCall(n, landed, fault.Status)
		writeS3Error(w, fault.Status, fault.Code, "injected fault")
		return
	}

	f.mu.Lock()
	_, exists := f.objects[key]
	if conditional && exists && !ignoreCondition {
		f.mu.Unlock()
		f.updateCall(n, false, http.StatusPreconditionFailed)
		writeS3Error(w, http.StatusPreconditionFailed, "PreconditionFailed", "At least one of the pre-conditions you specified did not hold")
		return
	}
	f.objects[key] = append([]byte(nil), body...)
	f.mu.Unlock()
	f.updateCall(n, true, http.StatusOK)
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
			f.updateCall(n, false, 0)
			hijackDrop(w)
			return
		}
		f.updateCall(n, false, fault.Status)
		writeS3Error(w, fault.Status, fault.Code, "injected fault")
		return
	}

	f.mu.Lock()
	obj, exists := f.objects[key]
	f.mu.Unlock()

	if !exists {
		f.updateCall(n, false, http.StatusNotFound)
		writeS3Error(w, http.StatusNotFound, "NoSuchKey", "the specified key does not exist")
		return
	}

	if fault != nil && fault.TruncateBody > 0 {
		f.updateCall(n, true, http.StatusOK)
		cut := fault.TruncateBody
		if cut > len(obj) {
			cut = len(obj)
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(obj)))
		w.WriteHeader(http.StatusOK)
		w.Write(obj[:cut])
		// Flush before hijacking: without it, the N bytes just written
		// are still sitting in the ResponseWriter's own buffer, and
		// hijackDrop's conn.Close() discards them unsent - the client
		// would see headers followed immediately by EOF regardless of N,
		// never the "headers + N bytes, then drop" this fault promises
		// to model.
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		hijackDrop(w)
		return
	}

	f.updateCall(n, true, http.StatusOK)
	w.Header().Set("Content-Length", strconv.Itoa(len(obj)))
	w.WriteHeader(http.StatusOK)
	w.Write(obj)
}

// handleDelete serves an unconditional DELETE of one object. It is
// idempotent, matching store.Client.Delete's contract: a key that does not
// exist still answers 204, never 404 - real S3 behaves the same way, and
// walden relies on it so a retried delete after a dropped response is never
// mistaken for a failure.
func (f *Fake) handleDelete(w http.ResponseWriter, r *http.Request, key string) {
	fault, n := f.matchRule(OpDelete, key)

	if fault != nil && fault.Delay > 0 {
		time.Sleep(fault.Delay)
	}

	if fault != nil && (fault.Status != 0 || fault.Drop) {
		landed := false
		if fault.Land {
			f.mu.Lock()
			_, existed := f.objects[key]
			delete(f.objects, key)
			f.mu.Unlock()
			landed = existed
		}
		if fault.Drop {
			f.updateCall(n, landed, 0)
			hijackDrop(w)
			return
		}
		f.updateCall(n, landed, fault.Status)
		writeS3Error(w, fault.Status, fault.Code, "injected fault")
		return
	}

	f.mu.Lock()
	_, existed := f.objects[key]
	delete(f.objects, key)
	f.mu.Unlock()

	f.updateCall(n, existed, http.StatusNoContent)
	w.WriteHeader(http.StatusNoContent)
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
			f.updateCall(n, false, 0)
			hijackDrop(w)
			return
		}
		f.updateCall(n, false, fault.Status)
		writeS3Error(w, fault.Status, fault.Code, "injected fault")
		return
	}

	// A continuation token is opaque: it must be one this fake actually
	// issued (see issueToken/resolveToken), never a client-supplied
	// string accepted at face value - real S3 answers 400 InvalidArgument
	// to a token it did not mint, and a fake that accepted any string
	// (including the raw last key a broken client fabricated one from)
	// would let that bug pass.
	after := startAfter
	if token != "" {
		key, ok := f.resolveToken(token)
		if !ok {
			f.updateCall(n, false, http.StatusBadRequest)
			writeS3Error(w, http.StatusBadRequest, "InvalidArgument", "invalid continuation token")
			return
		}
		after = key
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

	start := sort.Search(len(keys), func(i int) bool { return keys[i] > after })
	end := start + pageSize
	if end > len(keys) {
		end = len(keys)
	}
	page := keys[start:end]
	truncated := end < len(keys)
	next := ""
	if truncated {
		next = f.issueToken(page[len(page)-1])
	}

	f.updateCall(n, true, http.StatusOK)
	writeListResult(w, f.bucket, prefix, page, truncated, next)
}

// issueToken mints an opaque continuation token for lastKey and records
// the mapping so a later request carrying it can be resolved back to a
// real key - see resolveToken. The token itself carries no derivable
// relationship to lastKey (it is random bytes, not an encoding of it), so
// a client cannot fabricate one from a key it happened to see in a
// response body the way it could if the token were, say, the key itself
// or a reversible encoding of it.
func (f *Fake) issueToken(lastKey string) string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic(fmt.Sprintf("storetest: generating continuation token: %v", err))
	}
	token := hex.EncodeToString(buf[:])
	f.mu.Lock()
	f.tokens[token] = lastKey
	f.mu.Unlock()
	return token
}

// resolveToken looks up a continuation-token this fake actually issued via
// issueToken. ok is false for anything else - garbage, a stale token from
// a different Fake, or a client fabricating one out of a key it saw in an
// earlier page - so handleList can answer 400 InvalidArgument instead of
// silently restarting the listing or resuming from an arbitrary point.
func (f *Fake) resolveToken(token string) (key string, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key, ok = f.tokens[token]
	return key, ok
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

// putBodyError carries the S3 status and error code readPutBody wants the
// caller to answer with. Not every malformed-body case is the same error:
// a missing Content-Length on an aws-chunked PUT is 411
// MissingContentLength - real S3's answer to a request it cannot even
// frame, since aws-chunked's own outer transfer still needs a declared
// length even though the decoded payload length travels separately in
// X-Amz-Decoded-Content-Length - while every other short-or-malformed
// body is 400 IncompleteBody. A plain error defaults to IncompleteBody in
// the caller, so this type only needs constructing where the status
// actually differs.
type putBodyError struct {
	status int
	code   string
	msg    string
}

func (e *putBodyError) Error() string { return e.msg }

// readPutBody reads and validates a PUT body, decoding Content-Encoding:
// aws-chunked when present. It returns an error - never the raw bytes
// received so far - when the decoded length does not match what the
// request declared: per spec/journal/v1, S3 PUT is atomic, so a fake that
// stored a short body would not model that.
func readPutBody(r *http.Request) ([]byte, error) {
	if r.Header.Get("Content-Encoding") == "aws-chunked" {
		// aws-chunked framing carries its own X-Amz-Decoded-Content-Length,
		// but the outer request must still declare Content-Length for the
		// framed (chunk-header-and-terminator-inclusive) transfer - real S3
		// requires this even though the two lengths differ, and answers
		// 411 MissingContentLength to a request sent without it (typically
		// one where Transfer-Encoding: chunked replaced the declared
		// length entirely). client.go relies on exactly this.
		if r.ContentLength < 0 {
			return nil, &putBodyError{status: http.StatusLengthRequired, code: "MissingContentLength", msg: "aws-chunked PUT requires Content-Length"}
		}
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

// maxChunkSize bounds a single aws-chunked chunk's declared size.
// store.Client only ever sends 64 KiB chunks (chunkSize in client.go), so
// this is generously larger than any legitimate chunk while still small
// enough that a malformed or hostile size field can't force decodeAWSChunked
// into an enormous allocation.
const maxChunkSize = 64 << 20 // 64 MiB

// decodeAWSChunked reads the aws-chunked framing newChunkedBody (sigv4.go)
// writes — hex(len);chunk-signature=<sig>\r\n<data>\r\n, ending with a
// zero-length final chunk — and returns the concatenated chunk data.
// Signatures are not checked; see the package comment for why. The
// terminator after each chunk's data, and after the final zero-length
// chunk's header, must be exactly "\r\n": readCRLF rejects a bare "\n",
// junk before the newline, or a connection that ends before the
// terminator arrives, rather than accepting anything short of an outright
// read error the way a bare "any line" scan would.
func decodeAWSChunked(r io.Reader) ([]byte, error) {
	br := bufio.NewReader(r)
	var out bytes.Buffer
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("aws-chunked: reading chunk header: %w", err)
		}
		// The chunk header line must end in an exact CRLF, the same as
		// every other framing terminator in this format - a bare "\n" is
		// not one real S3 accepts, so TrimRight (which would silently
		// strip a lone "\n" the same as "\r\n") is deliberately not used
		// here.
		if !strings.HasSuffix(line, "\r\n") {
			return nil, fmt.Errorf("aws-chunked: chunk header line must end in CRLF, got %q", line)
		}
		sizeField := strings.TrimSuffix(line, "\r\n")
		if i := strings.IndexByte(sizeField, ';'); i >= 0 {
			sizeField = sizeField[:i]
		}
		size, err := strconv.ParseInt(sizeField, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("aws-chunked: invalid chunk size %q: %w", sizeField, err)
		}
		// A negative size passes ParseInt (hex allows a leading '-') but
		// would panic make() below; a chunk larger than maxChunkSize is
		// never legitimate either - store.Client only ever sends 64 KiB
		// chunks (chunkSize in client.go) - so both are refused the same
		// way a malformed size field is, rather than left to crash the
		// handler or force an enormous allocation.
		if size < 0 || size > maxChunkSize {
			return nil, fmt.Errorf("aws-chunked: invalid chunk size %q: out of range", sizeField)
		}
		if size == 0 {
			if err := readCRLF(br); err != nil {
				return nil, fmt.Errorf("aws-chunked: reading final chunk terminator: %w", err)
			}
			return out.Bytes(), nil
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, fmt.Errorf("aws-chunked: reading chunk data: %w", err)
		}
		out.Write(buf)
		if err := readCRLF(br); err != nil {
			return nil, fmt.Errorf("aws-chunked: reading chunk terminator: %w", err)
		}
	}
}

// readCRLF reads exactly two bytes from r and requires them to be "\r\n".
// aws-chunked framing always uses CRLF terminators (real S3, and
// newChunkedBody in sigv4.go, both do); a bare "\n", stray bytes before
// the newline, or the stream ending early are all malformed framing this
// fake refuses rather than silently tolerates.
func readCRLF(r io.Reader) error {
	var buf [2]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return fmt.Errorf("want CRLF: %w", err)
	}
	if buf[0] != '\r' || buf[1] != '\n' {
		return fmt.Errorf("want CRLF, got %q", buf[:])
	}
	return nil
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
