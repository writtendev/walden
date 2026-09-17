// Raw net/http tests of the fake's own semantics, independent of
// store.Client. This is the drift guard the WALD-24 plan calls for: the
// main risk with a fake object store is that its conditional semantics
// quietly diverge from spec/journal/v1 §11.1/§11.4.6, and a client-driven
// test alone would not catch that — it would just mean the client and the
// fake made the same mistake together. This file imports no walden package
// at all, only net/http and the fake itself.
package storetest_test

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/store/storetest"
)

// doRequest sends method to fake's key (bucket-relative) with an
// Authorization header (the fake does not verify it, only requires it) and
// the given body/headers, and returns the response with its body already
// read and the response closed.
type response struct {
	status int
	body   []byte
	header http.Header
}

func doRequest(t *testing.T, fake *storetest.Fake, method, key string, body []byte, extraHeaders map[string]string) response {
	t.Helper()
	req, err := http.NewRequest(method, fake.URL()+"/"+fake.Bucket()+"/"+key, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != nil {
		req.ContentLength = int64(len(body))
	}
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=test/test")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	return response{status: resp.StatusCode, body: b, header: resp.Header}
}

func s3Code(t *testing.T, body []byte) string {
	t.Helper()
	var parsed struct {
		Code string `xml:"Code"`
	}
	if err := xml.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("unmarshaling S3 error body %q: %v", body, err)
	}
	return parsed.Code
}

// doList sends a GET against the bucket root with the given raw query
// string, the same shape TestListPagination already builds by hand -
// factored out here so the query-rejection and start-after tests below
// don't each re-duplicate it.
func doList(t *testing.T, fake *storetest.Fake, query string) response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, fake.URL()+"/"+fake.Bucket()+"?"+query, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "x")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	return response{status: resp.StatusCode, body: b, header: resp.Header}
}

// rawConn opens a raw TCP connection to fake. Tests that need to put
// bytes on the wire net/http's own client would refuse to send - a body
// shorter than its declared Content-Length, or aws-chunked framing with
// deliberately wrong terminators - dial this instead of using doRequest.
func rawConn(t *testing.T, fake *storetest.Fake) (conn net.Conn, addr string) {
	t.Helper()
	addr = strings.TrimPrefix(fake.URL(), "http://")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	return conn, addr
}

// rawPut sends a PUT of exactly body's bytes - no more, no less - as a
// raw TCP request to fake, with headers set verbatim (the caller supplies
// Content-Length itself, since the whole point is sending a length that
// may not match what a well-behaved client would compute). It half-closes
// the connection's write side once body is written so the server sees a
// clean EOF instead of hanging, then reads back the response.
func rawPut(t *testing.T, fake *storetest.Fake, key string, headers map[string]string, body []byte) (status int, respBody []byte) {
	t.Helper()
	conn, addr := rawConn(t, fake)
	defer conn.Close()

	var req bytes.Buffer
	fmt.Fprintf(&req, "PUT /%s/%s HTTP/1.1\r\n", fake.Bucket(), key)
	fmt.Fprintf(&req, "Host: %s\r\n", addr)
	req.WriteString("Authorization: x\r\n")
	req.WriteString("Connection: close\r\n")
	for k, v := range headers {
		fmt.Fprintf(&req, "%s: %s\r\n", k, v)
	}
	req.WriteString("\r\n")
	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatalf("writing request head: %v", err)
	}
	if _, err := conn.Write(body); err != nil {
		t.Fatalf("writing request body: %v", err)
	}
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	return resp.StatusCode, b
}

// TestConditionalCreateThenPrecondition covers case 1: a conditional
// create on an absent key succeeds and stores the object; a second attempt
// at the same key is a real 412 with the original bytes untouched; a plain
// PUT overwrites.
func TestConditionalCreateThenPrecondition(t *testing.T) {
	fake := storetest.New(t)

	first := doRequest(t, fake, http.MethodPut, "k", []byte("first"), map[string]string{"If-None-Match": "*"})
	if first.status != http.StatusOK {
		t.Fatalf("first conditional create: status = %d, want 200", first.status)
	}
	if b, ok := fake.Object("k"); !ok || string(b) != "first" {
		t.Fatalf("Object(%q) = %q, %v, want %q, true", "k", b, ok, "first")
	}

	second := doRequest(t, fake, http.MethodPut, "k", []byte("second"), map[string]string{"If-None-Match": "*"})
	if second.status != http.StatusPreconditionFailed {
		t.Fatalf("second conditional create: status = %d, want 412", second.status)
	}
	if code := s3Code(t, second.body); code != "PreconditionFailed" {
		t.Errorf("second conditional create: Code = %q, want PreconditionFailed", code)
	}
	if b, _ := fake.Object("k"); string(b) != "first" {
		t.Errorf("object after failed conditional create = %q, want %q (untouched)", b, "first")
	}

	overwrite := doRequest(t, fake, http.MethodPut, "k", []byte("third"), nil)
	if overwrite.status != http.StatusOK {
		t.Fatalf("unconditional overwrite: status = %d, want 200", overwrite.status)
	}
	if b, _ := fake.Object("k"); string(b) != "third" {
		t.Errorf("object after unconditional overwrite = %q, want %q", b, "third")
	}
}

// TestConditionalCreateConcurrent covers case 2: fifty goroutines racing a
// conditional create at the same key see exactly one 200 and forty-nine
// 412s, under -race.
func TestConditionalCreateConcurrent(t *testing.T) {
	fake := storetest.New(t)

	const n = 50
	var wg sync.WaitGroup
	statuses := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp := doRequest(t, fake, http.MethodPut, "race", []byte("x"), map[string]string{"If-None-Match": "*"})
			statuses[i] = resp.status
		}(i)
	}
	wg.Wait()

	var ok, failed int
	for _, s := range statuses {
		switch s {
		case http.StatusOK:
			ok++
		case http.StatusPreconditionFailed:
			failed++
		default:
			t.Errorf("unexpected status %d", s)
		}
	}
	if ok != 1 {
		t.Errorf("200 count = %d, want 1", ok)
	}
	if failed != n-1 {
		t.Errorf("412 count = %d, want %d", failed, n-1)
	}
}

// TestUnsupportedConditionsAndAuth covers case 3: If-Match is refused,
// missing auth is refused, and an unknown bucket is refused - each with
// its own status and Code.
func TestUnsupportedConditionsAndAuth(t *testing.T) {
	fake := storetest.New(t)

	ifMatch := doRequest(t, fake, http.MethodPut, "k", []byte("x"), map[string]string{"If-Match": "\"etag\""})
	if ifMatch.status != http.StatusNotImplemented {
		t.Errorf("If-Match: status = %d, want 501", ifMatch.status)
	}

	req, err := http.NewRequest(http.MethodGet, fake.URL()+"/"+fake.Bucket()+"/k", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("missing Authorization: status = %d, want 403", resp.StatusCode)
	}

	req2, err := http.NewRequest(http.MethodGet, fake.URL()+"/not-the-bucket/k", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req2.Header.Set("Authorization", "x")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("unknown bucket: status = %d, want 404", resp2.StatusCode)
	}
	if code := s3Code(t, body2); code != "NoSuchBucket" {
		t.Errorf("unknown bucket: Code = %q, want NoSuchBucket", code)
	}
}

// TestShortBodyStoresNothing covers case 4: a body shorter than its
// declared length - raw Content-Length for an unencoded body, or a
// truncated aws-chunked stream - stores nothing and answers 400, and a
// well-formed aws-chunked body decodes to the same bytes a raw body
// would.
//
// This drives the fake over a raw TCP connection (rawPut) rather than
// net/http's client: net/http itself refuses to send a request whose
// body is shorter than its declared Content-Length ("http:
// ContentLength=10 with Body length 2"), so a test built on
// http.NewRequest never reaches the fake at all - 0 calls, and
// decodeAWSChunked plus readPutBody's short-body path both go untested.
func TestShortBodyStoresNothing(t *testing.T) {
	fake := storetest.New(t)

	status, _ := rawPut(t, fake, "short", map[string]string{"Content-Length": "10"}, []byte("ab"))
	if status != http.StatusBadRequest {
		t.Errorf("short raw body: status = %d, want 400", status)
	}
	if _, ok := fake.Object("short"); ok {
		t.Errorf("short raw body stored an object, want none")
	}

	full := encodeChunked(t, []byte("hello world"))
	truncated := full[:len(full)-5] // cuts off the final chunk's terminator
	chunkedStatus, _ := rawPut(t, fake, "shortchunked", map[string]string{
		"Content-Length":               strconv.Itoa(len(full)),
		"Content-Encoding":             "aws-chunked",
		"X-Amz-Decoded-Content-Length": "11",
	}, truncated)
	if chunkedStatus != http.StatusBadRequest {
		t.Errorf("truncated aws-chunked body: status = %d, want 400", chunkedStatus)
	}
	if _, ok := fake.Object("shortchunked"); ok {
		t.Errorf("truncated aws-chunked body stored an object, want none")
	}

	raw := doRequest(t, fake, http.MethodPut, "raw", []byte("hello world"), nil)
	if raw.status != http.StatusOK {
		t.Fatalf("raw body PUT: status = %d, want 200", raw.status)
	}
	chunked := doRequest(t, fake, http.MethodPut, "chunked", encodeChunked(t, []byte("hello world")), map[string]string{
		"Content-Encoding":             "aws-chunked",
		"X-Amz-Decoded-Content-Length": "11",
	})
	if chunked.status != http.StatusOK {
		t.Fatalf("aws-chunked body PUT: status = %d, want 200", chunked.status)
	}
	rawBytes, _ := fake.Object("raw")
	chunkedBytes, _ := fake.Object("chunked")
	if string(rawBytes) != string(chunkedBytes) || string(rawBytes) != "hello world" {
		t.Errorf("raw = %q, chunked = %q, want both %q", rawBytes, chunkedBytes, "hello world")
	}
}

// encodeChunked frames data as a single aws-chunked chunk plus the
// mandatory zero-length final chunk, in the same wire shape
// newChunkedBody (internal/store/sigv4.go) produces. The signature field
// is a placeholder: the fake does not check it.
func encodeChunked(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%x;chunk-signature=%s\r\n", len(data), strings.Repeat("0", 64))
	buf.Write(data)
	buf.WriteString("\r\n")
	fmt.Fprintf(&buf, "0;chunk-signature=%s\r\n\r\n", strings.Repeat("0", 64))
	return buf.Bytes()
}

// TestListPagination covers case 5: pagination with a small PageSize over
// ten keys returns every key exactly once, ascending, honouring prefix
// filtering, start-after, and advancing tokens.
func TestListPagination(t *testing.T) {
	fake := storetest.New(t)
	fake.PageSize = 3

	var want []string
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("p/%02d", i)
		fake.SetObject(key, []byte("v"))
		want = append(want, key)
	}
	fake.SetObject("other/00", []byte("v")) // outside the prefix below

	var got []string
	token := ""
	startAfter := ""
	for page := 0; page < 20; page++ {
		query := "list-type=2&prefix=p/"
		if token != "" {
			query += "&continuation-token=" + token
		} else if startAfter != "" {
			query += "&start-after=" + startAfter
		}
		req, err := http.NewRequest(http.MethodGet, fake.URL()+"/"+fake.Bucket()+"?"+query, nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Authorization", "x")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("List page %d: status = %d, want 200", page, resp.StatusCode)
		}
		var result struct {
			IsTruncated           bool   `xml:"IsTruncated"`
			NextContinuationToken string `xml:"NextContinuationToken"`
			Contents              []struct {
				Key string `xml:"Key"`
			} `xml:"Contents"`
		}
		if err := xml.Unmarshal(body, &result); err != nil {
			t.Fatalf("unmarshaling list page %d: %v", page, err)
		}
		if len(result.Contents) > 3 {
			t.Errorf("page %d: %d keys, want at most PageSize=3", page, len(result.Contents))
		}
		for _, c := range result.Contents {
			got = append(got, c.Key)
		}
		if !result.IsTruncated {
			break
		}
		if result.NextContinuationToken == "" {
			t.Fatalf("page %d: truncated with no continuation token", page)
		}
		token = result.NextContinuationToken
	}

	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("listed keys = %v, want %v", got, want)
	}
}

// TestRuleTargeting covers case 6: Call/Count target exactly the calls
// named, and Calls() records the burst faithfully.
func TestRuleTargeting(t *testing.T) {
	fake := storetest.New(t)
	fake.Inject(storetest.Rule{
		Op: storetest.OpPut, Key: "k", Call: 3, Count: 2,
		Fault: storetest.Fault{Status: http.StatusServiceUnavailable, Code: "SlowDown"},
	})

	var statuses []int
	for i := 0; i < 5; i++ {
		resp := doRequest(t, fake, http.MethodPut, "k", []byte("x"), nil)
		statuses = append(statuses, resp.status)
	}

	want := []int{200, 200, 503, 503, 200}
	for i, s := range statuses {
		if s != want[i] {
			t.Errorf("call %d: status = %d, want %d", i+1, s, want[i])
		}
	}

	calls := fake.Calls()
	if len(calls) != 5 {
		t.Fatalf("Calls() returned %d entries, want 5", len(calls))
	}
	for i, c := range calls {
		wantFaulted := i == 2 || i == 3
		if c.Faulted != wantFaulted {
			t.Errorf("call %d: Faulted = %v, want %v", i+1, c.Faulted, wantFaulted)
		}
		if c.N != i+1 {
			t.Errorf("call %d: N = %d, want %d", i+1, c.N, i+1)
		}
	}
}

// TestDropClosesWithNoResponse exercises Fault.Drop directly at the wire
// level: the client sees a connection closed with no status line at all.
func TestDropClosesWithNoResponse(t *testing.T) {
	fake := storetest.New(t)
	fake.Inject(storetest.Rule{Op: storetest.OpGet, Key: "k", Call: 1, Fault: storetest.Fault{Drop: true}})
	fake.SetObject("k", []byte("v"))

	req, err := http.NewRequest(http.MethodGet, fake.URL()+"/"+fake.Bucket()+"/k", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "x")
	_, err = http.DefaultClient.Do(req)
	if err == nil {
		t.Fatal("Do succeeded, want a connection error from the dropped connection")
	}

	calls := fake.Calls()
	if len(calls) != 1 || calls[0].Status != 0 {
		t.Errorf("Calls() = %+v, want one entry with Status 0", calls)
	}
}

// TestDelayEvaluatesRegardless proves latency does not cancel the write:
// even though the client below never reads the response, the fake still
// applies the conditional create after its delay.
func TestDelayEvaluatesRegardless(t *testing.T) {
	fake := storetest.New(t)
	fake.Inject(storetest.Rule{
		Op: storetest.OpPutIfAbsent, Key: "k", Call: 1,
		Fault: storetest.Fault{Delay: 100 * time.Millisecond},
	})

	req, err := http.NewRequest(http.MethodPut, fake.URL()+"/"+fake.Bucket()+"/k", bytes.NewReader([]byte("v")))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.ContentLength = 1
	req.Header.Set("Authorization", "x")
	req.Header.Set("If-None-Match", "*")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if b, ok := fake.Object("k"); !ok || string(b) != "v" {
		t.Errorf("Object(%q) = %q, %v, want %q, true", "k", b, ok, "v")
	}
}

// TestLandRespectsCondition is the round-1 major-finding regression test:
// Fault.Land must evaluate the same condition a normal request would
// before storing anything, never overwrite unconditionally just because
// Land is set. Reproduces the original bug directly - a conditional
// create against an existing key, with Land+500, used to store the new
// bytes anyway - and checks the unconditional, rival, and IgnoreCondition
// cases land (or don't) the same way a real CAS provider would.
func TestLandRespectsCondition(t *testing.T) {
	t.Run("unconditional PUT always lands", func(t *testing.T) {
		fake := storetest.New(t)
		fake.Inject(storetest.Rule{
			Op: storetest.OpPut, Key: "k", Call: 1,
			Fault: storetest.Fault{Land: true, Status: http.StatusInternalServerError, Code: "InternalError"},
		})
		resp := doRequest(t, fake, http.MethodPut, "k", []byte("new"), nil)
		if resp.status != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", resp.status)
		}
		if b, ok := fake.Object("k"); !ok || string(b) != "new" {
			t.Errorf("Object(%q) = %q, %v, want %q, true (unconditional PUT lands even under a fault)", "k", b, ok, "new")
		}
	})

	t.Run("conditional create against an existing key never lands, even with Land set", func(t *testing.T) {
		fake := storetest.New(t)
		fake.SetObject("k", []byte("orig"))
		fake.Inject(storetest.Rule{
			Op: storetest.OpPutIfAbsent, Key: "k", Call: 1,
			Fault: storetest.Fault{Land: true, Status: http.StatusInternalServerError, Code: "InternalError"},
		})
		resp := doRequest(t, fake, http.MethodPut, "k", []byte("new!"), map[string]string{"If-None-Match": "*"})
		if resp.status != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", resp.status)
		}
		if b, ok := fake.Object("k"); !ok || string(b) != "orig" {
			t.Errorf("Object(%q) = %q, %v, want %q, true (the condition failed, so Land must not overwrite)", "k", b, ok, "orig")
		}
		calls := fake.Calls()
		if len(calls) != 1 || calls[0].Landed {
			t.Errorf("Calls() = %+v, want one entry with Landed = false", calls)
		}
	})

	t.Run("a rival write plus Land never clobbers the rival", func(t *testing.T) {
		fake := storetest.New(t)
		fake.Inject(storetest.Rule{
			Op: storetest.OpPutIfAbsent, Key: "k", Call: 1,
			Fault: storetest.Fault{Rival: []byte("rival"), Land: true, Status: http.StatusInternalServerError, Code: "InternalError"},
		})
		resp := doRequest(t, fake, http.MethodPut, "k", []byte("mine"), map[string]string{"If-None-Match": "*"})
		if resp.status != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", resp.status)
		}
		if b, ok := fake.Object("k"); !ok || string(b) != "rival" {
			t.Errorf("Object(%q) = %q, %v, want %q, true (Land must not clobber the rival's bytes)", "k", b, ok, "rival")
		}
	})

	t.Run("IgnoreCondition plus Land overwrites, matching the non-CAS provider case", func(t *testing.T) {
		fake := storetest.New(t)
		fake.SetObject("k", []byte("orig"))
		fake.Inject(storetest.Rule{
			Op: storetest.OpPutIfAbsent, Key: "k", Call: 1,
			Fault: storetest.Fault{IgnoreCondition: true, Land: true, Status: http.StatusInternalServerError, Code: "InternalError"},
		})
		resp := doRequest(t, fake, http.MethodPut, "k", []byte("new"), map[string]string{"If-None-Match": "*"})
		if resp.status != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", resp.status)
		}
		if b, ok := fake.Object("k"); !ok || string(b) != "new" {
			t.Errorf("Object(%q) = %q, %v, want %q, true", "k", b, ok, "new")
		}
	})
}

// TestInjectPanicsOnZeroCall covers the round-1 finding that a Rule with
// Call left at its zero value never fires: rs.matched is always at least
// 1 once a request has arrived, so "matched < 0+count" is false and the
// rule silently never matches anything. Inject refuses such a rule
// outright rather than accept the false confidence of a test believing
// it injected a fault when it injected nothing.
func TestInjectPanicsOnZeroCall(t *testing.T) {
	fake := storetest.New(t)
	defer func() {
		if recover() == nil {
			t.Fatal("Inject did not panic on a Rule with Call == 0")
		}
	}()
	fake.Inject(storetest.Rule{Op: storetest.OpPut, Key: "k", Fault: storetest.Fault{Status: http.StatusServiceUnavailable, Code: "SlowDown"}})
}

// TestUnsupportedQueryParamsRejected covers the round-1 finding that
// unrecognised queries were accepted despite the package doc and plan
// promising 501 for "any other method or query": a LIST with delimiter,
// max-keys, or encoding-type; a GET with a ?acl subresource; a PUT with a
// ?tagging subresource. Only the query keys store.Client actually sends
// (list-type, prefix, start-after, continuation-token for LIST; none at
// all for object GET/PUT) are accepted - anything else is 501, and in
// particular a rejected ?tagging PUT must never apply.
func TestUnsupportedQueryParamsRejected(t *testing.T) {
	fake := storetest.New(t)
	fake.SetObject("a/b/c", []byte("v"))
	fake.SetObject("a/d", []byte("v"))

	list := doList(t, fake, "list-type=2&delimiter=/&prefix=a/&max-keys=1&encoding-type=url")
	if list.status != http.StatusNotImplemented {
		t.Errorf("LIST with delimiter/max-keys/encoding-type: status = %d, want 501", list.status)
	}

	acl := doRequest(t, fake, http.MethodGet, "a/d?acl", nil, nil)
	if acl.status != http.StatusNotImplemented {
		t.Errorf("GET ?acl: status = %d, want 501", acl.status)
	}

	tagging := doRequest(t, fake, http.MethodPut, "a/d?tagging", []byte("<Tagging/>"), nil)
	if tagging.status != http.StatusNotImplemented {
		t.Errorf("PUT ?tagging: status = %d, want 501", tagging.status)
	}
	if b, _ := fake.Object("a/d"); string(b) != "v" {
		t.Errorf("Object(%q) = %q, want unchanged %q (a rejected ?tagging PUT must not apply)", "a/d", b, "v")
	}
}

// TestTruncatedGetFailsMidStream covers the round-1 finding that
// Fault.TruncateBody on a GET sent zero body bytes regardless of N,
// because hijackDrop's conn.Close() discarded whatever was still sitting
// in the ResponseWriter's own buffer - only the already-flushed header
// block ever reached the wire. This reads the response over a raw TCP
// connection (net/http's client hides a short body behind an error,
// which would not prove how many bytes actually arrived) and asserts
// exactly N body bytes were received before the cut.
func TestTruncatedGetFailsMidStream(t *testing.T) {
	fake := storetest.New(t)
	obj := []byte("0123456789abcdefghi") // 20 bytes
	fake.SetObject("k", obj)
	const n = 7
	fake.Inject(storetest.Rule{Op: storetest.OpGet, Key: "k", Call: 1, Fault: storetest.Fault{TruncateBody: n}})

	conn, addr := rawConn(t, fake)
	defer conn.Close()
	fmt.Fprintf(conn, "GET /%s/k HTTP/1.1\r\nHost: %s\r\nAuthorization: x\r\nConnection: close\r\n\r\n", fake.Bucket(), addr)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body) // an error after the cut is expected; only the byte count matters
	if len(got) != n {
		t.Fatalf("received %d body bytes before the cut, want %d (got %q)", len(got), n, got)
	}
	if !bytes.Equal(got, obj[:n]) {
		t.Errorf("received bytes = %q, want %q", got, obj[:n])
	}
}

// TestListStartAfter covers plan case 5, never exercised in round 1:
// start-after resumes a list after the given key.
func TestListStartAfter(t *testing.T) {
	fake := storetest.New(t)
	for _, k := range []string{"p/00", "p/01", "p/02", "p/03"} {
		fake.SetObject(k, []byte("v"))
	}

	resp := doList(t, fake, "list-type=2&prefix=p/&start-after=p/01")
	if resp.status != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.status)
	}
	var result struct {
		Contents []struct {
			Key string `xml:"Key"`
		} `xml:"Contents"`
	}
	if err := xml.Unmarshal(resp.body, &result); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}
	var got []string
	for _, c := range result.Contents {
		got = append(got, c.Key)
	}
	want := []string{"p/02", "p/03"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("keys = %v, want %v", got, want)
	}
}

// TestListStartAfterIgnoredWithContinuationToken covers the package doc's
// claim that start-after is "ignored once a continuation token is
// present": a request carrying both a stale start-after and a real
// continuation token must resume from the token, not the start-after.
func TestListStartAfterIgnoredWithContinuationToken(t *testing.T) {
	fake := storetest.New(t)
	fake.PageSize = 2
	for _, k := range []string{"p/00", "p/01", "p/02", "p/03"} {
		fake.SetObject(k, []byte("v"))
	}

	first := doList(t, fake, "list-type=2&prefix=p/")
	var page1 struct {
		IsTruncated           bool   `xml:"IsTruncated"`
		NextContinuationToken string `xml:"NextContinuationToken"`
	}
	if err := xml.Unmarshal(first.body, &page1); err != nil {
		t.Fatalf("unmarshaling first page: %v", err)
	}
	if !page1.IsTruncated || page1.NextContinuationToken == "" {
		t.Fatalf("first page = %+v, want truncated with a continuation token", page1)
	}

	// start-after=p/00 alone would resume after p/00 (giving p/01, p/02);
	// the real continuation token resumes after p/01, where the first
	// page actually ended. The token must win.
	second := doList(t, fake, "list-type=2&prefix=p/&start-after=p/00&continuation-token="+page1.NextContinuationToken)
	if second.status != http.StatusOK {
		t.Fatalf("second page: status = %d, want 200", second.status)
	}
	var result struct {
		Contents []struct {
			Key string `xml:"Key"`
		} `xml:"Contents"`
	}
	if err := xml.Unmarshal(second.body, &result); err != nil {
		t.Fatalf("unmarshaling second page: %v", err)
	}
	var got []string
	for _, c := range result.Contents {
		got = append(got, c.Key)
	}
	want := []string{"p/02", "p/03"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("second page keys = %v, want %v (continuation-token must win over start-after)", got, want)
	}
}

// TestCallsRecordedAtArrival covers the round-1 finding that Calls()
// entries were appended on completion, not arrival, contradicting the
// doc comment ("the call log, in arrival order"). A PUT delayed 150ms
// followed 30ms later by an unrelated PUT that returns immediately must
// still show up in the log in the order they arrived, not the order they
// finished.
func TestCallsRecordedAtArrival(t *testing.T) {
	fake := storetest.New(t)
	fake.Inject(storetest.Rule{
		Op: storetest.OpPut, Key: "slow", Call: 1,
		Fault: storetest.Fault{Delay: 150 * time.Millisecond},
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		doRequest(t, fake, http.MethodPut, "slow", []byte("x"), nil)
	}()
	time.Sleep(30 * time.Millisecond)
	doRequest(t, fake, http.MethodPut, "fast", []byte("y"), nil)
	<-done

	calls := fake.Calls()
	if len(calls) != 2 {
		t.Fatalf("Calls() returned %d entries, want 2", len(calls))
	}
	if calls[0].Key != "slow" || calls[0].N != 1 {
		t.Errorf("calls[0] = %+v, want Key \"slow\", N 1 (arrival order, not completion order)", calls[0])
	}
	if calls[1].Key != "fast" || calls[1].N != 2 {
		t.Errorf("calls[1] = %+v, want Key \"fast\", N 2", calls[1])
	}
}

// TestAWSChunkedMalformedFramingRejected covers the round-1 finding that
// decodeAWSChunked accepted framing real S3 would reject: a bare "\n"
// terminator instead of "\r\n", junk bytes before the terminator, and a
// missing final CRLF after the zero-length chunk. Each must be refused
// with 400 and store nothing, never silently decoded.
func TestAWSChunkedMalformedFramingRejected(t *testing.T) {
	sig := strings.Repeat("0", 64)
	cases := []struct {
		name string
		body string
	}{
		{
			name: "bare LF instead of CRLF after chunk data",
			body: "5;chunk-signature=" + sig + "\r\nhello\n0;chunk-signature=" + sig + "\r\n\r\n",
		},
		{
			name: "junk after chunk data before the terminator",
			body: "5;chunk-signature=" + sig + "\r\nhelloXX\r\n0;chunk-signature=" + sig + "\r\n\r\n",
		},
		{
			name: "missing final CRLF after the zero-length chunk",
			body: "5;chunk-signature=" + sig + "\r\nhello\r\n0;chunk-signature=" + sig + "\r\n",
		},
		{
			// Round 2 finding: the header-line CRLF fix from round 1 only
			// covered chunk data/final terminators, not the chunk header
			// line itself - ReadString('\n') plus TrimRight accepted a
			// bare "\n" ending the "<size>;chunk-signature=..." line too.
			name: "bare LF terminating the chunk header line",
			body: "5;chunk-signature=" + sig + "\nhello\r\n0;chunk-signature=" + sig + "\r\n\r\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake := storetest.New(t)
			body := []byte(c.body)
			status, _ := rawPut(t, fake, "malformed", map[string]string{
				"Content-Length":               strconv.Itoa(len(body)),
				"Content-Encoding":             "aws-chunked",
				"X-Amz-Decoded-Content-Length": "5",
			}, body)
			if status != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", status)
			}
			if _, ok := fake.Object("malformed"); ok {
				t.Errorf("malformed framing stored an object, want none")
			}
		})
	}
}

// httpChunkEncode wraps data in standard HTTP/1.1 "Transfer-Encoding:
// chunked" framing (a single chunk plus the zero-length terminator) - not
// to be confused with aws-chunked, which is a different, S3-specific
// framing carried *inside* an HTTP body. TestAWSChunkedRequiresContentLength
// needs both layers at once: an aws-chunked payload sent over a request
// that declares no Content-Length at all, which is only a legal HTTP
// request when Transfer-Encoding: chunked supplies the framing instead.
func httpChunkEncode(data []byte) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%x\r\n", len(data))
	buf.Write(data)
	buf.WriteString("\r\n0\r\n\r\n")
	return buf.Bytes()
}

// TestListContinuationTokenIsOpaque covers the round-2 medium finding that
// ListObjectsV2's continuation token was just the raw last key of the
// previous page, so any string - including one a broken client fabricated
// by copying a key straight out of a page it already saw - was accepted as
// a valid token and silently resumed (or restarted) the listing. A
// genuinely opaque token only resolves through the fake's own issueToken/
// resolveToken bookkeeping; anything else must be refused outright.
func TestListContinuationTokenIsOpaque(t *testing.T) {
	fake := storetest.New(t)
	fake.PageSize = 2
	for _, k := range []string{"p/00", "p/01", "p/02", "p/03"} {
		fake.SetObject(k, []byte("v"))
	}

	first := doList(t, fake, "list-type=2&prefix=p/")
	if first.status != http.StatusOK {
		t.Fatalf("first page: status = %d, want 200", first.status)
	}
	var page1 struct {
		IsTruncated           bool   `xml:"IsTruncated"`
		NextContinuationToken string `xml:"NextContinuationToken"`
		Contents              []struct {
			Key string `xml:"Key"`
		} `xml:"Contents"`
	}
	if err := xml.Unmarshal(first.body, &page1); err != nil {
		t.Fatalf("unmarshaling first page: %v", err)
	}
	if !page1.IsTruncated || page1.NextContinuationToken == "" {
		t.Fatalf("first page = %+v, want truncated with a continuation token", page1)
	}
	lastKey := page1.Contents[len(page1.Contents)-1].Key
	if page1.NextContinuationToken == lastKey {
		t.Fatalf("continuation token %q equals the raw last key %q, want an opaque value unrelated to it", page1.NextContinuationToken, lastKey)
	}

	// A client that fabricates a token by sending the last key it saw
	// (exactly the bug this fake must not have) is refused.
	fabricated := doList(t, fake, "list-type=2&prefix=p/&continuation-token="+lastKey)
	if fabricated.status != http.StatusBadRequest {
		t.Errorf("fabricated token (raw last key %q): status = %d, want 400", lastKey, fabricated.status)
	}
	if code := s3Code(t, fabricated.body); code != "InvalidArgument" {
		t.Errorf("fabricated token: Code = %q, want InvalidArgument", code)
	}

	// Plain garbage the fake never issued is refused the same way.
	garbage := doList(t, fake, "list-type=2&prefix=p/&continuation-token=not-a-real-token")
	if garbage.status != http.StatusBadRequest {
		t.Errorf("garbage token: status = %d, want 400", garbage.status)
	}
	if code := s3Code(t, garbage.body); code != "InvalidArgument" {
		t.Errorf("garbage token: Code = %q, want InvalidArgument", code)
	}

	// The token the fake actually issued still works and resumes correctly.
	second := doList(t, fake, "list-type=2&prefix=p/&continuation-token="+page1.NextContinuationToken)
	if second.status != http.StatusOK {
		t.Fatalf("second page with the real token: status = %d, want 200", second.status)
	}
	var page2 struct {
		Contents []struct {
			Key string `xml:"Key"`
		} `xml:"Contents"`
	}
	if err := xml.Unmarshal(second.body, &page2); err != nil {
		t.Fatalf("unmarshaling second page: %v", err)
	}
	var got []string
	for _, c := range page2.Contents {
		got = append(got, c.Key)
	}
	want := []string{"p/02", "p/03"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("second page keys = %v, want %v", got, want)
	}
}

// TestAWSChunkedRequiresContentLength covers the round-2 minor finding
// that an aws-chunked PUT with no Content-Length at all was accepted:
// readPutBody's aws-chunked branch checked X-Amz-Decoded-Content-Length
// but never r.ContentLength. Real S3 answers 411 MissingContentLength to
// such a request (client.go's own comment near the aws-chunked send path
// relies on exactly that), so this sends the aws-chunked payload framed
// only by HTTP's own Transfer-Encoding: chunked - the one way to put bytes
// on the wire with no declared Content-Length at all.
func TestAWSChunkedRequiresContentLength(t *testing.T) {
	fake := storetest.New(t)

	payload := encodeChunked(t, []byte("hello"))
	status, respBody := rawPut(t, fake, "nolen", map[string]string{
		"Content-Encoding":             "aws-chunked",
		"X-Amz-Decoded-Content-Length": "5",
		"Transfer-Encoding":            "chunked",
	}, httpChunkEncode(payload))
	if status != http.StatusLengthRequired {
		t.Errorf("aws-chunked PUT with no Content-Length: status = %d, want 411", status)
	}
	if code := s3Code(t, respBody); code != "MissingContentLength" {
		t.Errorf("aws-chunked PUT with no Content-Length: Code = %q, want MissingContentLength", code)
	}
	if _, ok := fake.Object("nolen"); ok {
		t.Errorf("aws-chunked PUT with no Content-Length stored an object, want none")
	}
}

// TestAWSChunkedNegativeChunkSizeRejected covers the round-2 minor finding
// that a negative chunk size ("-5", which strconv.ParseInt happily accepts
// in base 16) reached make([]byte, size) and panicked the handler -
// net/http recovers from that by dropping the connection with no
// response, which is indistinguishable from an injected Fault.Drop and
// leaves store.Client treating a plain framing bug as ErrOutcomeUnknown.
// The documented behaviour is a clean 400 IncompleteBody, and the
// connection must not simply die.
func TestAWSChunkedNegativeChunkSizeRejected(t *testing.T) {
	fake := storetest.New(t)

	body := []byte("-5;chunk-signature=" + strings.Repeat("0", 64) + "\r\nhello\r\n0;chunk-signature=" + strings.Repeat("0", 64) + "\r\n\r\n")
	status, _ := rawPut(t, fake, "negsize", map[string]string{
		"Content-Length":               strconv.Itoa(len(body)),
		"Content-Encoding":             "aws-chunked",
		"X-Amz-Decoded-Content-Length": "5",
	}, body)
	if status != http.StatusBadRequest {
		t.Errorf("negative chunk size: status = %d, want 400", status)
	}
	if _, ok := fake.Object("negsize"); ok {
		t.Errorf("negative chunk size stored an object, want none")
	}
}

// TestDeleteRemovesObjectAndIsIdempotent covers WALD-23's DELETE support,
// added for the boot probe's own cleanup (Client.delete). DELETE is
// unconditional and answers 204 whether or not the key existed - real S3
// behaves the same way, and Client.delete relies on exactly this so
// a retried delete after a dropped response is never mistaken for a
// failure.
func TestDeleteRemovesObjectAndIsIdempotent(t *testing.T) {
	fake := storetest.New(t)
	fake.SetObject("k", []byte("v"))

	resp := doRequest(t, fake, http.MethodDelete, "k", nil, nil)
	if resp.status != http.StatusNoContent {
		t.Fatalf("DELETE existing key: status = %d, want 204", resp.status)
	}
	if _, ok := fake.Object("k"); ok {
		t.Errorf("Object(%q) still present after DELETE", "k")
	}

	// A second DELETE of the now-absent key must still succeed.
	resp2 := doRequest(t, fake, http.MethodDelete, "k", nil, nil)
	if resp2.status != http.StatusNoContent {
		t.Fatalf("DELETE of an already-absent key: status = %d, want 204 (idempotent)", resp2.status)
	}
}

// TestDeleteWithQueryStringUnsupported covers the same "only the request
// shapes store.Client actually sends are accepted" rule
// TestUnsupportedQueryParamsRejected proves for LIST/GET/PUT: a DELETE
// carrying a query string (a lifecycle or versioning sub-resource, say)
// answers 501 rather than being silently accepted as a plain delete.
func TestDeleteWithQueryStringUnsupported(t *testing.T) {
	fake := storetest.New(t)
	fake.SetObject("k", []byte("v"))

	resp := doRequest(t, fake, http.MethodDelete, "k?versionId=1", nil, nil)
	if resp.status != http.StatusNotImplemented {
		t.Errorf("DELETE with query string: status = %d, want 501", resp.status)
	}
	if _, ok := fake.Object("k"); !ok {
		t.Errorf("Object(%q) removed by an unsupported DELETE, want untouched", "k")
	}
}

// TestDeleteFaultInjectionAndCallLog covers Fault handling on OpDelete: a
// faulted call answers the injected status without touching the object,
// and the call log records Op, Faulted, and Landed the same way it does
// for the other three operations.
func TestDeleteFaultInjectionAndCallLog(t *testing.T) {
	fake := storetest.New(t)
	fake.SetObject("k", []byte("v"))
	fake.Inject(storetest.Rule{
		Op: storetest.OpDelete, Key: "k", Call: 1,
		Fault: storetest.Fault{Status: http.StatusForbidden, Code: "AccessDenied"},
	})

	resp := doRequest(t, fake, http.MethodDelete, "k", nil, nil)
	if resp.status != http.StatusForbidden {
		t.Fatalf("faulted DELETE: status = %d, want 403", resp.status)
	}
	if code := s3Code(t, resp.body); code != "AccessDenied" {
		t.Errorf("faulted DELETE: Code = %q, want AccessDenied", code)
	}
	if _, ok := fake.Object("k"); !ok {
		t.Errorf("Object(%q) removed by a faulted DELETE with no Land, want untouched", "k")
	}

	// The unfaulted retry actually deletes it.
	resp2 := doRequest(t, fake, http.MethodDelete, "k", nil, nil)
	if resp2.status != http.StatusNoContent {
		t.Fatalf("retried DELETE: status = %d, want 204", resp2.status)
	}

	calls := fake.Calls()
	if len(calls) != 2 {
		t.Fatalf("Calls() returned %d entries, want 2", len(calls))
	}
	if calls[0].Op != storetest.OpDelete || !calls[0].Faulted || calls[0].Landed {
		t.Errorf("call 1 = %+v, want Op=OpDelete Faulted=true Landed=false", calls[0])
	}
	if calls[1].Op != storetest.OpDelete || calls[1].Faulted || !calls[1].Landed {
		t.Errorf("call 2 = %+v, want Op=OpDelete Faulted=false Landed=true", calls[1])
	}
	if got := storetest.OpDelete.String(); got != "DELETE" {
		t.Errorf("OpDelete.String() = %q, want %q", got, "DELETE")
	}
}
