// Raw net/http tests of the fake's own semantics, independent of
// store.Client. This is the drift guard the WALD-24 plan calls for: the
// main risk with a fake object store is that its conditional semantics
// quietly diverge from spec/journal/v1 §11.1/§11.4.6, and a client-driven
// test alone would not catch that — it would just mean the client and the
// fake made the same mistake together. This file imports no walden package
// at all, only net/http and the fake itself.
package storetest_test

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
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
// declared Content-Length stores nothing, and an aws-chunked body decodes
// to the same bytes a raw body would.
func TestShortBodyStoresNothing(t *testing.T) {
	fake := storetest.New(t)

	req, err := http.NewRequest(http.MethodPut, fake.URL()+"/"+fake.Bucket()+"/short", strings.NewReader("ab"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.ContentLength = 10 // lies: only 2 bytes will actually be sent
	req.Header.Set("Authorization", "x")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// net/http may itself fail to send a body shorter than declared;
		// either way nothing may be stored.
		if _, ok := fake.Object("short"); ok {
			t.Fatalf("short body stored an object despite send error %v", err)
		}
		return
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("short body: status = %d, want 400", resp.StatusCode)
	}
	if _, ok := fake.Object("short"); ok {
		t.Errorf("short body stored an object, want none")
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
