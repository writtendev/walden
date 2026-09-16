package store_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/store"
)

// -----------------------------------------------------------------------
// Test scaffolding: a fake S3 server dialed directly (bypassing DNS and,
// for TLS, certificate verification), a test Journal/Client pair, and a
// signature verifier built from the sigv4.go internals export_test.go
// already exposes for the SigV4 conformance suite.
// -----------------------------------------------------------------------

var testCreds = store.Credentials{
	AccessKeyID:     "AKIDEXAMPLE",
	SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}

const testRegion = "us-east-1"

// newFakeServer starts an httptest server (TLS when useTLS) running
// handler, and returns an *http.Client whose Transport dials straight at
// that server no matter what host or port a request names - so a
// virtual-hosted Journal (bucket.s3.fake.test) needs no real DNS entry.
func newFakeServer(t *testing.T, useTLS bool, handler http.HandlerFunc) *http.Client {
	t.Helper()

	var srv *httptest.Server
	if useTLS {
		srv = httptest.NewTLSServer(handler)
	} else {
		srv = httptest.NewServer(handler)
	}
	t.Cleanup(srv.Close)

	client := srv.Client()
	transport := client.Transport.(*http.Transport).Clone()
	addr := srv.Listener.Addr().String()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	if useTLS {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}
		transport.TLSClientConfig.InsecureSkipVerify = true
	}
	client.Transport = transport
	// Match production's NewClient: never follow a redirect. Without this,
	// a fake server's 3xx with a Location header would be silently
	// followed by this *http.Client itself, and a test could never observe
	// what classify actually does with a 3xx response.
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client
}

func testJournal(endpoint, bucket, prefix string, pathStyle bool) *store.Journal {
	return &store.Journal{
		Endpoint:    endpoint,
		Region:      testRegion,
		Bucket:      bucket,
		Prefix:      prefix,
		PathStyle:   pathStyle,
		Credentials: testCreds,
	}
}

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// verifySignature recomputes the SigV4 signature server-side from the
// request the fake received and compares it with Authorization. It uses
// canonicalRequest and friends through the same ForTest shims sigv4_test.go
// uses, so it exercises the identical code path production signing does.
func verifySignature(t *testing.T, r *http.Request) error {
	t.Helper()

	auth := r.Header.Get("Authorization")
	if auth == "" {
		return errors.New("no Authorization header")
	}
	const prefix = "AWS4-HMAC-SHA256 "
	if !strings.HasPrefix(auth, prefix) {
		return fmt.Errorf("unexpected Authorization algorithm: %q", auth)
	}

	fields := map[string]string{}
	for _, kv := range strings.Split(strings.TrimPrefix(auth, prefix), ", ") {
		i := strings.IndexByte(kv, '=')
		if i < 0 {
			continue
		}
		fields[kv[:i]] = kv[i+1:]
	}
	credential := fields["Credential"]
	signature := fields["Signature"]
	signedHeaders := fields["SignedHeaders"]
	if credential == "" || signature == "" || signedHeaders == "" {
		return fmt.Errorf("malformed Authorization: %q", auth)
	}

	credParts := strings.Split(credential, "/")
	if len(credParts) != 5 {
		return fmt.Errorf("malformed Credential: %q", credential)
	}
	accessKeyID, date, region, service := credParts[0], credParts[1], credParts[2], credParts[3]
	if accessKeyID != testCreds.AccessKeyID {
		return fmt.Errorf("access key ID = %q, want %q", accessKeyID, testCreds.AccessKeyID)
	}

	amzDate := r.Header.Get("X-Amz-Date")
	now, err := time.Parse(store.AmzDateFormatForTest, amzDate)
	if err != nil {
		return fmt.Errorf("bad X-Amz-Date %q: %w", amzDate, err)
	}
	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		return errors.New("no X-Amz-Content-Sha256 header")
	}

	// A real S3-compatible verifier trusts the client's declared
	// SignedHeaders list rather than re-scanning every header it happens
	// to receive: the transport (gzip negotiation, keep-alive, …) adds
	// headers of its own after signing, and those were never covered by
	// the signature. Filter down to exactly the declared set before
	// recomputing, the same way a real server would.
	signed := make(http.Header, len(r.Header))
	for _, name := range strings.Split(signedHeaders, ";") {
		if name == "host" {
			continue // canonicalRequest signs host from the host argument
		}
		canon := http.CanonicalHeaderKey(name)
		if v, ok := r.Header[canon]; ok {
			signed[canon] = v
		}
	}

	creq, _ := store.CanonicalRequestForTest(r.Method, r.URL.Path, r.URL.Query(), signed, r.Host, payloadHash)
	scope := store.ScopeStringForTest(date, region, service)
	sts := store.StringToSignForTest(now, scope, creq)
	key := store.SigningKeyForTest(testCreds.SecretAccessKey, date, region, service)
	want := store.SignatureForTest(key, sts)

	if want != signature {
		return fmt.Errorf("signature = %s, want %s", signature, want)
	}
	return nil
}

// decodeChunkedBody parses signed aws-chunked framing (see sigv4.go's
// newChunkedBody) and returns the concatenated chunk data.
func decodeChunkedBody(t *testing.T, framed []byte) []byte {
	t.Helper()
	var out []byte
	for {
		nl := bytes.IndexByte(framed, '\n')
		if nl < 0 {
			t.Fatalf("chunked body: truncated, no chunk header")
		}
		header := strings.TrimRight(string(framed[:nl]), "\r")
		framed = framed[nl+1:]

		semi := strings.IndexByte(header, ';')
		if semi < 0 {
			t.Fatalf("chunked body: chunk header %q has no chunk-signature", header)
		}
		size, err := strconv.ParseInt(header[:semi], 16, 64)
		if err != nil {
			t.Fatalf("chunked body: bad chunk size %q: %v", header[:semi], err)
		}
		if int64(len(framed)) < size+2 {
			t.Fatalf("chunked body: truncated chunk data")
		}
		data := framed[:size]
		framed = framed[size:]
		if framed[0] != '\r' || framed[1] != '\n' {
			t.Fatalf("chunked body: missing CRLF after chunk data")
		}
		framed = framed[2:]

		if size == 0 {
			return out
		}
		out = append(out, data...)
	}
}

func xmlError(code string) []byte {
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>test</Message></Error>`, code))
}

// -----------------------------------------------------------------------
// 1. Signatures verify: GET, PUT over http (streaming) and PUT over https
//    (unsigned), for both path-style and virtual-hosted addressing.
// -----------------------------------------------------------------------

func TestSignaturesVerify(t *testing.T) {
	tests := []struct {
		name      string
		useTLS    bool
		pathStyle bool
		method    string
		key       string
		body      []byte
	}{
		{name: "get-path-style", method: http.MethodGet, key: "v1/streams/a.json", pathStyle: true},
		{name: "get-virtual-hosted", method: http.MethodGet, key: "v1/streams/a.json", pathStyle: false},
		{name: "put-http-streaming-path-style", method: http.MethodPut, key: "v1/streams/b.pack", pathStyle: true, body: bytes.Repeat([]byte("x"), 200)},
		{name: "put-http-streaming-virtual-hosted", method: http.MethodPut, key: "v1/streams/b.pack", pathStyle: false, body: bytes.Repeat([]byte("y"), 200)},
		{name: "put-https-unsigned-path-style", useTLS: true, method: http.MethodPut, key: "v1/streams/c.pack", pathStyle: true, body: bytes.Repeat([]byte("z"), 200)},
		{name: "put-https-unsigned-virtual-hosted", useTLS: true, method: http.MethodPut, key: "v1/streams/c.pack", pathStyle: false, body: bytes.Repeat([]byte("w"), 200)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sigErr error
			var reqCount int32
			handler := func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&reqCount, 1)
				io.Copy(io.Discard, r.Body)
				sigErr = verifySignature(t, r)
				w.WriteHeader(http.StatusOK)
			}
			client := newFakeServer(t, tt.useTLS, handler)

			scheme := "http"
			if tt.useTLS {
				scheme = "https"
			}
			j := testJournal(scheme+"://s3.fake.test", "test-bucket", "v1", tt.pathStyle)
			c := store.NewClientForTest(j, client, fixedClock(time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)))

			ctx := context.Background()
			switch tt.method {
			case http.MethodGet:
				rc, err := c.Get(ctx, tt.key)
				if err != nil {
					t.Fatalf("Get: %v", err)
				}
				rc.Close()
			case http.MethodPut:
				if err := c.Put(ctx, tt.key, bytes.NewReader(tt.body), int64(len(tt.body))); err != nil {
					t.Fatalf("Put: %v", err)
				}
			}

			if reqCount != 1 {
				t.Fatalf("server saw %d requests, want 1", reqCount)
			}
			if sigErr != nil {
				t.Errorf("signature verification failed: %v", sigErr)
			}
		})
	}
}

// -----------------------------------------------------------------------
// 2. Streaming PUT round-trips: Content-Length equals bytes received, no
//    Transfer-Encoding, X-Amz-Content-Sha256 is STREAMING-…, and the
//    aws-chunked frames decode back to the original body. A TLS PUT sees
//    UNSIGNED-PAYLOAD and the exact bytes.
// -----------------------------------------------------------------------

func TestStreamingPutRoundTrips(t *testing.T) {
	// 200 << 10 is larger than one 64 KiB chunk and not a multiple of it.
	body := make([]byte, 200<<10)
	for i := range body {
		body[i] = byte(i)
	}

	var gotContentLength int64
	var gotTransferEncoding []string
	var gotSha256 string
	var gotBody []byte

	handler := func(w http.ResponseWriter, r *http.Request) {
		gotContentLength = r.ContentLength
		gotTransferEncoding = r.TransferEncoding
		gotSha256 = r.Header.Get("X-Amz-Content-Sha256")
		var err error
		gotBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading request body: %v", err)
		}
		if int64(len(gotBody)) != r.ContentLength {
			t.Errorf("received %d bytes, Content-Length said %d", len(gotBody), r.ContentLength)
		}
		w.WriteHeader(http.StatusOK)
	}
	client := newFakeServer(t, false, handler)

	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	if err := c.Put(context.Background(), "v1/streams/big.pack", bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if len(gotTransferEncoding) != 0 {
		t.Errorf("Transfer-Encoding = %v, want none", gotTransferEncoding)
	}
	if !strings.HasPrefix(gotSha256, "STREAMING-") {
		t.Errorf("X-Amz-Content-Sha256 = %q, want STREAMING- prefix", gotSha256)
	}
	if gotContentLength != store.ChunkedLengthForTest(int64(len(body)), 64<<10) {
		t.Errorf("Content-Length = %d, want %d", gotContentLength, store.ChunkedLengthForTest(int64(len(body)), 64<<10))
	}

	decoded := decodeChunkedBody(t, gotBody)
	if !bytes.Equal(decoded, body) {
		t.Errorf("decoded chunked body does not match original (got %d bytes, want %d)", len(decoded), len(body))
	}
}

func TestTLSPutUnsignedPayloadExactBytes(t *testing.T) {
	body := []byte("exact bytes over TLS, no chunk framing")

	var gotSha256 string
	var gotBody []byte
	handler := func(w http.ResponseWriter, r *http.Request) {
		gotSha256 = r.Header.Get("X-Amz-Content-Sha256")
		var err error
		gotBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}
	client := newFakeServer(t, true, handler)

	j := testJournal("https://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	if err := c.Put(context.Background(), "v1/streams/small.pack", bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if gotSha256 != store.UnsignedPayloadForTest {
		t.Errorf("X-Amz-Content-Sha256 = %q, want %q", gotSha256, store.UnsignedPayloadForTest)
	}
	if !bytes.Equal(gotBody, body) {
		t.Errorf("body = %q, want %q", gotBody, body)
	}
}

// -----------------------------------------------------------------------
// 3. GET 200 returns the bytes. GET 404 NoSuchKey gives
//    errors.Is(err, ErrObjectNotFound) after exactly 1 request.
// -----------------------------------------------------------------------

func TestGetSuccess(t *testing.T) {
	want := []byte("journal segment bytes")
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(want)
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	rc, err := c.Get(context.Background(), "v1/streams/a.json")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestGetNotFound(t *testing.T) {
	var reqCount int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		w.WriteHeader(http.StatusNotFound)
		w.Write(xmlError("NoSuchKey"))
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	_, err := c.Get(context.Background(), "v1/streams/missing.json")
	if !errors.Is(err, store.ErrObjectNotFound) {
		t.Fatalf("errors.Is(err, ErrObjectNotFound) = false, err = %v", err)
	}
	if errors.Is(err, store.ErrStorageUnavailable) {
		t.Errorf("a permanent 404 must not also be ErrStorageUnavailable: %v", err)
	}
	if reqCount != 1 {
		t.Errorf("server saw %d requests, want 1 (NoSuchKey is not retried)", reqCount)
	}
}

// -----------------------------------------------------------------------
// 4. Retries recover: 503, 503, 200 succeeds after 3 requests, and the PUT
//    body is identical on every attempt.
// -----------------------------------------------------------------------

func TestRetriesRecover(t *testing.T) {
	restore := store.SetBackoffForTest(time.Millisecond, 5*time.Millisecond)
	defer restore()

	body := []byte("retry me until storage returns")

	var mu sync.Mutex
	var bodies [][]byte
	handler := func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, got)
		n := len(bodies)
		mu.Unlock()

		if n <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write(xmlError("SlowDown"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}
	// https, so the body arrives as exact bytes (UNSIGNED-PAYLOAD) rather
	// than aws-chunked framing: this test is about the retry loop resending
	// the same bytes, not about re-decoding the streaming envelope.
	client := newFakeServer(t, true, handler)
	j := testJournal("https://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	if err := c.Put(context.Background(), "v1/streams/retry.pack", bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatalf("Put: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 3 {
		t.Fatalf("server saw %d requests, want 3", len(bodies))
	}
	for i, b := range bodies {
		if !bytes.Equal(b, body) {
			t.Errorf("attempt %d body = %q, want %q", i+1, b, body)
		}
	}
}

// -----------------------------------------------------------------------
// 5. The cap holds: always-500 gives ErrStorageUnavailable after exactly
//    maxAttempts requests.
// -----------------------------------------------------------------------

func TestRetryCapHolds(t *testing.T) {
	restore := store.SetBackoffForTest(time.Millisecond, 5*time.Millisecond)
	defer restore()

	var reqCount int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(xmlError("InternalError"))
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	body := []byte("never succeeds")
	err := c.Put(context.Background(), "v1/streams/cap.pack", bytes.NewReader(body), int64(len(body)))
	if !errors.Is(err, store.ErrStorageUnavailable) {
		t.Fatalf("errors.Is(err, ErrStorageUnavailable) = false, err = %v", err)
	}
	if reqCount != store.MaxAttemptsForTest {
		t.Errorf("server saw %d requests, want %d", reqCount, store.MaxAttemptsForTest)
	}
}

// -----------------------------------------------------------------------
// 6. Classification table: permanent statuses stop after 1 request;
//    retryable statuses keep going until the cap.
// -----------------------------------------------------------------------

func TestClassificationTable(t *testing.T) {
	permanent := []struct {
		name   string
		status int
		code   string
	}{
		{"301-permanent-redirect", http.StatusMovedPermanently, "PermanentRedirect"},
		{"400-signature-does-not-match", http.StatusBadRequest, "SignatureDoesNotMatch"},
		{"403-access-denied", http.StatusForbidden, "AccessDenied"},
		{"404-no-such-bucket-on-put", http.StatusNotFound, "NoSuchBucket"},
	}
	for _, tt := range permanent {
		t.Run(tt.name, func(t *testing.T) {
			var reqCount int32
			handler := func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&reqCount, 1)
				io.Copy(io.Discard, r.Body)
				w.WriteHeader(tt.status)
				w.Write(xmlError(tt.code))
			}
			client := newFakeServer(t, false, handler)
			j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
			c := store.NewClientForTest(j, client, fixedClock(time.Now()))

			body := []byte("x")
			err := c.Put(context.Background(), "v1/streams/x.pack", bytes.NewReader(body), int64(len(body)))
			if !errors.Is(err, store.ErrStorageRefused) {
				t.Fatalf("errors.Is(err, ErrStorageRefused) = false, err = %v", err)
			}
			if errors.Is(err, store.ErrStorageUnavailable) {
				t.Errorf("a permanent refusal must not also be ErrStorageUnavailable: %v", err)
			}
			if reqCount != 1 {
				t.Errorf("server saw %d requests, want 1", reqCount)
			}
		})
	}

	retried := []struct {
		name   string
		status int
		code   string
	}{
		{"408-request-timeout-status", http.StatusRequestTimeout, ""},
		{"429-too-many-requests", http.StatusTooManyRequests, ""},
		{"500-internal-error", http.StatusInternalServerError, "InternalError"},
		{"502-bad-gateway", http.StatusBadGateway, ""},
		{"503-slow-down", http.StatusServiceUnavailable, "SlowDown"},
		{"504-gateway-timeout", http.StatusGatewayTimeout, ""},
		{"400-request-timeout-code", http.StatusBadRequest, "RequestTimeout"},
	}
	restore := store.SetBackoffForTest(time.Millisecond, 5*time.Millisecond)
	defer restore()
	for _, tt := range retried {
		t.Run(tt.name, func(t *testing.T) {
			var reqCount int32
			handler := func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&reqCount, 1)
				io.Copy(io.Discard, r.Body)
				w.WriteHeader(tt.status)
				if tt.code != "" {
					w.Write(xmlError(tt.code))
				}
			}
			client := newFakeServer(t, false, handler)
			j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
			c := store.NewClientForTest(j, client, fixedClock(time.Now()))

			body := []byte("x")
			err := c.Put(context.Background(), "v1/streams/x.pack", bytes.NewReader(body), int64(len(body)))
			if !errors.Is(err, store.ErrStorageUnavailable) {
				t.Fatalf("errors.Is(err, ErrStorageUnavailable) = false, err = %v", err)
			}
			if reqCount != store.MaxAttemptsForTest {
				t.Errorf("server saw %d requests, want %d", reqCount, store.MaxAttemptsForTest)
			}
		})
	}
}

// -----------------------------------------------------------------------
// 7. Transport error: a server that hijacks the connection and closes it
//    is retried.
// -----------------------------------------------------------------------

func TestTransportErrorRetried(t *testing.T) {
	restore := store.SetBackoffForTest(time.Millisecond, 5*time.Millisecond)
	defer restore()

	var reqCount int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&reqCount, 1)
		if n < store.MaxAttemptsForTest {
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("ResponseWriter does not support hijacking")
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Fatalf("Hijack: %v", err)
			}
			conn.Close()
			return
		}
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	body := []byte("x")
	if err := c.Put(context.Background(), "v1/streams/x.pack", bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if reqCount != store.MaxAttemptsForTest {
		t.Errorf("server saw %d requests, want %d", reqCount, store.MaxAttemptsForTest)
	}
}

// -----------------------------------------------------------------------
// 8. Deadline: a server that never responds and a 200ms context deadline
//    returns within about 200ms plus slack, with errors.Is true for both
//    ErrStorageUnavailable and context.DeadlineExceeded. A GET body that
//    stalls mid-read is aborted by ctx.
// -----------------------------------------------------------------------

func TestDeadline(t *testing.T) {
	// A plain defer, not t.Cleanup: it must unblock the handler before
	// newFakeServer's t.Cleanup(srv.Close) runs, since Close blocks until
	// every outstanding handler returns, and t.Cleanup funcs run in
	// last-registered-first order relative to each other but always after
	// this function's own defers.
	block := make(chan struct{})
	defer close(block)

	handler := func(w http.ResponseWriter, r *http.Request) {
		<-block
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, time.Now)

	t.Run("put", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		start := time.Now()
		body := []byte("x")
		err := c.Put(ctx, "v1/streams/x.pack", bytes.NewReader(body), int64(len(body)))
		elapsed := time.Since(start)

		if elapsed > time.Second {
			t.Errorf("Put took %s, want well under 1s", elapsed)
		}
		if !errors.Is(err, store.ErrStorageUnavailable) {
			t.Errorf("errors.Is(err, ErrStorageUnavailable) = false, err = %v", err)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("errors.Is(err, context.DeadlineExceeded) = false, err = %v", err)
		}
	})

	t.Run("get", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		start := time.Now()
		_, err := c.Get(ctx, "v1/streams/x.json")
		elapsed := time.Since(start)

		if elapsed > time.Second {
			t.Errorf("Get took %s, want well under 1s", elapsed)
		}
		if !errors.Is(err, store.ErrStorageUnavailable) {
			t.Errorf("errors.Is(err, ErrStorageUnavailable) = false, err = %v", err)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("errors.Is(err, context.DeadlineExceeded) = false, err = %v", err)
		}
	})
}

func TestGetBodyStallAbortedByContext(t *testing.T) {
	// See the comment in TestDeadline: this must be a plain defer, run
	// before newFakeServer's t.Cleanup(srv.Close), not a t.Cleanup itself.
	block := make(chan struct{})
	defer close(block)

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("partial"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-block
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, time.Now)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	rc, err := c.Get(ctx, "v1/streams/stall.json")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer rc.Close()

	start := time.Now()
	_, err = io.ReadAll(rc)
	elapsed := time.Since(start)

	if elapsed > time.Second {
		t.Errorf("read took %s, want well under 1s", elapsed)
	}
	if !errors.Is(err, store.ErrStorageUnavailable) {
		t.Errorf("errors.Is(err, ErrStorageUnavailable) = false, err = %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("errors.Is(err, context.DeadlineExceeded) = false, err = %v", err)
	}
}

// -----------------------------------------------------------------------
// 9. One line, no secrets: every returned error has no '\n', and none
//    contains the secret access key, the session token, or the signature.
// -----------------------------------------------------------------------

func TestErrorMessagesOneLineNoSecrets(t *testing.T) {
	restore := store.SetBackoffForTest(time.Millisecond, 5*time.Millisecond)
	defer restore()

	sessionToken := "FQoGZXIvYXdzEB0aDPS3SECRETTOKENVALUE"
	j := &store.Journal{
		Endpoint:  "http://s3.fake.test",
		Region:    testRegion,
		Bucket:    "test-bucket",
		Prefix:    "v1",
		PathStyle: true,
		Credentials: store.Credentials{
			AccessKeyID:     testCreds.AccessKeyID,
			SecretAccessKey: testCreds.SecretAccessKey,
			SessionToken:    sessionToken,
		},
	}

	cases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "permanent-refusal",
			handler: func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				w.WriteHeader(http.StatusForbidden)
				w.Write(xmlError("SignatureDoesNotMatch"))
			},
		},
		{
			name: "retries-exhausted",
			handler: func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				w.WriteHeader(http.StatusInternalServerError)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := newFakeServer(t, false, tc.handler)
			c := store.NewClientForTest(j, client, fixedClock(time.Now()))

			body := []byte("x")
			err := c.Put(context.Background(), "v1/streams/x.pack", bytes.NewReader(body), int64(len(body)))
			if err == nil {
				t.Fatal("Put succeeded, want an error")
			}
			msg := err.Error()
			if strings.ContainsAny(msg, "\n\r") {
				t.Errorf("error message contains a newline: %q", msg)
			}
			if strings.Contains(msg, j.Credentials.SecretAccessKey) {
				t.Errorf("error message leaks the secret access key: %q", msg)
			}
			if strings.Contains(msg, sessionToken) {
				t.Errorf("error message leaks the session token: %q", msg)
			}
			if strings.Contains(strings.ToLower(msg), "authorization=") {
				t.Errorf("error message leaks an Authorization value: %q", msg)
			}
		})
	}
}

// -----------------------------------------------------------------------
// 10. URL building: path-style and virtual-hosted, an empty and a nested
//     prefix, and RawPath encoding, observed through the request the fake
//     server actually receives.
// -----------------------------------------------------------------------

func TestObjectURLBuilding(t *testing.T) {
	tests := []struct {
		name      string
		pathStyle bool
		prefix    string
		key       string
		wantPath  string
		wantHost  string
	}{
		{
			name:      "path-style-nested-prefix",
			pathStyle: true,
			prefix:    "v1/streams",
			key:       "a.json",
			wantPath:  "/test-bucket/v1/streams/a.json",
			wantHost:  "s3.fake.test",
		},
		{
			name:      "path-style-empty-prefix",
			pathStyle: true,
			prefix:    "",
			key:       "a.json",
			wantPath:  "/test-bucket/a.json",
			wantHost:  "s3.fake.test",
		},
		{
			name:      "virtual-hosted-nested-prefix",
			pathStyle: false,
			prefix:    "v1/streams",
			key:       "a.json",
			wantPath:  "/v1/streams/a.json",
			wantHost:  "test-bucket.s3.fake.test",
		},
		{
			name:      "virtual-hosted-empty-prefix",
			pathStyle: false,
			prefix:    "",
			key:       "a.json",
			wantPath:  "/a.json",
			wantHost:  "test-bucket.s3.fake.test",
		},
		{
			name:      "raw-path-encoding",
			pathStyle: true,
			prefix:    "v1",
			key:       "streams/tx 1+2.json",
			wantPath:  "/test-bucket/v1/streams/tx 1+2.json",
			wantHost:  "s3.fake.test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPath, gotRawPath, gotHost string
			handler := func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotRawPath = r.URL.EscapedPath()
				gotHost = r.Host
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("ok"))
			}
			client := newFakeServer(t, false, handler)
			j := testJournal("http://s3.fake.test", "test-bucket", tt.prefix, tt.pathStyle)
			c := store.NewClientForTest(j, client, fixedClock(time.Now()))

			rc, err := c.Get(context.Background(), tt.key)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			rc.Close()

			if gotPath != tt.wantPath {
				t.Errorf("path = %q, want %q", gotPath, tt.wantPath)
			}
			if gotHost != tt.wantHost {
				t.Errorf("host = %q, want %q", gotHost, tt.wantHost)
			}
			if strings.Contains(tt.key, " ") && strings.Contains(gotRawPath, " ") {
				t.Errorf("RawPath %q was not percent-encoded", gotRawPath)
			}
		})
	}
}

// -----------------------------------------------------------------------
// 11. Redirects are never followed. NewClient itself blocks them, and a
//     PUT or GET answered with a 3xx-plus-Location sees the 3xx as
//     classify does - a permanent refusal - instead of net/http silently
//     replaying it as a GET to Location.
// -----------------------------------------------------------------------

func TestNewClientBlocksRedirects(t *testing.T) {
	j := testJournal("https://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClient(j)
	if err := store.CheckRedirectForTest(c); err != http.ErrUseLastResponse {
		t.Fatalf("CheckRedirect = %v, want http.ErrUseLastResponse", err)
	}
}

func TestPutRedirectNotFollowed(t *testing.T) {
	var reqCount int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		if r.Method == http.MethodPut {
			io.Copy(io.Discard, r.Body)
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		// Only reached if the redirect was followed: a bodyless GET to
		// Location that a broken client would see as a successful write.
		w.WriteHeader(http.StatusOK)
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	body := []byte("x")
	err := c.Put(context.Background(), "v1/streams/x.pack", bytes.NewReader(body), int64(len(body)))
	if err == nil {
		t.Fatal("Put succeeded following a redirect: nothing was actually written")
	}
	if !errors.Is(err, store.ErrStorageRefused) {
		t.Errorf("errors.Is(err, ErrStorageRefused) = false, err = %v", err)
	}
	if errors.Is(err, store.ErrStorageUnavailable) {
		t.Errorf("a redirect must not read as ErrStorageUnavailable (retryable): %v", err)
	}
	if reqCount != 1 {
		t.Errorf("server saw %d requests, want 1 (the redirect must not be followed)", reqCount)
	}
}

func TestGetRedirectNotFollowedNoLeak(t *testing.T) {
	var reqCount int32
	var foreignHit bool
	var foreignToken string
	handler := func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		if strings.Contains(r.URL.Path, "foreign") {
			// Only reached if the redirect was followed: a request that
			// would otherwise never happen, carrying whatever credentials
			// net/http chose to forward.
			foreignHit = true
			foreignToken = r.Header.Get("X-Amz-Security-Token")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("evil bytes"))
			return
		}
		http.Redirect(w, r, "http://evil.test/foreign", http.StatusMovedPermanently)
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	j.Credentials.SessionToken = "FQoGZXIvYXdzEB0aDPS3SECRETTOKENVALUE"
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	rc, err := c.Get(context.Background(), "v1/streams/x.json")
	if err == nil {
		rc.Close()
		t.Fatal("Get succeeded following a redirect")
	}
	if !errors.Is(err, store.ErrStorageRefused) {
		t.Errorf("errors.Is(err, ErrStorageRefused) = false, err = %v", err)
	}
	if foreignHit {
		t.Errorf("the redirect target was contacted, X-Amz-Security-Token = %q", foreignToken)
	}
	if reqCount != 1 {
		t.Errorf("server saw %d requests, want 1 (the redirect must not be followed)", reqCount)
	}
}

// -----------------------------------------------------------------------
// 12. A zero-byte PUT over https sends Content-Length: 0 with no
//     Transfer-Encoding, so S3 does not answer 411 MissingContentLength.
// -----------------------------------------------------------------------

func TestZeroByteHTTPSPut(t *testing.T) {
	var gotContentLength int64
	var gotTransferEncoding []string
	var gotBodyLen int
	handler := func(w http.ResponseWriter, r *http.Request) {
		gotContentLength = r.ContentLength
		gotTransferEncoding = r.TransferEncoding
		got, _ := io.ReadAll(r.Body)
		gotBodyLen = len(got)
		w.WriteHeader(http.StatusOK)
	}
	client := newFakeServer(t, true, handler)
	j := testJournal("https://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	if err := c.Put(context.Background(), "v1/streams/empty.pack", bytes.NewReader(nil), 0); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if gotContentLength != 0 {
		t.Errorf("Content-Length = %d, want 0", gotContentLength)
	}
	if len(gotTransferEncoding) != 0 {
		t.Errorf("Transfer-Encoding = %v, want none", gotTransferEncoding)
	}
	if gotBodyLen != 0 {
		t.Errorf("server received %d body bytes, want 0", gotBodyLen)
	}
}

// -----------------------------------------------------------------------
// 13. Transport errors are retried only when transient. An untrusted TLS
//     certificate, a caller ReaderAt shorter than the declared size, a DNS
//     name that does not exist, a port number that cannot exist, and a TLS
//     alert (protocol mismatch, a required client certificate) are all
//     permanent - retrying any of them can never succeed - so they must
//     classify as ErrStorageRefused, not ErrStorageUnavailable, and must
//     not be retried maxAttempts times. The last three all surface as
//     *net.OpError, the same as the connection-level failures that must
//     still be retried, so classify has to tell them apart by more than
//     the type alone.
// -----------------------------------------------------------------------

func TestTLSCertificateErrorIsPermanent(t *testing.T) {
	restore := store.SetBackoffForTest(time.Millisecond, 5*time.Millisecond)
	defer restore()

	var reqCount int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		w.WriteHeader(http.StatusOK)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
		// Deliberately no InsecureSkipVerify and no custom RootCAs: the
		// fake server's self-signed leaf must fail real verification, the
		// same as a misconfigured endpoint or a private CA walden was
		// never told to trust.
	}
	client := &http.Client{Transport: transport}

	j := testJournal("https://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	body := []byte("x")
	err := c.Put(context.Background(), "v1/streams/x.pack", bytes.NewReader(body), int64(len(body)))
	if err == nil {
		t.Fatal("Put succeeded against an untrusted certificate")
	}
	if !errors.Is(err, store.ErrStorageRefused) {
		t.Errorf("errors.Is(err, ErrStorageRefused) = false, err = %v", err)
	}
	if errors.Is(err, store.ErrStorageUnavailable) {
		t.Errorf("an untrusted certificate must not be classified as transient: %v", err)
	}
	if reqCount != 0 {
		t.Errorf("server handler ran %d times, want 0 (the TLS handshake must fail first)", reqCount)
	}
}

// shortReaderAt reports fewer bytes than a caller-declared size, the way a
// pack file truncated on disk after the caller measured it would.
type shortReaderAt struct {
	data []byte
}

func (s shortReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(s.data)) {
		return 0, io.EOF
	}
	n := copy(p, s.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func TestShortReaderAtIsPermanent(t *testing.T) {
	restore := store.SetBackoffForTest(time.Millisecond, 5*time.Millisecond)
	defer restore()

	handler := func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	// Declares 10 bytes but the ReaderAt only ever has 3.
	err := c.Put(context.Background(), "v1/streams/short.pack", shortReaderAt{data: []byte("abc")}, 10)
	if err == nil {
		t.Fatal("Put succeeded reading past the end of a short ReaderAt")
	}
	if !errors.Is(err, store.ErrStorageRefused) {
		t.Errorf("errors.Is(err, ErrStorageRefused) = false, err = %v", err)
	}
	if errors.Is(err, store.ErrStorageUnavailable) {
		t.Errorf("a short ReaderAt must not be classified as transient: %v", err)
	}
}

// TestDNSNotFoundIsPermanent uses the .invalid TLD, which RFC 2606 reserves
// as guaranteed never to resolve, so the lookup fails the same way a typo
// in a journal URL (or virtual-hosted addressing against a bucket with no
// wildcard DNS) would. The backoff is set to an hour: if classify ever
// regresses to retrying this, the test - bounded by ctx - fails instead of
// hanging.
func TestDNSNotFoundIsPermanent(t *testing.T) {
	restore := store.SetBackoffForTest(time.Hour, time.Hour)
	defer restore()

	j := testJournal("http://walden-nonexistent.invalid", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, http.DefaultClient, fixedClock(time.Now()))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	body := []byte("x")
	err := c.Put(ctx, "v1/streams/x.pack", bytes.NewReader(body), int64(len(body)))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Put succeeded against a DNS name that does not exist")
	}
	if elapsed > 2*time.Second {
		t.Errorf("Put took %s, want a single fast attempt (a retry would sleep up to 1h)", elapsed)
	}
	if !errors.Is(err, store.ErrStorageRefused) {
		t.Errorf("errors.Is(err, ErrStorageRefused) = false, err = %v", err)
	}
	if errors.Is(err, store.ErrStorageUnavailable) {
		t.Errorf("a nonexistent DNS name must not be classified as transient: %v", err)
	}
}

// TestInvalidPortIsPermanent uses a port number outside 0-65535, which
// net.Dial rejects locally (an *net.AddrError) before any network I/O, the
// same way a malformed journal URL would.
func TestInvalidPortIsPermanent(t *testing.T) {
	restore := store.SetBackoffForTest(time.Hour, time.Hour)
	defer restore()

	j := testJournal("http://s3.fake.test:99999", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, http.DefaultClient, fixedClock(time.Now()))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	body := []byte("x")
	err := c.Put(ctx, "v1/streams/x.pack", bytes.NewReader(body), int64(len(body)))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Put succeeded against an impossible port")
	}
	if elapsed > 2*time.Second {
		t.Errorf("Put took %s, want a single fast attempt (a retry would sleep up to 1h)", elapsed)
	}
	if !errors.Is(err, store.ErrStorageRefused) {
		t.Errorf("errors.Is(err, ErrStorageRefused) = false, err = %v", err)
	}
	if errors.Is(err, store.ErrStorageUnavailable) {
		t.Errorf("an invalid port must not be classified as transient: %v", err)
	}
}

// TestTLSAlertIsPermanent points a client that refuses to negotiate above
// TLS 1.2 at a server that requires TLS 1.3, so the server sends a
// protocol-version alert while parsing ClientHello - before either side
// considers the handshake complete - and crypto/tls wraps it as
// *net.OpError{Op: "remote error"}, the same shape any other alert takes.
// (A ClientAuth-required-but-absent repro was tried first and rejected: in
// TLS 1.3 the client's Handshake call can return success before the server
// finishes validating the (absent) client certificate, so the failure
// racily surfaces as a local "write: use of closed network connection"
// instead of the alert this test needs.)
func TestTLSAlertIsPermanent(t *testing.T) {
	restore := store.SetBackoffForTest(time.Hour, time.Hour)
	defer restore()

	var reqCount int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		w.WriteHeader(http.StatusOK)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(handler))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MaxVersion:         tls.VersionTLS12,
		},
	}
	client := &http.Client{Transport: transport}

	j := testJournal("https://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	body := []byte("x")
	err := c.Put(ctx, "v1/streams/x.pack", bytes.NewReader(body), int64(len(body)))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Put succeeded despite a TLS version the server does not accept")
	}
	if elapsed > 2*time.Second {
		t.Errorf("Put took %s, want a single fast attempt (a retry would sleep up to 1h)", elapsed)
	}
	if !errors.Is(err, store.ErrStorageRefused) {
		t.Errorf("errors.Is(err, ErrStorageRefused) = false, err = %v", err)
	}
	if errors.Is(err, store.ErrStorageUnavailable) {
		t.Errorf("a TLS alert must not be classified as transient: %v", err)
	}
	if reqCount != 0 {
		t.Errorf("server handler ran %d times, want 0 (the TLS handshake must fail first)", reqCount)
	}
}

// -----------------------------------------------------------------------
// 14. A deadline shorter than the next backoff stops at once instead of
//     sleeping past it, and reports the real cause (a 503) rather than
//     letting it be replaced by a context error. Both Put and Get.
// -----------------------------------------------------------------------

func TestDeadlineShorterThanBackoffStopsWithoutSleeping(t *testing.T) {
	// base == cap == 1h makes the planned wait, uniformly random in
	// [0, 1h], overwhelmingly likely to exceed the 300ms deadline below;
	// the failure probability is about 300ms/1h (~1 in 12000).
	restore := store.SetBackoffForTest(time.Hour, time.Hour)
	defer restore()

	handler := func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write(xmlError("SlowDown"))
	}
	client := newFakeServer(t, false, handler)
	j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
	c := store.NewClientForTest(j, client, fixedClock(time.Now()))

	t.Run("put", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()

		start := time.Now()
		body := []byte("x")
		err := c.Put(ctx, "v1/streams/x.pack", bytes.NewReader(body), int64(len(body)))
		elapsed := time.Since(start)

		if elapsed > time.Second {
			t.Errorf("Put took %s, want well under 1s (must not sleep into the deadline)", elapsed)
		}
		if !errors.Is(err, store.ErrStorageUnavailable) {
			t.Errorf("errors.Is(err, ErrStorageUnavailable) = false, err = %v", err)
		}
		if !strings.Contains(err.Error(), "503") {
			t.Errorf("error = %q, want the 503 cause preserved instead of a context error", err.Error())
		}
	})

	t.Run("get", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()

		start := time.Now()
		_, err := c.Get(ctx, "v1/streams/x.json")
		elapsed := time.Since(start)

		if elapsed > time.Second {
			t.Errorf("Get took %s, want well under 1s (must not sleep into the deadline)", elapsed)
		}
		if !errors.Is(err, store.ErrStorageUnavailable) {
			t.Errorf("errors.Is(err, ErrStorageUnavailable) = false, err = %v", err)
		}
		if !strings.Contains(err.Error(), "503") {
			t.Errorf("error = %q, want the 503 cause preserved instead of a context error", err.Error())
		}
	})
}

// -----------------------------------------------------------------------
// 15. A permanent refusal's why line names the S3 Code, not just the HTTP
//     status text, for every status - including the default branch that
//     previously dropped it.
// -----------------------------------------------------------------------

func TestPermanentRefusalIncludesCode(t *testing.T) {
	tests := []struct {
		name   string
		status int
		code   string
	}{
		{"403-access-denied", http.StatusForbidden, "AccessDenied"},
		{"403-signature-does-not-match", http.StatusForbidden, "SignatureDoesNotMatch"},
		{"403-request-time-too-skewed", http.StatusForbidden, "RequestTimeTooSkewed"},
		{"301-permanent-redirect", http.StatusMovedPermanently, "PermanentRedirect"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				w.WriteHeader(tt.status)
				w.Write(xmlError(tt.code))
			}
			client := newFakeServer(t, false, handler)
			j := testJournal("http://s3.fake.test", "test-bucket", "v1", true)
			c := store.NewClientForTest(j, client, fixedClock(time.Now()))

			body := []byte("x")
			err := c.Put(context.Background(), "v1/streams/x.pack", bytes.NewReader(body), int64(len(body)))
			if err == nil {
				t.Fatal("Put succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tt.code) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tt.code)
			}
		})
	}
}
