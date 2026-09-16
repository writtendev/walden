package store_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/store"
)

// -----------------------------------------------------------------------
// 1. The generic AWS SigV4 conformance suite (awslabs/aws-c-auth).
//
// See testdata/sigv4/README.md for provenance. Each case directory is
// driven through canonicalRequest, stringToSign, signingKey and the
// Authorization formatter directly rather than through signV4, because the
// suite's "service" is not S3: whether the body is hashed at all
// (context.json's sign_body) is per-case, where production signV4 always
// hashes the payload, as S3 requires. x-amz-date and (when credentials
// carry a token) x-amz-security-token are, like x-amz-content-sha256,
// signing-time additions that never appear in request.txt itself — the
// harness adds them the same way signV4 would.
// -----------------------------------------------------------------------

// suiteSkip lists cases this signer does not, and per WALD-19's scope
// never will, reproduce, each with a one-line reason. The test below fails
// if a listed case stops existing in testdata, so this list cannot go
// stale silently.
var suiteSkip = map[string]string{
	"get-relative-normalized":            "assumes dot-segment normalization; S3 signs the path single-encoded and unnormalized",
	"get-relative-relative-normalized":   "assumes dot-segment normalization; S3 signs the path single-encoded and unnormalized",
	"get-slash-dot-slash-normalized":     "assumes dot-segment normalization; S3 signs the path single-encoded and unnormalized",
	"get-slash-normalized":               "assumes dot-segment normalization; S3 signs the path single-encoded and unnormalized",
	"get-slash-pointless-dot-normalized": "assumes dot-segment normalization; S3 signs the path single-encoded and unnormalized",
	"get-slashes-normalized":             "assumes dot-segment normalization; S3 signs the path single-encoded and unnormalized",
}

func TestSigV4Suite(t *testing.T) {
	const root = "testdata/sigv4/suite"

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", root, err)
	}

	seenSkip := make(map[string]bool, len(suiteSkip))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue // README.md sits beside suite/, not inside it, but be defensive.
		}
		name := entry.Name()
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(root, name)
			if reason, ok := suiteSkip[name]; ok {
				seenSkip[name] = true
				// A case can only sit in suiteSkip while it genuinely fails.
				// If it now matches every fixture, the reason it was skipped
				// for no longer holds and the skip has gone stale silently.
				if mismatches := suiteCaseMismatches(t, dir); len(mismatches) == 0 {
					t.Errorf("case %q is listed in suiteSkip (%s) but passes unmodified; remove it from suiteSkip", name, reason)
					return
				}
				t.Skip(reason)
			}
			for _, mismatch := range suiteCaseMismatches(t, dir) {
				t.Error(mismatch)
			}
		})
	}

	for name := range suiteSkip {
		if !seenSkip[name] {
			t.Errorf("suiteSkip names case %q, which no longer exists under %s", name, root)
		}
	}
}

// suiteContext is context.json's shape: the fields sigv4_test.go needs out
// of the fields aws-c-auth's runner defines.
type suiteContext struct {
	Credentials struct {
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
		Token           string `json:"token"`
	} `json:"credentials"`
	Region           string `json:"region"`
	Service          string `json:"service"`
	SignBody         bool   `json:"sign_body"`
	Timestamp        string `json:"timestamp"`
	OmitSessionToken bool   `json:"omit_session_token"`
}

// suiteCaseMismatches runs the AWS SigV4 conformance check for the case in
// dir and returns one message per stage (canonical request, string to sign,
// signature, Authorization header) whose output does not match its
// fixture. An empty result means the case passes in full; suiteSkip may
// only name a case for which this is never empty, and the guard in
// TestSigV4Suite enforces that.
func suiteCaseMismatches(t *testing.T, dir string) []string {
	t.Helper()

	var ctx suiteContext
	if err := json.Unmarshal(readTestFile(t, dir, "context.json"), &ctx); err != nil {
		t.Fatalf("unmarshal context.json: %v", err)
	}
	now, err := time.Parse(time.RFC3339, ctx.Timestamp)
	if err != nil {
		t.Fatalf("parse timestamp %q: %v", ctx.Timestamp, err)
	}

	method, path, rawQuery, header, host, body := parseSuiteRequest(t, readTestFile(t, dir, "request.txt"))
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		t.Fatalf("ParseQuery(%q): %v", rawQuery, err)
	}

	// Signing-time headers: always x-amz-date, the session token when
	// credentials carry one and the case doesn't ask for it to be left out,
	// and the payload hash only when this case opted into signing the
	// body. None of these come from request.txt.
	header.Set("X-Amz-Date", now.UTC().Format(store.AmzDateFormatForTest))
	if ctx.Credentials.Token != "" && !ctx.OmitSessionToken {
		header.Set("X-Amz-Security-Token", ctx.Credentials.Token)
	}
	payloadHash := store.EmptySHA256ForTest
	if ctx.SignBody {
		sum := sha256.Sum256(body)
		payloadHash = hex.EncodeToString(sum[:])
		header.Set("X-Amz-Content-Sha256", payloadHash)
	}

	var mismatches []string

	creq, signedHeaders := store.CanonicalRequestForTest(method, path, query, header, host, payloadHash)
	if want := string(readTestFile(t, dir, "header-canonical-request.txt")); creq != want {
		mismatches = append(mismatches, fmt.Sprintf("canonical request:\n got: %q\nwant: %q", creq, want))
	}

	dateStamp := now.UTC().Format(store.DateFormatForTest)
	scope := store.ScopeStringForTest(dateStamp, ctx.Region, ctx.Service)
	sts := store.StringToSignForTest(now, scope, creq)
	if want := string(readTestFile(t, dir, "header-string-to-sign.txt")); sts != want {
		mismatches = append(mismatches, fmt.Sprintf("string to sign:\n got: %q\nwant: %q", sts, want))
	}

	key := store.SigningKeyForTest(ctx.Credentials.SecretAccessKey, dateStamp, ctx.Region, ctx.Service)
	sig := store.SignatureForTest(key, sts)
	if want := string(readTestFile(t, dir, "header-signature.txt")); sig != want {
		mismatches = append(mismatches, fmt.Sprintf("signature: got %s want %s", sig, want))
	}

	authz := store.AuthorizationHeaderForTest(ctx.Credentials.AccessKeyID, scope, signedHeaders, sig)
	if want := extractAuthorization(t, readTestFile(t, dir, "header-signed-request.txt")); authz != want {
		mismatches = append(mismatches, fmt.Sprintf("authorization header:\n got: %q\nwant: %q", authz, want))
	}

	return mismatches
}

// parseSuiteRequest parses request.txt's raw-HTTP-ish text into the pieces
// canonicalRequest needs. It is a small purpose-built parser, not
// http.ReadRequest, because some vectors (folded and duplicate headers)
// are not requests net/http's parser accepts. Lines are split on bare "\n"
// because that is how the upstream files are written; the Host header is
// pulled out of the header map and returned separately, matching how
// http.Request itself keeps it (Host, not Header).
func parseSuiteRequest(t *testing.T, data []byte) (method, path, rawQuery string, header http.Header, host string, body []byte) {
	t.Helper()

	lines := strings.Split(string(data), "\n")
	// The request line is "METHOD SP request-target SP HTTP-version".
	// request-target may itself contain an unencoded space (the
	// get-space-* cases exercise exactly that), so it cannot be found by
	// splitting on every space: split the method off the front, then the
	// HTTP version off the back, and whatever remains is the target.
	sp := strings.IndexByte(lines[0], ' ')
	if sp < 0 {
		t.Fatalf("malformed request line: %q", lines[0])
	}
	method, rest := lines[0][:sp], lines[0][sp+1:]
	lastSP := strings.LastIndexByte(rest, ' ')
	if lastSP < 0 {
		t.Fatalf("malformed request line: %q", lines[0])
	}
	target := rest[:lastSP]
	if i := strings.IndexByte(target, '?'); i >= 0 {
		path, rawQuery = target[:i], target[i+1:]
	} else {
		path = target
	}

	header = make(http.Header)
	var lastKey string
	var lastIsHost bool
	i := 1
	for ; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			i++
			break
		}
		if (line[0] == ' ' || line[0] == '\t') && (lastKey != "" || lastIsHost) {
			cont := " " + strings.TrimSpace(line)
			if lastIsHost {
				host += cont
			} else {
				vals := header[lastKey]
				vals[len(vals)-1] += cont
			}
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			t.Fatalf("malformed header line: %q", line)
		}
		key, val := line[:colon], line[colon+1:]
		if strings.EqualFold(key, "host") {
			host = val
			lastIsHost = true
			lastKey = ""
			continue
		}
		lastIsHost = false
		lastKey = http.CanonicalHeaderKey(key)
		header.Add(key, val)
	}
	if i < len(lines) {
		body = []byte(strings.Join(lines[i:], "\n"))
	}
	return method, path, rawQuery, header, host, body
}

// extractAuthorization pulls the value of the "Authorization:" line out of
// a header-signed-request.txt fixture.
func extractAuthorization(t *testing.T, signedRequest []byte) string {
	t.Helper()
	for _, line := range strings.Split(string(signedRequest), "\n") {
		if v, ok := strings.CutPrefix(line, "Authorization:"); ok {
			return v
		}
	}
	t.Fatalf("no Authorization line in fixture")
	return ""
}

func readTestFile(t *testing.T, dir, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", filepath.Join(dir, name), err)
	}
	return data
}

// -----------------------------------------------------------------------
// 2. S3 header-auth examples: "Signature Calculations for the
// Authorization Header: Transferring Payload in a Single Chunk (AWS
// Signature Version 4)".
// https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
// -----------------------------------------------------------------------

func TestSigV4S3HeaderAuthExamples(t *testing.T) {
	const (
		accessKeyID     = "AKIAIOSFODNN7EXAMPLE"
		secretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		region          = "us-east-1"
		service         = "s3"
	)
	now, err := time.Parse(time.RFC3339, "2013-05-24T00:00:00Z")
	if err != nil {
		t.Fatalf("parse timestamp: %v", err)
	}

	tests := []struct {
		name          string
		method        string
		path          string
		rawQuery      string
		header        http.Header
		payloadHash   string
		wantSignature string
	}{
		{
			name:   "GetObject",
			method: "GET",
			path:   "/test.txt",
			header: http.Header{
				"Range": {"bytes=0-9"},
			},
			payloadHash:   store.EmptySHA256ForTest,
			wantSignature: "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
		},
		{
			name:   "PutObject",
			method: "PUT",
			path:   "/test%24file.text",
			header: http.Header{
				"Date":                {"Fri, 24 May 2013 00:00:00 GMT"},
				"X-Amz-Storage-Class": {"REDUCED_REDUNDANCY"},
			},
			payloadHash:   "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
			wantSignature: "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
		},
		{
			name:          "GetBucketLifecycle",
			method:        "GET",
			path:          "/",
			rawQuery:      "lifecycle=",
			payloadHash:   store.EmptySHA256ForTest,
			wantSignature: "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
		},
		{
			name:          "GetBucketListObjects",
			method:        "GET",
			path:          "/",
			rawQuery:      "max-keys=2&prefix=J",
			payloadHash:   store.EmptySHA256ForTest,
			wantSignature: "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := tt.header
			if header == nil {
				header = http.Header{}
			}
			req, err := http.NewRequest(tt.method, "https://examplebucket.s3.amazonaws.com"+tt.path, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.URL.RawQuery = tt.rawQuery
			req.Host = "examplebucket.s3.amazonaws.com"
			for name, values := range header {
				for _, v := range values {
					req.Header.Add(name, v)
				}
			}

			creds := store.Credentials{AccessKeyID: accessKeyID, SecretAccessKey: secretAccessKey}
			sig := store.SignV4ForTest(req, creds, region, service, tt.payloadHash, now)
			if sig != tt.wantSignature {
				t.Errorf("signature = %s, want %s", sig, tt.wantSignature)
			}
		})
	}
}

// -----------------------------------------------------------------------
// 3. Streaming: "Signature Calculations for the Authorization Header:
// Transferring Payload in Multiple Chunks (Chunked Upload) (AWS Signature
// Version 4)". https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html
// -----------------------------------------------------------------------

func TestSigV4Streaming(t *testing.T) {
	const (
		accessKeyID     = "AKIAIOSFODNN7EXAMPLE"
		secretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		region          = "us-east-1"
		service         = "s3"

		decodedLength     = 66560 // 65536 + 1024 bytes of 'a'
		chunkSize         = 65536
		wantContentLength = 66824

		wantSeedCanonicalRequest = "PUT\n" +
			"/examplebucket/chunkObject.txt\n" +
			"\n" +
			"content-encoding:aws-chunked\n" +
			"content-length:66824\n" +
			"host:s3.amazonaws.com\n" +
			"x-amz-content-sha256:STREAMING-AWS4-HMAC-SHA256-PAYLOAD\n" +
			"x-amz-date:20130524T000000Z\n" +
			"x-amz-decoded-content-length:66560\n" +
			"x-amz-storage-class:REDUCED_REDUNDANCY\n" +
			"\n" +
			"content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class\n" +
			"STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
		wantSeedStringToSign = "AWS4-HMAC-SHA256\n" +
			"20130524T000000Z\n" +
			"20130524/us-east-1/s3/aws4_request\n" +
			"cee3fed04b70f867d036f722359b0b1f2f0e5dc0efadbc082b76c4c60e316455"
		wantSeedSignature = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9"
	)

	wantChunks := []struct {
		size      int
		signature string
	}{
		{65536, "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648"},
		{1024, "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497"},
		{0, "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9"},
	}

	now, err := time.Parse(time.RFC3339, "2013-05-24T00:00:00Z")
	if err != nil {
		t.Fatalf("parse timestamp: %v", err)
	}

	req, err := http.NewRequest("PUT", "https://s3.amazonaws.com/examplebucket/chunkObject.txt", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Host = "s3.amazonaws.com"
	req.Header.Set("X-Amz-Storage-Class", "REDUCED_REDUNDANCY")
	req.Header.Set("Content-Encoding", "aws-chunked")
	req.Header.Set("X-Amz-Decoded-Content-Length", "66560")
	req.Header.Set("Content-Length", "66824")

	if got := store.ChunkedLengthForTest(decodedLength, chunkSize); got != wantContentLength {
		t.Fatalf("ChunkedLengthForTest(%d, %d) = %d, want %d", decodedLength, chunkSize, got, wantContentLength)
	}

	// signV4 sets X-Amz-Date and X-Amz-Content-Sha256 on req as a side
	// effect, the same way it would for a real streaming PUT; the seed
	// canonical request and string to sign are then recomputed from that
	// same, now fully-populated req.Header and pinned against the doc
	// example, so a mismatch is legible at the step that caused it.
	creds := store.Credentials{AccessKeyID: accessKeyID, SecretAccessKey: secretAccessKey}
	seed := store.SignV4ForTest(req, creds, region, service, store.StreamingPayloadForTest, now)
	if seed != wantSeedSignature {
		t.Fatalf("seed signature = %s, want %s", seed, wantSeedSignature)
	}

	creq, _ := store.CanonicalRequestForTest(req.Method, req.URL.Path, req.URL.Query(), req.Header, req.Host, store.StreamingPayloadForTest)
	if creq != wantSeedCanonicalRequest {
		t.Errorf("seed canonical request:\n got: %q\nwant: %q", creq, wantSeedCanonicalRequest)
	}
	dateStamp := now.UTC().Format(store.DateFormatForTest)
	scope := store.ScopeStringForTest(dateStamp, region, service)
	sts := store.StringToSignForTest(now, scope, creq)
	if sts != wantSeedStringToSign {
		t.Errorf("seed string to sign:\n got: %q\nwant: %q", sts, wantSeedStringToSign)
	}

	key := store.SigningKeyForTest(secretAccessKey, dateStamp, region, service)
	body := bytes.NewReader(bytes.Repeat([]byte("a"), decodedLength))
	chunked := store.NewChunkedBodyForTest(body, chunkSize, key, scope, now, seed)

	framed, err := io.ReadAll(chunked)
	if err != nil {
		t.Fatalf("ReadAll(chunked body): %v", err)
	}
	if int64(len(framed)) != wantContentLength {
		t.Errorf("framed body length = %d, want %d", len(framed), wantContentLength)
	}

	rest := framed
	for i, want := range wantChunks {
		prefix := strconv.FormatInt(int64(want.size), 16) + ";chunk-signature=" + want.signature + "\r\n"
		if !bytes.HasPrefix(rest, []byte(prefix)) {
			end := len(rest)
			if want := len(prefix) + 16; want < end {
				end = want
			}
			t.Fatalf("chunk %d: framed body does not start with %q; has %q", i, prefix, rest[:end])
		}
		rest = rest[len(prefix):]

		for _, b := range rest[:want.size] {
			if b != 'a' {
				t.Fatalf("chunk %d: data byte = %q, want 'a'", i, b)
			}
		}
		rest = rest[want.size:]

		if !bytes.HasPrefix(rest, []byte("\r\n")) {
			t.Fatalf("chunk %d: missing trailing CRLF", i)
		}
		rest = rest[2:]
	}
	if len(rest) != 0 {
		t.Errorf("%d unexpected trailing bytes after the final chunk", len(rest))
	}
}

// -----------------------------------------------------------------------
// 4. Unsigned payload: "Authenticating Requests: Using Query Parameters
// (AWS Signature Version 4)", the presigned-URL GET Object example — the
// only published UNSIGNED-PAYLOAD vector. walden does not implement
// presigned URLs; this exercises canonicalRequest directly with that
// example's query parameters and UNSIGNED-PAYLOAD, per WALD-19's stated
// risk note.
// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
// -----------------------------------------------------------------------

func TestSigV4UnsignedPayloadPresignExample(t *testing.T) {
	const (
		secretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		accessKeyID     = "AKIAIOSFODNN7EXAMPLE"
		region          = "us-east-1"
		service         = "s3"

		wantCanonicalRequest = "GET\n" +
			"/test.txt\n" +
			"X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host\n" +
			"host:examplebucket.s3.amazonaws.com\n" +
			"\n" +
			"host\n" +
			"UNSIGNED-PAYLOAD"
		wantStringToSign = "AWS4-HMAC-SHA256\n" +
			"20130524T000000Z\n" +
			"20130524/us-east-1/s3/aws4_request\n" +
			"3bfa292879f6447bbcda7001decf97f4a54dc650c8942174ae0a9121cf58ad04"
		wantSignature = "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
	)

	now, err := time.Parse(time.RFC3339, "2013-05-24T00:00:00Z")
	if err != nil {
		t.Fatalf("parse timestamp: %v", err)
	}

	query := url.Values{
		"X-Amz-Algorithm":     {"AWS4-HMAC-SHA256"},
		"X-Amz-Credential":    {"AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request"},
		"X-Amz-Date":          {"20130524T000000Z"},
		"X-Amz-Expires":       {"86400"},
		"X-Amz-SignedHeaders": {"host"},
	}

	creq, signedHeaders := store.CanonicalRequestForTest("GET", "/test.txt", query, http.Header{}, "examplebucket.s3.amazonaws.com", store.UnsignedPayloadForTest)
	if creq != wantCanonicalRequest {
		t.Fatalf("canonical request:\n got: %q\nwant: %q", creq, wantCanonicalRequest)
	}
	if signedHeaders != "host" {
		t.Fatalf("signed headers = %q, want %q", signedHeaders, "host")
	}

	dateStamp := now.UTC().Format(store.DateFormatForTest)
	scope := store.ScopeStringForTest(dateStamp, region, service)
	sts := store.StringToSignForTest(now, scope, creq)
	if sts != wantStringToSign {
		t.Fatalf("string to sign:\n got: %q\nwant: %q", sts, wantStringToSign)
	}

	key := store.SigningKeyForTest(secretAccessKey, dateStamp, region, service)
	sig := store.SignatureForTest(key, sts)
	if sig != wantSignature {
		t.Fatalf("signature = %s, want %s", sig, wantSignature)
	}
}

// TestSigV4UnsignedPayloadSetsContentSha256 is the structural half of the
// unsigned-payload coverage: signV4 called with unsignedPayload sets
// X-Amz-Content-Sha256 to the literal string UNSIGNED-PAYLOAD and signs
// that value, rather than a real body hash.
func TestSigV4UnsignedPayloadSetsContentSha256(t *testing.T) {
	now := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)

	req, err := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Host = "examplebucket.s3.amazonaws.com"

	creds := store.Credentials{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	signature := store.SignV4ForTest(req, creds, "us-east-1", "s3", store.UnsignedPayloadForTest, now)

	if got := req.Header.Get("X-Amz-Content-Sha256"); got != store.UnsignedPayloadForTest {
		t.Fatalf("X-Amz-Content-Sha256 = %q, want %q", got, store.UnsignedPayloadForTest)
	}

	// Recompute independently through the low-level functions and confirm
	// signV4 signed the literal UNSIGNED-PAYLOAD string, not a body hash.
	creq, _ := store.CanonicalRequestForTest(req.Method, req.URL.Path, req.URL.Query(), req.Header, req.Host, store.UnsignedPayloadForTest)
	dateStamp := now.UTC().Format(store.DateFormatForTest)
	scope := store.ScopeStringForTest(dateStamp, "us-east-1", "s3")
	sts := store.StringToSignForTest(now, scope, creq)
	key := store.SigningKeyForTest(creds.SecretAccessKey, dateStamp, "us-east-1", "s3")
	want := store.SignatureForTest(key, sts)

	if signature != want {
		t.Fatalf("signature = %s, want %s", signature, want)
	}
}

// -----------------------------------------------------------------------
// 5. CanonicalHeaders Trim() collapses ASCII space and tab only. S3 does
// not treat other Unicode whitespace — e.g. U+00A0 (NBSP) or U+0085
// (NEL) — as trimmable or collapsible, so a header value carrying one
// must reach the canonical request unchanged, aside from ASCII trimming
// and collapsing around it.
// -----------------------------------------------------------------------

func TestSigV4CanonicalHeadersOnlyCollapseASCIIWhitespace(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "NBSP is not a separator",
			value: "foo bar",
			want:  "foo bar",
		},
		{
			name:  "NEL is not a separator",
			value: "foobar",
			want:  "foobar",
		},
		{
			name:  "ASCII space/tab trimmed and collapsed around non-ASCII whitespace",
			value: " foo bar\tbaz ",
			want:  "foo bar baz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{"X-Test": {tt.value}}
			creq, _ := store.CanonicalRequestForTest("GET", "/", url.Values{}, headers, "example.com", store.EmptySHA256ForTest)

			wantLine := "x-test:" + tt.want + "\n"
			if !strings.Contains(creq, wantLine) {
				t.Fatalf("canonical request does not contain %q\ngot:\n%s", wantLine, creq)
			}
		})
	}
}

// -----------------------------------------------------------------------
// 6. Session token: signV4 sets X-Amz-Security-Token from
// Credentials.SessionToken and signs it, the same way it always sets and
// signs X-Amz-Content-Sha256 (see
// TestSigV4UnsignedPayloadSetsContentSha256). Credentials, region,
// service, and timestamp are the published get-vanilla-with-session-token
// suite vector (testdata/sigv4/suite); that case's own fixture files
// aren't reused byte for byte because it signs for a generic "service"
// that, per its sign_body: false, never signs x-amz-content-sha256, where
// production signV4 always does (its payload is empty here regardless, so
// the hash it signs is the same emptySHA256 value either way).
// -----------------------------------------------------------------------

func TestSigV4SessionTokenIsSetAndSigned(t *testing.T) {
	const (
		accessKeyID     = "AKIDEXAMPLE"
		secretAccessKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
		sessionToken    = "6e86291e8372ff2a2260956d9b8aae1d763fbf315fa00fa31553b73ebf194267"
		region          = "us-east-1"
		service         = "service"
	)
	now, err := time.Parse(time.RFC3339, "2015-08-30T12:36:00Z")
	if err != nil {
		t.Fatalf("parse timestamp: %v", err)
	}

	req, err := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Host = "example.amazonaws.com"

	creds := store.Credentials{AccessKeyID: accessKeyID, SecretAccessKey: secretAccessKey, SessionToken: sessionToken}
	signature := store.SignV4ForTest(req, creds, region, service, store.EmptySHA256ForTest, now)

	if got := req.Header.Get("X-Amz-Security-Token"); got != sessionToken {
		t.Fatalf("X-Amz-Security-Token = %q, want %q", got, sessionToken)
	}

	// Recompute independently through the low-level functions, from req's
	// now fully-populated headers, and confirm signV4 signed the same
	// bytes it sent. This is what catches a security token that lands on
	// req only after signV4's internal canonicalRequest call already ran
	// (e.g. moved after that call): the header would be on req, but
	// absent from signedHeaders and from the signature signV4 actually
	// returned, so the two would disagree below.
	creq, signedHeaders := store.CanonicalRequestForTest(req.Method, req.URL.Path, req.URL.Query(), req.Header, req.Host, store.EmptySHA256ForTest)
	if !strings.Contains(signedHeaders, "x-amz-security-token") {
		t.Fatalf("signed headers = %q, want it to contain x-amz-security-token", signedHeaders)
	}

	dateStamp := now.UTC().Format(store.DateFormatForTest)
	scope := store.ScopeStringForTest(dateStamp, region, service)
	sts := store.StringToSignForTest(now, scope, creq)
	key := store.SigningKeyForTest(secretAccessKey, dateStamp, region, service)
	want := store.SignatureForTest(key, sts)

	if signature != want {
		t.Fatalf("signature = %s, want %s", signature, want)
	}

	wantAuthz := store.AuthorizationHeaderForTest(accessKeyID, scope, signedHeaders, want)
	if authz := req.Header.Get("Authorization"); authz != wantAuthz {
		t.Fatalf("Authorization = %q, want %q", authz, wantAuthz)
	}
}
