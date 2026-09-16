package store

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// This file signs outgoing object-storage requests with AWS Signature
// Version 4, S3's flavor of it: single-encoded, unnormalized paths, no
// double-encoding, no dot-segment resolution. It has no clock of its own —
// every entry point takes now time.Time, so a test can hold it still and a
// caller decides what "now" means. It sends nothing; WALD-20 and WALD-21
// build the client that execs these functions before a PUT or GET.
//
// Canonicalization follows the AWS S3 API Reference, "Signature
// Calculations for the Authorization Header: Transferring Payload in a
// Single Chunk" and "...: Transferring Payload in Multiple Chunks (Chunked
// Upload)" (AWS Signature Version 4). Test vectors are cited in
// testdata/sigv4/README.md.

const (
	// unsignedPayload is the x-amz-content-sha256 value for a request whose
	// body is not covered by the signature.
	unsignedPayload = "UNSIGNED-PAYLOAD"

	// streamingPayload is the x-amz-content-sha256 value for a request body
	// framed as signed aws-chunked chunks (see newChunkedBody).
	streamingPayload = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"

	// emptySHA256 is Hex(SHA256Hash("")), used both as the payload hash of
	// an empty body and, inside chunk framing, as the hash of each chunk's
	// (always empty) trailing headers.
	emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// amzDateFormat and dateFormat are the two timestamp forms SigV4 needs:
	// the full request timestamp and the date alone that scopes the signing
	// key. Both are always rendered in UTC.
	amzDateFormat = "20060102T150405Z"
	dateFormat    = "20060102"
)

// unsignableHeaders are excluded from the signature because Go's transport
// (or an intermediary) may add or rewrite them after signing, which would
// make a previously valid signature no longer match the bytes actually
// sent.
var unsignableHeaders = map[string]bool{
	"authorization":   true,
	"user-agent":      true,
	"expect":          true,
	"x-amzn-trace-id": true,
}

// canonicalRequest builds the SigV4 canonical request and the sorted,
// semicolon-joined list of header names it signed. path is the decoded
// request path (e.g. req.URL.Path); it is URI-encoded here exactly once,
// byte by byte, with no dot-segment normalization — S3's rule, not the
// general SigV4 rule. query is encoded and sorted by key then by value.
// headers is signed in full except for unsignableHeaders; host is signed
// as the "host" header regardless of whether it appears in headers, since
// Go's http.Request keeps it separately (req.Host, not req.Header).
func canonicalRequest(method, path string, query url.Values, headers http.Header, host string, payloadHash string) (creq, signedHeaders string) {
	canonicalURI := uriEncode(path, false)
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	values := make(map[string][]string, len(headers)+1)
	for name, vals := range headers {
		lower := strings.ToLower(name)
		if unsignableHeaders[lower] {
			continue
		}
		values[lower] = append(values[lower], vals...)
	}
	values["host"] = []string{host}

	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)

	var headerBlock strings.Builder
	for _, name := range names {
		normalized := make([]string, len(values[name]))
		for i, v := range values[name] {
			normalized[i] = collapseSpaces(v)
		}
		headerBlock.WriteString(name)
		headerBlock.WriteByte(':')
		headerBlock.WriteString(strings.Join(normalized, ","))
		headerBlock.WriteByte('\n')
	}
	signedHeaders = strings.Join(names, ";")

	creq = method + "\n" +
		canonicalURI + "\n" +
		canonicalQueryString(query) + "\n" +
		headerBlock.String() + "\n" +
		signedHeaders + "\n" +
		payloadHash
	return creq, signedHeaders
}

// collapseSpaces trims a header value and collapses every internal run of
// whitespace to a single space, per the CanonicalHeaders Trim() rule.
// strings.Fields already does both: it splits on runs of whitespace and
// drops empty leading/trailing fields.
func collapseSpaces(v string) string {
	return strings.Join(strings.Fields(v), " ")
}

// canonicalQueryString URI-encodes every key and value in query (encoding
// '/' too, unlike the path rule) and returns them sorted by key, then by
// value, joined as "k=v" pairs. A key with an empty value renders as "k=".
func canonicalQueryString(query url.Values) string {
	if len(query) == 0 {
		return ""
	}

	type pair struct{ key, value string }
	pairs := make([]pair, 0, len(query))
	for k, vals := range query {
		ek := uriEncode(k, true)
		for _, v := range vals {
			pairs = append(pairs, pair{ek, uriEncode(v, true)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].key != pairs[j].key {
			return pairs[i].key < pairs[j].key
		}
		return pairs[i].value < pairs[j].value
	})

	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p.key + "=" + p.value
	}
	return strings.Join(parts, "&")
}

// uriEncode percent-encodes s byte by byte: RFC 3986 unreserved characters
// pass through unchanged, every other byte becomes %XX with uppercase hex
// digits. When encodeSlash is false, '/' also passes through unchanged,
// which is the rule for a request path; query keys and values encode '/'
// like everything else.
func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isUnreservedByte(c):
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func isUnreservedByte(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// stringToSign builds Task 2 of the signing process: the algorithm name,
// the request timestamp, the credential scope, and the hash of creq.
func stringToSign(now time.Time, scope, creq string) string {
	hash := sha256.Sum256([]byte(creq))
	return "AWS4-HMAC-SHA256\n" +
		now.UTC().Format(amzDateFormat) + "\n" +
		scope + "\n" +
		hex.EncodeToString(hash[:])
}

// scopeString is the credential scope: the date, region, and service a
// signature is bound to.
func scopeString(date, region, service string) string {
	return date + "/" + region + "/" + service + "/aws4_request"
}

// signingKey derives Task 3's signing key: secret, scoped to a date, a
// region, and a service, by four chained HMAC-SHA256 rounds.
func signingKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// signV4 signs req with SigV4 header authentication: it sets X-Amz-Date,
// X-Amz-Content-Sha256, X-Amz-Security-Token (when creds.SessionToken is
// set), and finally Authorization, then returns the signature. Production
// callers pass service = "s3"; the parameter exists because the generic
// conformance suite signs for other service names.
//
// The returned signature seeds the first chunk of a streaming body (see
// newChunkedBody) — that is the only reason it is returned rather than
// left as a side effect of setting the Authorization header.
func signV4(req *http.Request, creds Credentials, region, service, payloadHash string, now time.Time) string {
	amzDate := now.UTC().Format(amzDateFormat)
	dateStamp := now.UTC().Format(dateFormat)

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	creq, signedHeaders := canonicalRequest(req.Method, req.URL.Path, req.URL.Query(), req.Header, host, payloadHash)
	scope := scopeString(dateStamp, region, service)
	sts := stringToSign(now, scope, creq)
	key := signingKey(creds.SecretAccessKey, dateStamp, region, service)
	signature := hex.EncodeToString(hmacSHA256(key, []byte(sts)))

	req.Header.Set("Authorization", authorizationHeader(creds.AccessKeyID, scope, signedHeaders, signature))

	return signature
}

// authorizationHeader formats Task 4's Authorization header value: the
// algorithm, the credential (access key scoped to date/region/service),
// the signed header list, and the signature.
func authorizationHeader(accessKeyID, scope, signedHeaders, signature string) string {
	return fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKeyID, scope, signedHeaders, signature)
}

// chunkedReader frames a body as signed aws-chunked chunks: each chunk is
// hex(len);chunk-signature=<sig>\r\n<data>\r\n, ending with a mandatory
// zero-length final chunk. It keeps at most one framed chunk in memory and
// passes through any read error from the underlying body unchanged.
type chunkedReader struct {
	body      io.Reader
	chunkSize int
	key       []byte
	scope     string
	amzDate   string
	prevSig   string

	buf       []byte // scratch space, reused every chunk
	pending   *bytes.Reader
	bodyDone  bool
	finalSent bool
}

// newChunkedBody wraps body as an io.Reader that yields the signed
// aws-chunked framing of its bytes, chunkSize bytes at a time (the last
// data chunk may be shorter). key is the signing key for the request's
// date/region/service scope; seed is the Authorization signature signV4
// returned for the same request. The caller sets Content-Encoding:
// aws-chunked and X-Amz-Decoded-Content-Length before calling signV4 with
// streamingPayload, then wraps the body with newChunkedBody using the
// signature signV4 returned.
func newChunkedBody(body io.Reader, chunkSize int, key []byte, scope string, now time.Time, seed string) io.Reader {
	return &chunkedReader{
		body:      body,
		chunkSize: chunkSize,
		key:       key,
		scope:     scope,
		amzDate:   now.UTC().Format(amzDateFormat),
		prevSig:   seed,
		buf:       make([]byte, chunkSize),
	}
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	for c.pending == nil || c.pending.Len() == 0 {
		if c.finalSent {
			return 0, io.EOF
		}
		if err := c.fill(); err != nil {
			return 0, err
		}
	}
	return c.pending.Read(p)
}

// fill reads the next chunk of data from body (up to chunkSize bytes) and
// frames it into c.pending. A short or empty read marks bodyDone; the
// mandatory zero-length final chunk is framed either in that same call
// (an already-empty body) or in the next one, and finalSent then makes
// Read report io.EOF once it has been drained.
func (c *chunkedReader) fill() error {
	var n int
	if !c.bodyDone {
		var err error
		n, err = io.ReadFull(c.body, c.buf)
		switch {
		case err == nil:
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			c.bodyDone = true
		default:
			return err
		}
	}
	if n == 0 {
		c.finalSent = true
	}
	c.pending = bytes.NewReader(c.frame(c.buf[:n]))
	return nil
}

// frame signs data as one chunk and returns its wire bytes, advancing
// prevSig so the next chunk chains from this one.
func (c *chunkedReader) frame(data []byte) []byte {
	hash := sha256.Sum256(data)
	sts := "AWS4-HMAC-SHA256-PAYLOAD\n" +
		c.amzDate + "\n" +
		c.scope + "\n" +
		c.prevSig + "\n" +
		emptySHA256 + "\n" +
		hex.EncodeToString(hash[:])
	sig := hex.EncodeToString(hmacSHA256(c.key, []byte(sts)))
	c.prevSig = sig

	var out bytes.Buffer
	fmt.Fprintf(&out, "%x;chunk-signature=%s\r\n", len(data), sig)
	out.Write(data)
	out.WriteString("\r\n")
	return out.Bytes()
}

// chunkedLength returns the framed Content-Length for a decodedLen-byte
// body sent in chunkSize chunks: the sum of every chunk's frame overhead
// (hex length, ";chunk-signature=", a 64-character hex signature, two
// \r\n's) plus the mandatory zero-length final chunk.
func chunkedLength(decodedLen int64, chunkSize int) int64 {
	var total int64
	remaining := decodedLen
	for remaining > 0 {
		n := int64(chunkSize)
		if remaining < n {
			n = remaining
		}
		total += chunkFrameLen(n)
		remaining -= n
	}
	return total + chunkFrameLen(0)
}

func chunkFrameLen(size int64) int64 {
	const sigHexLen = sha256.Size * 2
	header := fmt.Sprintf("%x;chunk-signature=", size)
	return int64(len(header)) + sigHexLen + 2 + size + 2
}
