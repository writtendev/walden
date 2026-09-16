package store

import (
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"time"
)

// ProviderHostRow is one row of the provider host table, in the shape a test
// can read. The table and its fields are unexported, so the external test
// package reaches them through this row rather than directly. There is no Go
// table anywhere else to bind it to: spec/journal/v1 section 11.2 is
// documentation, and compare-and-swap is the boot probe's business.
type ProviderHostRow struct {
	Provider string
	Suffix   string
	CAS      bool
}

// ProviderHostsForTest returns the provider host table.
func ProviderHostsForTest() []ProviderHostRow {
	rows := make([]ProviderHostRow, 0, len(providerHosts))
	for _, rule := range providerHosts {
		rows = append(rows, ProviderHostRow{Provider: rule.provider, Suffix: rule.suffix, CAS: rule.cas})
	}
	return rows
}

// HookIsRunnableForTest exposes hookIsRunnable to the external test package.
func HookIsRunnableForTest(hookPath string) error {
	return hookIsRunnable(hookPath)
}

// ClassifyRenameFailureForTest exposes classifyRenameFailure to the external
// test package.
func ClassifyRenameFailureForTest(err error, repo string) error {
	return classifyRenameFailure(err, repo)
}

// sigv4ForTest exposes the unexported SigV4 signer (WALD-19) to the
// external test package, the same way the rest of this file does for
// store.go and repo.go. None of it is part of the package's public API;
// callers outside walden have no reason to sign S3 requests themselves.

// CanonicalRequestForTest exposes canonicalRequest.
func CanonicalRequestForTest(method, path string, query url.Values, headers http.Header, host, payloadHash string) (creq, signedHeaders string) {
	return canonicalRequest(method, path, query, headers, host, payloadHash)
}

// StringToSignForTest exposes stringToSign.
func StringToSignForTest(now time.Time, scope, creq string) string {
	return stringToSign(now, scope, creq)
}

// ScopeStringForTest exposes scopeString.
func ScopeStringForTest(date, region, service string) string {
	return scopeString(date, region, service)
}

// SigningKeyForTest exposes signingKey.
func SigningKeyForTest(secret, date, region, service string) []byte {
	return signingKey(secret, date, region, service)
}

// SignV4ForTest exposes signV4.
func SignV4ForTest(req *http.Request, creds Credentials, region, service, payloadHash string, now time.Time) string {
	return signV4(req, creds, region, service, payloadHash, now)
}

// NewChunkedBodyForTest exposes newChunkedBody.
func NewChunkedBodyForTest(body io.Reader, chunkSize int, key []byte, scope string, now time.Time, seed string) io.Reader {
	return newChunkedBody(body, chunkSize, key, scope, now, seed)
}

// ChunkedLengthForTest exposes chunkedLength.
func ChunkedLengthForTest(decodedLen int64, chunkSize int) int64 {
	return chunkedLength(decodedLen, chunkSize)
}

// Payload hash constants, exposed for test tables.
const (
	UnsignedPayloadForTest  = unsignedPayload
	StreamingPayloadForTest = streamingPayload
	EmptySHA256ForTest      = emptySHA256
)

// SignatureForTest computes hex(HMAC-SHA256(key, stringToSign)), Task 3's
// final step, without going through signV4.
func SignatureForTest(key []byte, stringToSign string) string {
	return hex.EncodeToString(hmacSHA256(key, []byte(stringToSign)))
}

// AuthorizationHeaderForTest exposes authorizationHeader.
func AuthorizationHeaderForTest(accessKeyID, scope, signedHeaders, signature string) string {
	return authorizationHeader(accessKeyID, scope, signedHeaders, signature)
}

// Timestamp layouts, exposed so a test builds header values the same way
// signV4 does instead of duplicating the layout strings.
const (
	AmzDateFormatForTest = amzDateFormat
	DateFormatForTest    = dateFormat
)
