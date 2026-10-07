package store

import (
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"time"
)

// HookIsRunnableForTest exposes hookIsRunnable to the external test package.
func HookIsRunnableForTest(hookPath string) error {
	return hookIsRunnable(hookPath)
}

// ClassifyRenameFailureForTest exposes classifyRenameFailure to the external
// test package.
func ClassifyRenameFailureForTest(err error, repo string) error {
	return classifyRenameFailure(err, repo)
}

// InitBareConfigKeysForTest exposes the repository-config allowlist to the
// external test package, as a copy, so the drift test can compare git's
// actual output against it without being able to edit it into agreement.
func InitBareConfigKeysForTest() map[string]struct{} {
	out := make(map[string]struct{}, len(initBareConfigKeys))
	for k := range initBareConfigKeys {
		out[k] = struct{}{}
	}
	return out
}

// VouchedScopesForTest exposes the scope filter to the external test package,
// as a copy, for the same reason.
func VouchedScopesForTest() map[string]struct{} {
	out := make(map[string]struct{}, len(vouchedScopes))
	for k := range vouchedScopes {
		out[k] = struct{}{}
	}
	return out
}

// VouchProbeArgsForTest exposes the probe's arguments, so the drift test asks
// git exactly the question VouchRepoConfig asks rather than a hand-copied
// approximation of it that could drift from the one that runs.
func VouchProbeArgsForTest() []string {
	return append([]string(nil), vouchProbeArgs...)
}

// ReportableKeyForTest exposes reportableKey, so the two things it does to a
// key on its way to the wire — redacting a subsection, and bounding what is
// left without cutting a rune in half — can be driven against key names
// directly. Both are about bytes a repository's config file supplied, and
// some of those bytes are awkward to get through a real git and a real
// config file in a test.
func ReportableKeyForTest(key string) (string, bool) {
	return reportableKey(key)
}

// MaxVouchedKeyReportForTest exposes the bound, so a test states the length it
// is about once.
const MaxVouchedKeyReportForTest = maxVouchedKeyReport

// FirstUnvouchedKeyForTest exposes firstUnvouchedKey, so its framing
// assumptions can be driven directly against bytes a git version might
// produce rather than only through an exec.
func FirstUnvouchedKeyForTest(out []byte) (string, error) {
	return firstUnvouchedKey(out)
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

// NewClientForTest builds a Client with an injected http.Client (typically
// pointed at an httptest server) and clock, so a test can hold time still
// and exercise real signing and retries without touching production DNS or
// TLS trust roots.
func NewClientForTest(j *Journal, httpClient *http.Client, now func() time.Time) *Client {
	return &Client{journal: j, http: httpClient, now: now}
}

// SetBackoffForTest overrides the retry backoff's base and cap so a test's
// retries run in milliseconds instead of seconds. It returns a func that
// restores the production schedule. The schedule is package state, so
// tests using it must not run in parallel with each other.
func SetBackoffForTest(base, cap time.Duration) (restore func()) {
	prevBase, prevCap := backoffBase, backoffCap
	backoffBase, backoffCap = base, cap
	return func() { backoffBase, backoffCap = prevBase, prevCap }
}

// MaxAttemptsForTest exposes maxAttempts.
const MaxAttemptsForTest = maxAttempts

// CheckRedirectForTest calls c's underlying http.Client.CheckRedirect (as
// NewClient built it) and reports the error it returns, so a test can
// confirm production blocks redirects - http.ErrUseLastResponse - without
// following them, independent of whatever client a test injects through
// NewClientForTest.
func CheckRedirectForTest(c *Client) error {
	return c.http.CheckRedirect(nil, nil)
}

// DeleteForTest exposes delete (unexported: it exists only for the boot
// probe's own cleanup of its own key, probe.go) to the external test
// package, so client_test.go can drive its retry/idempotent behaviour
// directly rather than only indirectly through ProbeCAS.
func DeleteForTest(c *Client, ctx context.Context, key string) error {
	return c.delete(ctx, key)
}
