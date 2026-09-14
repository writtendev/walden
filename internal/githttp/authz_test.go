package githttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/refusal"
	"github.com/writtendev/walden/internal/store"
)

func TestCredentialFromRequest(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		path       string
		wantToken  string
		wantLog    string
	}{
		{
			name:       "absent header",
			authHeader: "",
			path:       "/repo/info/refs",
			wantToken:  "",
			wantLog:    "",
		},
		{
			name:       "bearer standard",
			authHeader: "Bearer test_bearer_token",
			path:       "/repo/info/refs",
			wantToken:  "test_bearer_token",
			wantLog:    "",
		},
		{
			name:       "bearer mixed case",
			authHeader: "bEaReR test_mixed_token",
			path:       "/repo/git-upload-pack",
			wantToken:  "test_mixed_token",
			wantLog:    "",
		},
		{
			name:       "basic standard walden username",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("walden:test_basic_token")),
			path:       "/repo/git-receive-pack",
			wantToken:  "test_basic_token",
			wantLog:    "",
		},
		{
			name:       "basic custom username ignored",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("anyuser:test_custom_token")),
			path:       "/repo/info/refs",
			wantToken:  "test_custom_token",
			wantLog:    "",
		},
		{
			name:       "basic password containing colons",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("walden:token:with:colons")),
			path:       "/repo/git-upload-pack",
			wantToken:  "token:with:colons",
			wantLog:    "",
		},
		{
			name:       "basic invalid base64",
			authHeader: "Basic not_valid_base64!!!",
			path:       "/repo/info/refs",
			wantToken:  "",
			wantLog:    `githttp: info/refs: unusable Authorization header (scheme "Basic")`,
		},
		{
			name:       "basic missing colon",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("no_colon_in_payload")),
			path:       "/repo/git-upload-pack",
			wantToken:  "",
			wantLog:    `githttp: upload-pack: unusable Authorization header (scheme "Basic")`,
		},
		{
			name:       "unsupported scheme negotiate",
			authHeader: "Negotiate some_token_blob",
			path:       "/repo/git-receive-pack",
			wantToken:  "",
			wantLog:    `githttp: receive-pack: unusable Authorization header (scheme "Negotiate")`,
		},
		{
			name:       "bearer empty parameter",
			authHeader: "Bearer ",
			path:       "/repo/info/refs",
			wantToken:  "",
			wantLog:    `githttp: info/refs: unusable Authorization header (scheme "Bearer")`,
		},
		{
			name:       "basic empty parameter",
			authHeader: "Basic ",
			path:       "/repo/info/refs",
			wantToken:  "",
			wantLog:    `githttp: info/refs: unusable Authorization header (scheme "Basic")`,
		},
		{
			name:       "bare token without delimiter",
			authHeader: "bare_token_value",
			path:       "/repo/info/refs",
			wantToken:  "",
			wantLog:    `githttp: info/refs: unusable Authorization header (missing scheme delimiter)`,
		},
		{
			name:       "bare token with leading whitespace",
			authHeader: "   bare_token_value",
			path:       "/repo/git-upload-pack",
			wantToken:  "",
			wantLog:    `githttp: upload-pack: unusable Authorization header (missing scheme delimiter)`,
		},
		{
			name:       "whitespace only header",
			authHeader: "   \t  ",
			path:       "/repo/git-upload-pack",
			wantToken:  "",
			wantLog:    `githttp: upload-pack: unusable Authorization header (missing scheme delimiter)`,
		},
		{
			name:       "bearer tab separated",
			authHeader: "Bearer\ttest_tab_token",
			path:       "/repo/info/refs",
			wantToken:  "test_tab_token",
			wantLog:    "",
		},
		{
			name:       "basic tab separated",
			authHeader: "Basic\t" + base64.StdEncoding.EncodeToString([]byte("walden:test_tab_basic")),
			path:       "/repo/git-receive-pack",
			wantToken:  "test_tab_basic",
			wantLog:    "",
		},
		{
			name:       "invalid scheme characters",
			authHeader: "invalid@scheme param",
			path:       "/repo/info/refs",
			wantToken:  "",
			wantLog:    `githttp: info/refs: unusable Authorization header (invalid scheme)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			prevOutput := log.Writer()
			prevFlags := log.Flags()
			log.SetOutput(&logBuf)
			log.SetFlags(0)
			defer func() {
				log.SetOutput(prevOutput)
				log.SetFlags(prevFlags)
			}()

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			gotToken := credentialFromRequest(req)
			if gotToken != tt.wantToken {
				t.Errorf("credentialFromRequest() = %q, want %q", gotToken, tt.wantToken)
			}

			gotLog := strings.TrimSpace(logBuf.String())
			if tt.wantLog == "" {
				if gotLog != "" {
					t.Errorf("unexpected log output: %q", gotLog)
				}
			} else {
				if !strings.Contains(gotLog, tt.wantLog) {
					t.Errorf("log %q does not contain expected %q", gotLog, tt.wantLog)
				}
			}
		})
	}
}

func TestWriteAuthRefusal(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		wantStatus    int
		wantChallenge bool
		wantLog       bool
	}{
		{
			name: "ErrRepoNotFound mapped to 404",
			err: refusal.RefuseWithCause(
				"repository not found",
				"repository 'newrepo' does not exist and token lacks create scope 'c'",
				"request create scope 'c' or push to an existing repository",
				store.ErrRepoNotFound,
			),
			wantStatus:    http.StatusNotFound,
			wantChallenge: false,
			wantLog:       false,
		},
		{
			name: "ErrForbidden mapped to 403 without challenge",
			err: refusal.RefuseWithCause(
				"forbidden",
				"token does not grant action 'write' on repository 'repo'",
				"request scope 'w:repo'",
				auth.ErrForbidden,
			),
			wantStatus:    http.StatusForbidden,
			wantChallenge: false,
			wantLog:       false,
		},
		{
			name: "ErrInvalidRepo mapped to 400",
			err: refusal.RefuseWithCause(
				"invalid repository identifier",
				"contains uppercase letters",
				"use lowercase letters, digits, '-', or '_'",
				auth.ErrInvalidRepo,
			),
			wantStatus:    http.StatusBadRequest,
			wantChallenge: false,
			wantLog:       false,
		},
		{
			name: "ErrUnauthorized mapped to 401 with challenge",
			err: refusal.RefuseWithCause(
				"unauthorized",
				"missing authentication token",
				"provide token via Bearer header or HTTP Basic auth",
				auth.ErrUnauthorized,
			),
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: true,
			wantLog:       false,
		},
		{
			name: "ErrInvalidToken mapped to 401 with challenge",
			err: refusal.RefuseWithCause(
				"invalid capability",
				"malformed compact token structure",
				"expected format 'v1.<payload>.<sig>'",
				auth.ErrInvalidToken,
			),
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: true,
			wantLog:       false,
		},
		{
			name: "ErrExpired mapped to 401 with challenge",
			err: refusal.RefuseWithCause(
				"capability expired",
				"token expired at 2026-09-01T12:00:00Z",
				"request a fresh token from the issuer",
				auth.ErrExpired,
			),
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: true,
			wantLog:       false,
		},
		{
			name: "ErrNotYetValid mapped to 401 with challenge",
			err: refusal.RefuseWithCause(
				"capability not yet valid",
				"token is not valid until 2026-09-01T12:00:00Z",
				"wait until token activation time",
				auth.ErrNotYetValid,
			),
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: true,
			wantLog:       false,
		},
		{
			name: "ErrInvalidSignature mapped to 401 with challenge",
			err: refusal.RefuseWithCause(
				"invalid signature",
				"capability signature verification failed",
				"verify token was signed with the trusted WALDEN_AUTH_TRUST key",
				auth.ErrInvalidSignature,
			),
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: true,
			wantLog:       false,
		},
		{
			name: "ErrStoreUnavailable mapped to 500 with log",
			err: refusal.RefuseWithCause(
				"token store unavailable",
				"file unreadable",
				"contact operator",
				auth.ErrStoreUnavailable,
			),
			wantStatus:    http.StatusInternalServerError,
			wantChallenge: false,
			wantLog:       true,
		},
		{
			name:          "unrecognized error mapped to 500 with log",
			err:           errors.New("unexpected database error"),
			wantStatus:    http.StatusInternalServerError,
			wantChallenge: false,
			wantLog:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			prevOutput := log.Writer()
			prevFlags := log.Flags()
			log.SetOutput(&logBuf)
			log.SetFlags(0)
			defer func() {
				log.SetOutput(prevOutput)
				log.SetFlags(prevFlags)
			}()

			rec := httptest.NewRecorder()
			writeAuthRefusal(rec, "upload-pack", "testrepo", tt.err)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			challenge := rec.Header().Get("WWW-Authenticate")
			if tt.wantChallenge {
				if challenge != authChallenge {
					t.Errorf("WWW-Authenticate = %q, want %q", challenge, authChallenge)
				}
			} else {
				if challenge != "" {
					t.Errorf("unexpected WWW-Authenticate header: %q", challenge)
				}
			}

			body := strings.TrimRight(rec.Body.String(), "\n")
			if body != tt.err.Error() {
				t.Errorf("body = %q, want %q", body, tt.err.Error())
			}
			if strings.Contains(body, "\n") {
				t.Errorf("refusal body is not a single line: %q", body)
			}

			logStr := strings.TrimSpace(logBuf.String())
			if tt.wantLog {
				if logStr == "" {
					t.Errorf("expected operator log line for status %d, got none", tt.wantStatus)
				}
				if !strings.Contains(logStr, "githttp: upload-pack: auth failure for \"testrepo\":") {
					t.Errorf("log %q does not contain expected prefix", logStr)
				}
			} else {
				if logStr != "" {
					t.Errorf("unexpected log output: %q", logStr)
				}
			}
		})
	}
}

func TestNilAuthorizerRefusesWith500(t *testing.T) {
	s := store.New(t.TempDir())
	h := NewHandler(nil, s, "")

	routes := []struct {
		method      string
		path        string
		contentType string
	}{
		{http.MethodGet, "/repo/info/refs?service=git-upload-pack", ""},
		{http.MethodPost, "/repo/git-upload-pack", "application/x-git-upload-pack-request"},
		{http.MethodPost, "/repo/git-receive-pack", "application/x-git-receive-pack-request"},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, nil)
			req.Header.Set("Authorization", "Bearer dummy_token")
			if route.contentType != "" {
				req.Header.Set("Content-Type", route.contentType)
			}
			rec := httptest.NewRecorder()

			// Must not panic!
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
			}
			body := strings.TrimRight(rec.Body.String(), "\n")
			if !strings.Contains(body, "server misconfigured") {
				t.Errorf("body %q does not contain 'server misconfigured'", body)
			}
			if strings.Contains(body, "\n") {
				t.Errorf("body is not a single line: %q", body)
			}
		})
	}

	// Also test ensureRepoForPush directly with nil authorizer.
	_, err := h.ensureRepoForPush(context.Background(), "dummy_token", "repo")
	if err == nil {
		t.Fatal("ensureRepoForPush with nil authorizer = nil, want error")
	}
	if !strings.Contains(err.Error(), "server misconfigured") {
		t.Errorf("error %q does not contain 'server misconfigured'", err.Error())
	}
}
