// No t.Parallel anywhere in this file: the standard logger is process-global.
package githttp_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/githttp"
	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/store"
)

func scanForSecrets(blob string, secrets []string) (string, bool) {
	for _, s := range secrets {
		if s != "" && strings.Contains(blob, s) {
			return s, true
		}
	}
	return "", false
}

func TestSecretsScannerSelfTest(t *testing.T) {
	const canary = "walden_CANARY_5f3a9c2e1b7d48a6"
	canaryHash := auth.HashToken(canary)
	canaryHashTail := strings.TrimPrefix(canaryHash, "sha256:")
	canaryBasic := base64.StdEncoding.EncodeToString([]byte("walden:" + canary))

	priv, _, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	now := time.Now().UTC()
	capToken, err := auth.SignCapability(priv, &auth.CapabilityPayload{
		Version:   "v1",
		ID:        "cap_" + canary,
		Subject:   "sub_" + canary,
		Scopes:    []string{"rw:repo"},
		IssuedAt:  now.Format(time.RFC3339),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("SignCapability: %v", err)
	}
	capParts := strings.Split(capToken, ".")

	secrets := []string{
		canary,
		canaryHash,
		canaryHashTail,
		canaryBasic,
		capToken,
		capParts[0],
		capParts[1],
		capParts[2],
	}

	for _, s := range secrets {
		synthetic := fmt.Sprintf("header: foo\nbody: contains %s inside\nlog: trace", s)
		leaked, found := scanForSecrets(synthetic, secrets)
		if !found {
			t.Errorf("scanner failed to find secret %q in synthetic blob", s)
		}
		if leaked != s && !strings.Contains(s, leaked) && !strings.Contains(leaked, s) {
			t.Errorf("scanner found %q, want %q", leaked, s)
		}
	}

	clean := "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Basic realm=\"walden\"\nContent-Type: text/plain\n\nunauthorized: missing authentication token"
	if leaked, found := scanForSecrets(clean, secrets); found {
		t.Errorf("scanner false positive on clean blob: detected %q", leaked)
	}
}

func TestNoSecretInOutputGrid(t *testing.T) {
	const canary = "walden_CANARY_5f3a9c2e1b7d48a6"
	canaryHash := auth.HashToken(canary)
	canaryHashTail := strings.TrimPrefix(canaryHash, "sha256:")
	canaryBasic := base64.StdEncoding.EncodeToString([]byte("walden:" + canary))

	priv, pub, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	wrongPriv, _, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair (wrong): %v", err)
	}

	now := time.Now().UTC()
	expiredCap, err := auth.SignCapability(priv, &auth.CapabilityPayload{
		Version:   "v1",
		ID:        "cap_exp_" + canary,
		Subject:   "sub_exp_" + canary,
		Scopes:    []string{"rw:repo"},
		IssuedAt:  now.Add(-2 * time.Hour).Format(time.RFC3339),
		ExpiresAt: now.Add(-time.Hour).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("SignCapability (expired): %v", err)
	}

	wrongKeyCap, err := auth.SignCapability(wrongPriv, &auth.CapabilityPayload{
		Version:   "v1",
		ID:        "cap_wrong_" + canary,
		Subject:   "sub_wrong_" + canary,
		Scopes:    []string{"rw:repo"},
		IssuedAt:  now.Format(time.RFC3339),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("SignCapability (wrong key): %v", err)
	}

	validDelegatedCap, err := auth.SignCapability(priv, &auth.CapabilityPayload{
		Version:   "v1",
		ID:        "cap_valid_" + canary,
		Subject:   "sub_valid_" + canary,
		Scopes:    []string{"rwc:*"},
		IssuedAt:  now.Format(time.RFC3339),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("SignCapability (valid): %v", err)
	}

	expiredParts := strings.Split(expiredCap, ".")
	wrongParts := strings.Split(wrongKeyCap, ".")
	validParts := strings.Split(validDelegatedCap, ".")

	allSecrets := []string{
		canary,
		canaryHash,
		canaryHashTail,
		canaryBasic,
		expiredCap,
		expiredParts[1],
		expiredParts[2],
		wrongKeyCap,
		wrongParts[1],
		wrongParts[2],
		validDelegatedCap,
		validParts[1],
		validParts[2],
	}

	routes := []struct {
		name        string
		method      string
		path        string
		contentType string
		body        string
		is405       bool
		isCatchAll  bool
	}{
		{
			name:   "info/refs upload-pack",
			method: http.MethodGet,
			path:   "/repo/info/refs?service=git-upload-pack",
		},
		{
			name:   "info/refs receive-pack",
			method: http.MethodGet,
			path:   "/repo/info/refs?service=git-receive-pack",
		},
		{
			name:        "git-upload-pack",
			method:      http.MethodPost,
			path:        "/repo/git-upload-pack",
			contentType: "application/x-git-upload-pack-request",
			body:        "0000",
		},
		{
			name:        "git-receive-pack",
			method:      http.MethodPost,
			path:        "/repo/git-receive-pack",
			contentType: "application/x-git-receive-pack-request",
			body:        "0000",
		},
		{
			name:   "405 info/refs POST",
			method: http.MethodPost,
			path:   "/repo/info/refs",
			is405:  true,
		},
		{
			name:   "405 git-upload-pack GET",
			method: http.MethodGet,
			path:   "/repo/git-upload-pack",
			is405:  true,
		},
		{
			name:   "405 git-receive-pack GET",
			method: http.MethodGet,
			path:   "/repo/git-receive-pack",
			is405:  true,
		},
		{
			name:       "catch-all root GET",
			method:     http.MethodGet,
			path:       "/",
			isCatchAll: true,
		},
	}

	type credShape struct {
		name       string
		authHeader string
		authorizer func(t *testing.T) auth.Authorizer
		targetRepo string
		wantStatus int
		wantSubstr string
		wantLog    string
	}

	credShapes := []credShape{
		{
			name:       "no header",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
			wantSubstr: "unauthorized:",
		},
		{
			name:       "bearer unknown canary",
			authHeader: "Bearer " + canary,
			wantStatus: http.StatusUnauthorized,
			wantSubstr: "unauthorized:",
		},
		{
			name:       "basic unknown canary",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte("walden:"+canary)),
			wantStatus: http.StatusUnauthorized,
			wantSubstr: "unauthorized:",
		},
		{
			name:       "canary in username position",
			authHeader: "Basic " + base64.StdEncoding.EncodeToString([]byte(canary+":")),
			wantStatus: http.StatusUnauthorized,
			wantSubstr: "unauthorized:",
		},
		{
			name:       "basic invalid base64 with canary",
			authHeader: "Basic not_valid_b64_" + canary + "_end",
			wantStatus: http.StatusUnauthorized,
			wantSubstr: "unauthorized:",
			wantLog:    `unusable Authorization header (scheme "Basic")`,
		},
		{
			name:       "unsupported scheme negotiate",
			authHeader: "Negotiate " + canary,
			wantStatus: http.StatusUnauthorized,
			wantSubstr: "unauthorized:",
			wantLog:    `unusable Authorization header (scheme "Negotiate")`,
		},
		{
			name:       "bare token without scheme",
			authHeader: canary,
			wantStatus: http.StatusUnauthorized,
			wantSubstr: "unauthorized:",
			wantLog:    "unusable Authorization header (missing scheme delimiter)",
		},
		{
			name:       "bearer tab separated canary",
			authHeader: "Bearer\t" + canary,
			wantStatus: http.StatusUnauthorized,
			wantSubstr: "unauthorized:",
		},
		{
			name:       "basic tab separated canary",
			authHeader: "Basic\t" + base64.StdEncoding.EncodeToString([]byte("walden:"+canary)),
			wantStatus: http.StatusUnauthorized,
			wantSubstr: "unauthorized:",
		},
		{
			name:       "known canary token with scope r:other-repo",
			authHeader: "Bearer " + canary,
			authorizer: func(t *testing.T) auth.Authorizer {
				t.Helper()
				scopes, err := auth.ParseScopes([]string{"r:other-repo"})
				if err != nil {
					t.Fatalf("ParseScopes: %v", err)
				}
				s := auth.NewMemoryTokenStore()
				if err := s.CreateToken(context.Background(), &auth.TokenRecord{
					TokenID:   "tok_other",
					TokenHash: auth.HashToken(canary),
					Scopes:    scopes,
					CreatedAt: time.Now().UTC(),
				}); err != nil {
					t.Fatalf("CreateToken: %v", err)
				}
				return auth.NewBuiltinAuthorizer(s)
			},
			wantStatus: http.StatusForbidden,
			wantSubstr: "forbidden:",
		},
		{
			name:       "revoked canary token",
			authHeader: "Bearer " + canary,
			authorizer: func(t *testing.T) auth.Authorizer {
				t.Helper()
				scopes, err := auth.ParseScopes([]string{"rwc:*"})
				if err != nil {
					t.Fatalf("ParseScopes: %v", err)
				}
				s := auth.NewMemoryTokenStore()
				if err := s.CreateToken(context.Background(), &auth.TokenRecord{
					TokenID:   "tok_revoked",
					TokenHash: auth.HashToken(canary),
					Scopes:    scopes,
					CreatedAt: time.Now().UTC(),
					Revoked:   true,
				}); err != nil {
					t.Fatalf("CreateToken: %v", err)
				}
				return auth.NewBuiltinAuthorizer(s)
			},
			wantStatus: http.StatusUnauthorized,
			wantSubstr: "unauthorized:",
		},
		{
			name:       "delegated-mode expired capability",
			authHeader: "Bearer " + expiredCap,
			authorizer: func(t *testing.T) auth.Authorizer {
				return auth.NewDelegatedAuthorizer(pub)
			},
			wantStatus: http.StatusUnauthorized,
			wantSubstr: "capability expired",
		},
		{
			name:       "delegated-mode wrong key",
			authHeader: "Bearer " + wrongKeyCap,
			authorizer: func(t *testing.T) auth.Authorizer {
				return auth.NewDelegatedAuthorizer(pub)
			},
			wantStatus: http.StatusUnauthorized,
			wantSubstr: "invalid signature",
		},
		{
			name:       "rw:* to missing repo",
			authHeader: "Bearer " + canary,
			targetRepo: "missingrepo",
			authorizer: func(t *testing.T) auth.Authorizer {
				t.Helper()
				scopes, err := auth.ParseScopes([]string{"rw:*"})
				if err != nil {
					t.Fatalf("ParseScopes: %v", err)
				}
				s := auth.NewMemoryTokenStore()
				if err := s.CreateToken(context.Background(), &auth.TokenRecord{
					TokenID:   "tok_rw",
					TokenHash: auth.HashToken(canary),
					Scopes:    scopes,
					CreatedAt: time.Now().UTC(),
				}); err != nil {
					t.Fatalf("CreateToken: %v", err)
				}
				return auth.NewBuiltinAuthorizer(s)
			},
			wantStatus: http.StatusNotFound,
			wantSubstr: "repository not found:",
		},
	}

	for _, route := range routes {
		for _, shape := range credShapes {
			caseName := fmt.Sprintf("%s / %s", route.name, shape.name)
			t.Run(caseName, func(t *testing.T) {
				var logBuf bytes.Buffer
				prevOutput := log.Writer()
				prevFlags := log.Flags()
				log.SetOutput(&logBuf)
				log.SetFlags(0)
				defer func() {
					log.SetOutput(prevOutput)
					log.SetFlags(prevFlags)
				}()

				repoDir := t.TempDir()
				s := store.New(repoDir)
				repoName := "repo"
				if shape.targetRepo != "" {
					repoName = shape.targetRepo
				}
				// Create the repo unless testing missing repo
				if shape.targetRepo == "" {
					newBareRepoWithCommit(t, s, repoName)
				}

				var authorizer auth.Authorizer
				if shape.authorizer != nil {
					authorizer = shape.authorizer(t)
				} else {
					authorizer, _ = newTestAuthorizer(t, "rwc:*")
				}

				h := githttp.NewHandler(authorizer, s, "")

				reqPath := route.path
				if shape.targetRepo != "" {
					reqPath = strings.Replace(reqPath, "/repo/", "/"+shape.targetRepo+"/", 1)
				}

				var bodyReader *strings.Reader
				if route.body != "" {
					bodyReader = strings.NewReader(route.body)
				} else {
					bodyReader = strings.NewReader("")
				}

				req := httptest.NewRequest(route.method, reqPath, bodyReader)
				if route.contentType != "" {
					req.Header.Set("Content-Type", route.contentType)
				}
				if shape.authHeader != "" {
					req.Header.Set("Authorization", shape.authHeader)
				}

				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)

				// Determine expected status and substring: 405 and catch-all override credential shape
				expectedStatus := shape.wantStatus
				expectedSubstr := shape.wantSubstr
				if route.is405 {
					expectedStatus = http.StatusMethodNotAllowed
					expectedSubstr = "method not allowed:"
				} else if route.isCatchAll {
					expectedStatus = http.StatusOK
					expectedSubstr = ""
				}

				// 1. Assert status and required refusal substring first
				if rec.Code != expectedStatus {
					t.Fatalf("status = %d, want %d; body: %s", rec.Code, expectedStatus, rec.Body.String())
				}
				if expectedSubstr != "" && !strings.Contains(rec.Body.String(), expectedSubstr) {
					t.Fatalf("body %q does not contain required refusal substring %q", rec.Body.String(), expectedSubstr)
				}

				// If 401, assert WWW-Authenticate matches fixed constant exactly
				if rec.Code == http.StatusUnauthorized {
					if authHdr := rec.Header().Get("WWW-Authenticate"); authHdr != githttp.AuthChallenge {
						t.Errorf("WWW-Authenticate = %q, want %q", authHdr, githttp.AuthChallenge)
					}
				}

				// Build captured output blob
				var captured strings.Builder
				captured.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\n", rec.Code, http.StatusText(rec.Code)))
				for k, vv := range rec.Header() {
					for _, v := range vv {
						captured.WriteString(fmt.Sprintf("%s: %s\n", k, v))
					}
				}
				captured.WriteString(rec.Body.String())
				captured.WriteString("\nLOG:\n")
				captured.WriteString(logBuf.String())
				capturedBlob := captured.String()

				// 2. Assert captured blob is non-empty
				if len(capturedBlob) == 0 {
					t.Fatal("captured blob is empty")
				}

				// Assert single-line refusal on error responses
				if rec.Code >= 400 {
					trimmedBody := strings.TrimRight(rec.Body.String(), "\n")
					if strings.Contains(trimmedBody, "\n") {
						t.Errorf("refusal body contains embedded newline: %q", trimmedBody)
					}
				}

				// 3. If unusable-header log is expected, assert log blob contains it
				if shape.wantLog != "" && !route.is405 && !route.isCatchAll {
					if !strings.Contains(logBuf.String(), shape.wantLog) {
						t.Errorf("log %q does not contain %q", logBuf.String(), shape.wantLog)
					}
				}

				// 4. Assert no secret or derived form appears in captured output
				if leaked, found := scanForSecrets(capturedBlob, allSecrets); found {
					t.Fatalf("secret leak detected: found %q in captured output:\n%s", leaked, capturedBlob)
				}
			})
		}
	}

	// Positive control 1: 200 success case
	t.Run("positive-control-200-success", func(t *testing.T) {
		var logBuf bytes.Buffer
		prevOutput := log.Writer()
		prevFlags := log.Flags()
		log.SetOutput(&logBuf)
		log.SetFlags(0)
		defer func() {
			log.SetOutput(prevOutput)
			log.SetFlags(prevFlags)
		}()

		s := store.New(t.TempDir())
		newBareRepoWithCommit(t, s, "repo")
		authorizer, tok := newTestAuthorizer(t, "rwc:*")
		h := githttp.NewHandler(authorizer, s, "")

		req := httptest.NewRequest(http.MethodGet, "/repo/info/refs?service=git-upload-pack", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}

		var captured strings.Builder
		captured.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\n", rec.Code, http.StatusText(rec.Code)))
		for k, vv := range rec.Header() {
			for _, v := range vv {
				captured.WriteString(fmt.Sprintf("%s: %s\n", k, v))
			}
		}
		captured.WriteString(rec.Body.String())
		captured.WriteString("\nLOG:\n")
		captured.WriteString(logBuf.String())
		capturedBlob := captured.String()

		controlSecrets := []string{
			tok,
			auth.HashToken(tok),
			strings.TrimPrefix(auth.HashToken(tok), "sha256:"),
			base64.StdEncoding.EncodeToString([]byte("walden:" + tok)),
		}
		if leaked, found := scanForSecrets(capturedBlob, controlSecrets); found {
			t.Fatalf("secret leak detected in 200 response: found %q in:\n%s", leaked, capturedBlob)
		}
	})

	// Positive control 2: operator-fault 500
	t.Run("positive-control-500-unresolvable-datadir", func(t *testing.T) {
		var logBuf bytes.Buffer
		prevOutput := log.Writer()
		prevFlags := log.Flags()
		log.SetOutput(&logBuf)
		log.SetFlags(0)
		defer func() {
			log.SetOutput(prevOutput)
			log.SetFlags(prevFlags)
		}()

		badStore := store.New(filepath.Join(t.TempDir(), "does-not-exist"))
		authorizer, tok := newTestAuthorizer(t, "rwc:*")
		h := githttp.NewHandler(authorizer, badStore, "")

		req := httptest.NewRequest(http.MethodGet, "/repo/info/refs?service=git-upload-pack", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
		}
		if !strings.Contains(rec.Body.String(), "repository unavailable:") {
			t.Fatalf("body %q does not contain 'repository unavailable:'", rec.Body.String())
		}
		if logBuf.Len() == 0 {
			t.Fatal("500 operator-fault case produced no log output")
		}

		var captured strings.Builder
		captured.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\n", rec.Code, http.StatusText(rec.Code)))
		for k, vv := range rec.Header() {
			for _, v := range vv {
				captured.WriteString(fmt.Sprintf("%s: %s\n", k, v))
			}
		}
		captured.WriteString(rec.Body.String())
		captured.WriteString("\nLOG:\n")
		captured.WriteString(logBuf.String())
		capturedBlob := captured.String()

		controlSecrets := []string{
			tok,
			auth.HashToken(tok),
			strings.TrimPrefix(auth.HashToken(tok), "sha256:"),
			base64.StdEncoding.EncodeToString([]byte("walden:" + tok)),
		}
		if leaked, found := scanForSecrets(capturedBlob, controlSecrets); found {
			t.Fatalf("secret leak detected in 500 response: found %q in:\n%s", leaked, capturedBlob)
		}
	})
}

func TestChallengeAcceptedByGitCredentialHelper(t *testing.T) {
	s := store.New(t.TempDir())
	wantSHA := newBareRepoWithCommit(t, s, "repo")

	authorizer, tok := newTestAuthorizer(t, "rwc:*")
	server := httptest.NewServer(githttp.NewHandler(authorizer, s, ""))
	defer server.Close()

	markerFile := filepath.Join(t.TempDir(), "helper_marker")
	// The credential helper touches markerFile and prints username and password on stdout.
	helperScript := fmt.Sprintf("!f() { touch %q; echo username=walden; echo password=%s; }; f", markerFile, tok)

	dest := filepath.Join(t.TempDir(), "clone")
	cmd := exec.Command("git", "-c", "credential.helper=", "-c", "credential.helper="+helperScript, "clone", "-q", server.URL+"/repo", dest)
	cmd.Dir = t.TempDir()
	cmd.Env = gitClientEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git clone failed: %v\n%s", err, out)
	}

	// Assert the helper wrote the marker file, proving the credentials came from the challenge
	if _, err := os.Stat(markerFile); err != nil {
		t.Fatalf("marker file was not created by credential helper: %v", err)
	}

	gotSHA := strings.TrimSpace(runGit(t, dest, "rev-parse", "HEAD"))
	if gotSHA != wantSHA {
		t.Errorf("cloned HEAD = %q, want %q", gotSHA, wantSHA)
	}

	// Negative control: wrong token must fail as an auth failure.
	wrongMarkerFile := filepath.Join(t.TempDir(), "wrong_marker")
	wrongHelperScript := fmt.Sprintf("!f() { touch %q; echo username=walden; echo password=wrong_token; }; f", wrongMarkerFile)

	destBad := filepath.Join(t.TempDir(), "clone_bad")
	cmdBad := exec.Command("git", "-c", "credential.helper=", "-c", "credential.helper="+wrongHelperScript, "clone", "-q", server.URL+"/repo", destBad)
	cmdBad.Dir = t.TempDir()
	cmdBad.Env = gitClientEnv()
	outBad, errBad := cmdBad.CombinedOutput()
	if errBad == nil {
		t.Fatalf("git clone with wrong token succeeded, want error; output: %q", outBad)
	}
	if _, err := os.Stat(wrongMarkerFile); err != nil {
		t.Fatalf("wrong marker file was not created by credential helper: %v", err)
	}
}
