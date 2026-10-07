package githttp_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/githttp"
	"github.com/writtendev/walden/internal/store"
)

func TestHandlerServeHTTPJournalLess(t *testing.T) {
	s := store.New(t.TempDir())
	h := githttp.NewHandler(nil, s, "")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("expected Content-Type text/plain; charset=utf-8, got %q", ct)
	}
	wantBody := githttp.JournalLessWarning + "\n"
	if rec.Body.String() != wantBody {
		t.Errorf("expected body %q, got %q", wantBody, rec.Body.String())
	}
}

func TestHandlerServeHTTPConfiguredJournal(t *testing.T) {
	s := store.New(t.TempDir())
	h := githttp.NewHandler(nil, s, "s3://bucket/prefix")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("expected Content-Type text/plain; charset=utf-8, got %q", ct)
	}
	if strings.Contains(rec.Body.String(), "journal-less mode") {
		t.Errorf("expected no journal-less warning when journal is configured, got %q", rec.Body.String())
	}
}

func TestHandlerServeHTTPHead(t *testing.T) {
	s := store.New(t.TempDir())
	h := githttp.NewHandler(nil, s, "")

	req := httptest.NewRequest(http.MethodHead, "/", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("expected empty body for HEAD /, got %q", rec.Body.String())
	}
}

func TestHandlerServeHTTPMethodNotAllowed(t *testing.T) {
	s := store.New(t.TempDir())
	h := githttp.NewHandler(nil, s, "")

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != "GET, HEAD" {
		t.Errorf("expected Allow 'GET, HEAD', got %q", allow)
	}
	body := strings.TrimRight(rec.Body.String(), "\n")
	if !strings.Contains(body, "method not allowed") {
		t.Errorf("expected refusal mentioning 'method not allowed', got %q", body)
	}
	if strings.Contains(body, "\n") {
		t.Errorf("refusal is not a single line: %q", body)
	}
}

func TestHandlerServeHTTPNotFound(t *testing.T) {
	s := store.New(t.TempDir())
	h := githttp.NewHandler(nil, s, "")

	req := httptest.NewRequest(http.MethodGet, "/unknown", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, rec.Code)
	}
	body := strings.TrimRight(rec.Body.String(), "\n")
	if !strings.Contains(body, "not found") {
		t.Errorf("expected refusal mentioning 'not found', got %q", body)
	}
	if strings.Contains(body, "\n") {
		t.Errorf("refusal is not a single line: %q", body)
	}
}
