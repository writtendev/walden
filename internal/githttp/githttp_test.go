package githttp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/writtendev/walden/internal/githttp"
	"github.com/writtendev/walden/internal/store"
)

func TestHandlerServeHTTP(t *testing.T) {
	s := store.New(t.TempDir())
	h := githttp.NewHandler(nil, s)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}
