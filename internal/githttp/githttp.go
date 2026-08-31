// Package githttp implements git's smart HTTP protocol endpoints.
// Per ARCHITECTURE.md: "walden serves exactly three routes per repo:
// GET /{repo}/info/refs, POST /{repo}/git-upload-pack, POST /{repo}/git-receive-pack"
package githttp

import (
	"net/http"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/store"
)

// Handler serves git smart HTTP requests.
type Handler struct {
	auth  auth.Authorizer
	store *store.Store
	mux   *http.ServeMux
}

// NewHandler creates a new git HTTP handler.
func NewHandler(authorizer auth.Authorizer, repoStore *store.Store) *Handler {
	h := &Handler{
		auth:  authorizer,
		store: repoStore,
		mux:   http.NewServeMux(),
	}
	h.registerRoutes()
	return h
}

func (h *Handler) registerRoutes() {
	h.mux.HandleFunc("/", h.handleRequest)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Root/status handler or route dispatcher placeholder for smart HTTP routes
	w.WriteHeader(http.StatusOK)
}
