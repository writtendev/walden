// Package githttp implements git's smart HTTP protocol endpoints.
// Per ARCHITECTURE.md: "walden serves exactly three routes per repo:
// GET /{repo}/info/refs, POST /{repo}/git-upload-pack, POST /{repo}/git-receive-pack"
package githttp

import (
	"fmt"
	"net/http"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/refusal"
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
	h.mux.HandleFunc("GET /{repo}/info/refs", h.handleInfoRefs)
	// Registered without a method so it, not the "/" catch-all below,
	// answers every other method for this path: see methodNotAllowed for
	// why this can't be left to the mux's own method-mismatch handling.
	h.mux.HandleFunc("/{repo}/info/refs", methodNotAllowed("/{repo}/info/refs", "GET, HEAD"))
	h.mux.HandleFunc("POST /{repo}/git-upload-pack", h.handleUploadPack)
	h.mux.HandleFunc("/{repo}/git-upload-pack", methodNotAllowed("/{repo}/git-upload-pack", "POST"))
	h.mux.HandleFunc("/", h.handleRequest)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Root/status handler or route dispatcher placeholder for smart HTTP routes
	w.WriteHeader(http.StatusOK)
}

// methodNotAllowed returns a handler that refuses every request reaching
// it with a one-line 405 naming route, and sets Allow to allowed exactly
// as given (e.g. "GET, HEAD" or "POST").
//
// This exists because relying on net/http.ServeMux to produce that 405
// automatically doesn't hold: the mux only auto-generates one when no
// other registered pattern matches the path, and this package also
// registers a "/" catch-all (handleRequest, above) that matches every
// path regardless of method. registerRoutes binds each git route twice —
// once with its real method(s), once bound to this handler with no
// method at all — so ServeMux prefers the more specific registration for
// a supported method (including HEAD, which ServeMux routes to a
// "GET ..." registration on its own) and falls through to this one for
// everything else.
//
// RFC 9110 §15.5.6 makes the Allow header a MUST on a 405: it must name
// the target resource's currently supported methods. For a route
// registered as "GET ...", that list is "GET, HEAD" rather than just
// "GET" — ServeMux's GET-also-matches-HEAD rule means a HEAD request is
// genuinely supported here even though this handler never sees it, and
// naming only GET would tell the exact audience Allow exists for
// (proxies, scanners, cache revalidation) that HEAD is unsupported,
// which can turn a cheap conditional HEAD into a full GET on their end.
func methodNotAllowed(route, allowed string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", allowed)
		writeRefusal(w, http.StatusMethodNotAllowed, refusal.Refuse(
			"method not allowed",
			fmt.Sprintf("%s is not supported for %s", r.Method, route),
			fmt.Sprintf("use %s", allowed),
		))
	}
}
