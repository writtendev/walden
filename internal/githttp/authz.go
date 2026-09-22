package githttp

import (
	"context"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/refusal"
	"github.com/writtendev/walden/internal/store"
)

// authChallenge is the fixed 401 challenge. The realm is a literal, not
// configuration: a configurable realm would be a sixth knob.
const authChallenge = `Basic realm="walden"`

// credentialFromRequest extracts an authentication token from r's Authorization
// header per spec/auth/v1 §6.1. It accepts Bearer <token> and Basic <b64>
// (extracting the password and ignoring any username). It never reads credentials
// from URLs or query strings. If the header is absent, it returns "". If the
// header is present but unusable (missing scheme delimiter, unknown scheme,
// malformed base64, or no colon), it logs an operator warning without quoting
// unvalidated secrets and returns "".
func credentialFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	rawHdr := r.Header.Get("Authorization")
	if rawHdr == "" {
		return ""
	}

	authHdr := strings.TrimLeft(rawHdr, " \t")
	route := requestRoute(r)
	if authHdr == "" {
		log.Printf("githttp: %s: unusable Authorization header (missing scheme delimiter)", route)
		return ""
	}

	idx := strings.IndexAny(authHdr, " \t")
	if idx < 0 {
		log.Printf("githttp: %s: unusable Authorization header (missing scheme delimiter)", route)
		return ""
	}

	scheme := authHdr[:idx]
	param := strings.TrimSpace(authHdr[idx+1:])

	if strings.EqualFold(scheme, "Bearer") {
		if param != "" {
			return param
		}
	} else if strings.EqualFold(scheme, "Basic") {
		if param != "" {
			if decoded, err := base64.StdEncoding.DecodeString(param); err == nil {
				if _, pass, ok := strings.Cut(string(decoded), ":"); ok {
					return pass
				}
			}
		}
	}

	if !isToken(scheme) {
		log.Printf("githttp: %s: unusable Authorization header (invalid scheme)", route)
		return ""
	}

	log.Printf("githttp: %s: unusable Authorization header (scheme %q)", route, scheme)
	return ""
}

// isToken reports whether s is a valid HTTP token (RFC 9110 §5.6.2) of bounded length.
func isToken(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' ||
			c == '*' || c == '+' || c == '-' || c == '.' || c == '^' || c == '_' ||
			c == '`' || c == '|' || c == '~' {
			continue
		}
		return false
	}
	return true
}

// requestRoute extracts a normalized route name ("info/refs", "upload-pack",
// "receive-pack") from r for logging.
func requestRoute(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/info/refs"):
		return "info/refs"
	case strings.HasSuffix(r.URL.Path, "/git-upload-pack"):
		return "upload-pack"
	case strings.HasSuffix(r.URL.Path, "/git-receive-pack"):
		return "receive-pack"
	default:
		return r.URL.Path
	}
}

// authorize checks whether token grants required on repo. A nil authorizer
// refuses with an operator-facing 500 refusal rather than panicking.
func (h *Handler) authorize(ctx context.Context, token string, required auth.Actions, repo string) error {
	if h.auth == nil {
		return refusal.Refuse(
			"server misconfigured",
			"authorizer is not configured",
			"contact the operator",
		)
	}
	return h.auth.Authorize(ctx, token, required, repo)
}

// writeAuthRefusal maps an authorization or repository resolution error to an
// HTTP status code and writes the single-line refusal as the response body.
// ErrRepoNotFound is mapped to 404 (checked before ErrForbidden), ErrForbidden to
// 403 (no challenge), ErrInvalidRepo to 400, auth credential errors to 401 with
// the fixed WWW-Authenticate challenge, ErrStoreUnavailable to the same
// path-free 500 resolveRepoDir writes (checked before the default branch,
// which would otherwise forward store's own cause — the absolute repository
// path — onto the wire), and any other unexpected error to 500 with an
// operator log line.
func writeAuthRefusal(w http.ResponseWriter, route, repo string, err error) {
	switch {
	case errors.Is(err, store.ErrRepoNotFound):
		writeRefusal(w, http.StatusNotFound, err)
	case errors.Is(err, auth.ErrForbidden):
		writeRefusal(w, http.StatusForbidden, err)
	case errors.Is(err, auth.ErrInvalidRepo):
		writeRefusal(w, http.StatusBadRequest, err)
	case errors.Is(err, auth.ErrUnauthorized),
		errors.Is(err, auth.ErrInvalidToken),
		errors.Is(err, auth.ErrExpired),
		errors.Is(err, auth.ErrNotYetValid),
		errors.Is(err, auth.ErrInvalidSignature):
		w.Header().Set("WWW-Authenticate", authChallenge)
		writeRefusal(w, http.StatusUnauthorized, err)
	case errors.Is(err, store.ErrStoreUnavailable):
		log.Printf("githttp: %s: repository unavailable for %q: %v", route, repo, err)
		writeRefusal(w, http.StatusInternalServerError, refusal.RefuseWithCause(
			"repository unavailable",
			"the server could not resolve the repository path",
			"contact the operator",
			store.ErrStoreUnavailable,
		))
	default:
		log.Printf("githttp: %s: auth failure for %q: %v", route, repo, err)
		writeRefusal(w, http.StatusInternalServerError, err)
	}
}
