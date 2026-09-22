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
// the fixed WWW-Authenticate challenge, ErrHookUnavailable to its own path-free 500
// (its own sentinel and its own wording, because a repository whose pre-receive hook
// is not walden's resolved its path perfectly well — saying otherwise would send an
// operator looking at the wrong thing; the distinct sentinel is also why this needs
// no marker type of the repoCreateError kind, which exists only to tell apart two
// failures wearing the same one). That wording is deliberately the one thing true of
// every ErrHookUnavailable rather than the commonest. store.EnsureHook refuses on
// five counts: git would not report which hook the repository runs (which is also
// how a repository that went away between the re-resolve and the check arrives
// here), the hook git reported is not the one walden owns, hooks/pre-receive could
// not be stat'ed at all, something that is not walden's symlink is sitting at that
// path, and the repair could not be written. "Is not walden's and could not be
// repaired" was false for more than one of those. The operator log line above
// carries store's own cause, which says which it was.
// ErrStoreUnavailable maps to a path-free 500
// (checked before the default branch, which would otherwise forward store's
// own cause — the absolute repository path — onto the wire), and any other
// unexpected error to 500 with an operator log line.
//
// writeAuthRefusal's caller is ensureRepoForPush, whose ErrStoreUnavailable can
// come from either resolving the path (store.ResolveRepo, before Authorize is
// even asked) or, for a repository that did not yet exist, creating it
// (store.CreateRepo, after Authorize succeeds: an unwritable data directory, a
// failed git init, a failed publish rename). Those are different failures and
// get different wording: a path-resolution ErrStoreUnavailable must still read
// exactly like resolveRepoDir's — info/refs, upload-pack, and receive-pack
// agree byte-for-byte on a regular file, dangling symlink, or FIFO occupying a
// repository's path (repoexistence_test.go pins this) — while a repoCreateError
// says the server failed to create the repository instead, which is what
// actually happened and is never true of the other two routes (only
// receive-pack ever creates a repository).
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
	case errors.Is(err, store.ErrHookUnavailable):
		log.Printf("githttp: %s: hook unavailable for %q: %v", route, repo, err)
		writeRefusal(w, http.StatusInternalServerError, refusal.RefuseWithCause(
			"repository hook unavailable",
			"walden could not confirm the repository's pre-receive hook is its own",
			"contact the operator",
			store.ErrHookUnavailable,
		))
	case errors.Is(err, store.ErrStoreUnavailable):
		log.Printf("githttp: %s: repository unavailable for %q: %v", route, repo, err)
		why := "the server could not resolve the repository path"
		var creationErr *repoCreateError
		if errors.As(err, &creationErr) {
			why = "the server could not create the repository"
		}
		writeRefusal(w, http.StatusInternalServerError, refusal.RefuseWithCause(
			"repository unavailable",
			why,
			"contact the operator",
			store.ErrStoreUnavailable,
		))
	default:
		log.Printf("githttp: %s: auth failure for %q: %v", route, repo, err)
		writeRefusal(w, http.StatusInternalServerError, err)
	}
}
