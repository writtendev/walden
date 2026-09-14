package githttp

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"

	"github.com/writtendev/walden/internal/refusal"
	"github.com/writtendev/walden/internal/store"
)

// gitEnv returns the explicit, minimal environment for a git subprocess
// this package execs: just PATH, so git can find anything it execs
// internally, plus GIT_PROTOCOL when the caller has negotiated protocol
// v2. The value forwarded is always this package's own literal
// "GIT_PROTOCOL=version=2" — never a client's raw header value — so a
// client cannot use this to inject an arbitrary environment variable
// into the git child.
func gitEnv(wantV2 bool) []string {
	env := []string{}
	if p := os.Getenv("PATH"); p != "" {
		env = append(env, "PATH="+p)
	}
	if wantV2 {
		env = append(env, "GIT_PROTOCOL=version=2")
	}
	return env
}

// resolveRepoDir resolves repo to its bare repository directory on disk.
// On success it returns the path and true. On failure it writes a
// one-line refusal to w — mapping store.ErrStoreUnavailable to 500,
// every other RepoPath refusal to 400, a missing repository to 404, and
// any other stat error to 500 — and returns false, telling the caller to
// stop.
func (h *Handler) resolveRepoDir(w http.ResponseWriter, repo string) (string, bool) {
	path, err := h.store.RepoPath(repo)
	if err != nil {
		// store.RepoPath already distinguishes caller fault (a bad
		// identifier, or a containment escape — auth.ErrInvalidRepo or
		// store.ErrInvalidRepo) from operator fault (the data directory
		// could not be resolved — store.ErrStoreUnavailable). Map the
		// latter to 5xx and everything else to 4xx, so a misconfigured
		// server is never reported to the client as though it typed a
		// bad repository name.
		if errors.Is(err, store.ErrStoreUnavailable) {
			// The underlying error names the data directory's absolute
			// path (e.g. "lstat /private/var/.../data: no such file or
			// directory"). That belongs in the operator's log, not on
			// the wire to an unauthenticated client — PHILOSOPHY.md's
			// refusal convention is scoped to the operator, and this
			// route has no authentication in front of it yet.
			log.Printf("githttp: repo path for %q: %v", repo, err)
			writeRefusal(w, http.StatusInternalServerError, refusal.RefuseWithCause(
				"repository unavailable",
				"the server could not resolve the repository path",
				"contact the operator",
				store.ErrStoreUnavailable,
			))
			return "", false
		}
		writeRefusal(w, http.StatusBadRequest, err)
		return "", false
	}

	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeRefusal(w, http.StatusNotFound, refusal.RefuseWithCause(
				"repository not found",
				fmt.Sprintf("no repository named %q", repo),
				"check the repository identifier or create it with a push",
				store.ErrRepoNotFound,
			))
			return "", false
		}
		// As above: log the full stat error (it names the absolute
		// repository path) and send the client a fixed one-liner.
		log.Printf("githttp: stat repository path for %q: %v", repo, err)
		writeRefusal(w, http.StatusInternalServerError, refusal.RefuseWithCause(
			"repository unavailable",
			"the server could not access the repository",
			"contact the operator",
			store.ErrStoreUnavailable,
		))
		return "", false
	}

	return path, true
}
