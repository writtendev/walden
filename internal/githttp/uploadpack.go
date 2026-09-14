package githttp

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/refusal"
)

// uploadPackContentType is the only Content-Type this endpoint accepts,
// per git's smart-HTTP protocol.
const uploadPackContentType = "application/x-git-upload-pack-request"

// isUploadPackContentType reports whether v names uploadPackContentType,
// ignoring any parameters (e.g. a charset) and case, per RFC 9110 §8.3.1.
func isUploadPackContentType(v string) bool {
	mediaType, _, err := mime.ParseMediaType(v)
	if err != nil {
		return false
	}
	return strings.EqualFold(mediaType, uploadPackContentType)
}

// requestBodyReader returns the reader handleUploadPack should treat as
// the request body: r.Body itself, or r.Body inflated through
// compress/gzip when Content-Encoding asks for it. git-http-backend
// inflates both "gzip" and "x-gzip", and git gzips small RPC request
// bodies by default, so a real clone depends on this. gzip.NewReader
// reads and validates the gzip header immediately, before any response
// header is written, so a corrupt body is reported as a clean one-line
// 400 here rather than surfacing later as a truncated 200. Any other
// Content-Encoding is refused with a one-line 415; ok reports whether
// the caller should continue, matching resolveRepoDir's convention.
func requestBodyReader(w http.ResponseWriter, r *http.Request) (io.Reader, bool) {
	switch strings.ToLower(r.Header.Get("Content-Encoding")) {
	case "", "identity":
		return r.Body, true
	case "gzip", "x-gzip":
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			writeRefusal(w, http.StatusBadRequest, refusal.FromError(
				"invalid request body",
				err,
				"send a valid gzip-encoded request body",
			))
			return nil, false
		}
		return gz, true
	default:
		writeRefusal(w, http.StatusUnsupportedMediaType, refusal.Refuse(
			"unsupported content encoding",
			fmt.Sprintf("Content-Encoding %q is not identity or gzip", r.Header.Get("Content-Encoding")),
			"send an uncompressed or gzip-encoded body",
		))
		return nil, false
	}
}

// handleUploadPack serves POST /{repo}/git-upload-pack: git's
// stateless-rpc fetch/clone endpoint. Per ARCHITECTURE.md, walden wraps
// git rather than reimplementing it — the request body goes into git's
// stdin and git's stdout comes back out verbatim, neither buffered
// whole, and no preamble is added on this route in either protocol
// version.
func (h *Handler) handleUploadPack(w http.ResponseWriter, r *http.Request) {
	repo := r.PathValue("repo")

	// required is the auth.Actions this request needs: fetch/clone only
	// ever needs read, per spec/auth/v1 §3.2. WALD-52 owns the 401
	// challenge and the actual authorization check; this is the one
	// obvious insertion point for it, placed before repository
	// resolution so that once it lands, an unauthenticated client cannot
	// use a 404 to probe which repositories exist.
	required := auth.Actions{Read: true}
	token := credentialFromRequest(r)
	if err := h.authorize(r.Context(), token, required, repo); err != nil {
		writeAuthRefusal(w, "upload-pack", repo, err)
		return
	}

	if ct := r.Header.Get("Content-Type"); !isUploadPackContentType(ct) {
		writeRefusal(w, http.StatusUnsupportedMediaType, refusal.Refuse(
			"unsupported content type",
			fmt.Sprintf("Content-Type %q is not %s", ct, uploadPackContentType),
			"send a git-upload-pack-request body",
		))
		return
	}

	reqBody, ok := requestBodyReader(w, r)
	if !ok {
		return
	}

	path, ok := h.resolveRepoDir(w, "upload-pack", repo)
	if !ok {
		return
	}

	// wantV2 mirrors inforefs.go's own negotiation: an exact match on the
	// Git-Protocol header, and what reaches the child is always the
	// allowlisted constant in gitEnv, never the raw header value. Without
	// this, a v2 client's request fails outright — git upload-pack
	// expects "0000command=..." framing under v2 and errors with
	// "expected to get object ID, not 'command=ls-refs'" if the child
	// isn't told to expect it.
	wantV2 := r.Header.Get("Git-Protocol") == "version=2"

	releaseBody := func() {
		_ = http.NewResponseController(w).SetReadDeadline(time.Now())
	}
	proc, err := startGit(r.Context(), gitEnv(wantV2), reqBody, releaseBody, "upload-pack", "--stateless-rpc", path)
	if err != nil {
		writeRefusal(w, http.StatusInternalServerError, refusal.Refuse(
			"upload-pack failed",
			"could not start the git subprocess",
			"check the server's git installation",
		))
		return
	}
	defer func() {
		if !proc.waited {
			proc.release()
			if err := proc.wait(); err != nil {
				log.Printf("githttp: upload-pack: git upload-pack %q: %v (%s)", repo, err, strings.TrimSpace(proc.stderr.String()))
			}
		}
	}()

	// Peek before writing anything: if git exits non-zero having
	// produced no output at all, nothing has reached the client yet and
	// this can still be a clean refusal instead of a half-written
	// response. Peeking cannot deadlock here: the stdin copy runs in its
	// own goroutine inside os/exec, so blocking on git's first output
	// byte blocks only this handler goroutine.
	_, peekErr := proc.stdout.Peek(1)
	if peekErr != nil {
		proc.release()
		if waitErr := proc.wait(); waitErr != nil {
			log.Printf("githttp: upload-pack: git upload-pack %q: %v (%s)", repo, waitErr, strings.TrimSpace(proc.stderr.String()))
			writeRefusal(w, http.StatusInternalServerError, refusal.Refuse(
				"upload-pack failed",
				"git exited with an error before producing any output",
				"check the server log for the underlying git error",
			))
			return
		}
		// git exited 0 with no output at all; fall through and write an
		// empty response.
	}

	w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "Fri, 01 Jan 1980 00:00:00 GMT")
	w.WriteHeader(http.StatusOK)

	var body io.Reader = bytes.NewReader(nil)
	if peekErr == nil {
		body = proc.stdout
	}

	if _, err := io.Copy(newFlushingWriter(w), body); err != nil {
		// Bytes are already on the wire; the honest move is to stop and
		// log rather than append a refusal into a half-written pack.
		// The deferred wait() above still reaps the subprocess.
		log.Printf("githttp: upload-pack: writing response for %q: %v", repo, err)
		return
	}
	if peekErr == nil {
		// git's --stateless-rpc does not read its stdin to EOF: it reads
		// the negotiation, streams the packfile, and exits. io.Copy above
		// returning nil means git's stdout hit EOF, i.e. git is done -- but
		// if the client over-declared its Content-Length, the stdin-copy
		// goroutine can still be parked reading the request body at this
		// exact moment. waitSettled bounds how long it waits for wait()
		// before unblocking the stuck body read via release().
		if err := proc.waitSettled(); err != nil {
			log.Printf("githttp: upload-pack: git upload-pack %q exited with error after streaming: %v (%s)", repo, err, strings.TrimSpace(proc.stderr.String()))
		}
	}
}
