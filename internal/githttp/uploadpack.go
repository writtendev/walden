package githttp

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/refusal"
)

// uploadPackWaitDelay bounds how long cmd.Wait may block after git's own
// exit and pipe closures have otherwise settled. Cancelling the request
// context kills the child, but killing is not reaping: the stdin-copy
// goroutine os/exec starts for cmd.Stdin can still be blocked writing to
// a dead child's closed pipe. Without a WaitDelay, Wait can block on that
// goroutine forever instead of the handler's deferred wait() ever
// returning — the exact "cancelled rather than orphaned" case this
// ticket names. This is one field, not a supervision layer: deadlines,
// process groups, and reaping policy beyond this belong to WALD-41.
const uploadPackWaitDelay = 5 * time.Second

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

// flushingWriter wraps a ResponseWriter so every Write is immediately
// flushed to the connection. Without this, sideband progress on a long
// fetch sits in net/http's own buffering and a real clone looks hung —
// git's own backend writes unbuffered, and this endpoint matches it.
type flushingWriter struct {
	w http.ResponseWriter
	c *http.ResponseController
}

func newFlushingWriter(w http.ResponseWriter) *flushingWriter {
	return &flushingWriter{w: w, c: http.NewResponseController(w)}
}

func (f *flushingWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if err != nil {
		return n, err
	}
	if flushErr := f.c.Flush(); flushErr != nil && !errors.Is(flushErr, http.ErrNotSupported) {
		return n, flushErr
	}
	return n, nil
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
	_ = required

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

	path, ok := h.resolveRepoDir(w, repo)
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

	// Binding to the request context means a client disconnect kills the
	// subprocess. Killing is not reaping, though: only Wait collects its
	// exit status and releases its pipes. See the waited/wait closure
	// below, and uploadPackWaitDelay above for why Wait itself cannot
	// hang forever on this path.
	cmd := exec.CommandContext(r.Context(), "git", "upload-pack", "--stateless-rpc", path)
	cmd.Env = gitEnv(wantV2)
	cmd.Stdin = reqBody
	cmd.WaitDelay = uploadPackWaitDelay

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		writeRefusal(w, http.StatusInternalServerError, refusal.Refuse(
			"upload-pack failed",
			"could not open a pipe to the git subprocess",
			"check the server's git installation",
		))
		return
	}
	var stderrBuf bytes.Buffer
	cmd.Stderr = &boundedWriter{buf: &stderrBuf, limit: maxStderrCapture}

	if err := cmd.Start(); err != nil {
		writeRefusal(w, http.StatusInternalServerError, refusal.Refuse(
			"upload-pack failed",
			"could not start the git subprocess",
			"check the server's git installation",
		))
		return
	}

	// From here on the process has been started, so it must be reaped on
	// every exit path — including a client aborting mid-fetch, which
	// cancels r.Context() and kills the child without waiting for it.
	// wait() is the single place that calls cmd.Wait(); the deferred call
	// is the backstop that catches any return this function takes
	// without having called wait() itself (in particular the io.Copy
	// error path), and the "waited" guard means an explicit call earlier
	// in the function is never repeated by the defer. Mirrors
	// handleInfoRefs's identical discipline in inforefs.go.
	var waited bool
	wait := func() error {
		waited = true
		return cmd.Wait()
	}
	defer func() {
		if !waited {
			if err := wait(); err != nil {
				log.Printf("githttp: upload-pack: git upload-pack %q: %v (%s)", repo, err, strings.TrimSpace(stderrBuf.String()))
			}
		}
	}()

	// Peek before writing anything: if git exits non-zero having
	// produced no output at all, nothing has reached the client yet and
	// this can still be a clean refusal instead of a half-written
	// response. Peeking cannot deadlock here: the stdin copy runs in its
	// own goroutine inside os/exec, so blocking on git's first output
	// byte blocks only this handler goroutine.
	br := bufio.NewReader(stdout)
	_, peekErr := br.Peek(1)
	if peekErr != nil {
		if waitErr := wait(); waitErr != nil {
			log.Printf("githttp: upload-pack: git upload-pack %q: %v (%s)", repo, waitErr, strings.TrimSpace(stderrBuf.String()))
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
		body = br
	}

	if _, err := io.Copy(newFlushingWriter(w), body); err != nil {
		// Bytes are already on the wire; the honest move is to stop and
		// log rather than append a refusal into a half-written pack.
		// The deferred wait() above still reaps the subprocess.
		log.Printf("githttp: upload-pack: writing response for %q: %v", repo, err)
		return
	}
	if peekErr == nil {
		if err := wait(); err != nil {
			log.Printf("githttp: upload-pack: git upload-pack %q exited with error after streaming: %v (%s)", repo, err, strings.TrimSpace(stderrBuf.String()))
		}
	}
}
