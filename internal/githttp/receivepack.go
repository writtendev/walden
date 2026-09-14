package githttp

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/refusal"
	"github.com/writtendev/walden/internal/store"
)

// receivePackContentType is the one Content-Type a receive-pack RPC body
// may carry. Anything else, including absent, is refused: git's own
// client always sends exactly this value for this route, so accepting
// anything looser would be guessing at a client this repo has not seen.
const receivePackContentType = "application/x-git-receive-pack-request"

// receivePackWaitDelay bounds how long cmd.Wait may block after git's own
// exit and pipe closures have otherwise settled, mirroring
// uploadPackWaitDelay (WALD-38, uploadpack.go) so the two handlers that
// pipe a request body into git's stdin are consistent. On its own this
// does not fix the clean-500 hang below: os/exec's WaitDelay forcibly
// closes only the pipe end *it* owns (the write end feeding git's
// stdin), and the stdin-copy goroutine here is blocked reading from the
// request body, upstream of that pipe — closing the far end does not
// unblock a Read already in flight (confirmed against go1.25's os/exec
// source and by reproducing it standalone before writing the real fix
// below). It still earns its place as the same bound WALD-38 uses for
// the case WaitDelay does cover — the copy goroutine stuck writing once
// the child is already gone — so a future change to how stdin is fed
// here does not silently lose that protection.
const receivePackWaitDelay = 5 * time.Second

// handleReceivePackMethodNotAllowed refuses any method other than POST for
// /{repo}/git-receive-pack with a one-line 405.
//
// Same reasoning as handleInfoRefsMethodNotAllowed in inforefs.go: relying
// on net/http.ServeMux to auto-generate this 405 does not hold once the
// package's "/" catch-all (githttp.go's handleRequest) is also registered,
// since that catch-all matches every path regardless of method and would
// otherwise answer a non-POST request here with a bare 200. registerRoutes
// binds this handler to the same path pattern without a method, so
// ServeMux prefers the more specific "POST /{repo}/git-receive-pack"
// registration for POST and leaves every other method here.
func (h *Handler) handleReceivePackMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", "POST")
	writeRefusal(w, http.StatusMethodNotAllowed, refusal.Refuse(
		"method not allowed",
		fmt.Sprintf("%s is not supported for /{repo}/git-receive-pack", r.Method),
		"use POST",
	))
}

// handleReceivePack serves POST /{repo}/git-receive-pack: a push. Per
// ARCHITECTURE.md, walden wraps git rather than reimplementing it — the
// request body is git's own stateless-rpc packfile, piped straight to
// `git receive-pack`'s stdin, and the response is git's stdout piped
// straight back, unparsed in both directions.
//
// The headline promise this handler exists to keep (see AGENTS.md and
// PHILOSOPHY.md's "failures must be legible"): a declined push is a
// completed RPC. Once the first byte of git's output has reached the
// client, this handler never turns git's exit status into an HTTP
// failure — a hook rejection must arrive as git's own `remote:` lines and
// an `ng` report, not as a broken pipe.
func (h *Handler) handleReceivePack(w http.ResponseWriter, r *http.Request) {
	repo := r.PathValue("repo")

	if ct := r.Header.Get("Content-Type"); ct != receivePackContentType {
		writeRefusal(w, http.StatusUnsupportedMediaType, refusal.Refuse(
			"unsupported content type",
			fmt.Sprintf("Content-Type %q is not %q", ct, receivePackContentType),
			fmt.Sprintf("set Content-Type to %q", receivePackContentType),
		))
		return
	}

	// Content-Encoding gate.
	//
	// This plan originally refused any Content-Encoding, including gzip,
	// on the theory that a push body is an already-compressed packfile
	// and no git client would gzip one. WALD-38's planner tested the real
	// binaries and found git-http-backend — the reference
	// implementation this repo wraps rather than reimplements — does
	// accept and inflate a gzip-encoded request body. Settling this by
	// testing rather than by the earlier assumption (recorded in a
	// comment on WALD-39):
	//
	//   - `strings` on git-http-backend (git 2.50.1, Apple Git-155) shows
	//     it links the gzip-decompression path for its request body:
	//     "Content-Encoding: gzip", "x-gzip", and "request ended in the
	//     middle of the gzip stream" (its own truncation error) are all
	//     present.
	//   - A real `git push` of both a trivial commit and a 5MB
	//     highly-redundant file, captured with GIT_TRACE_CURL against a
	//     git-http-backend CGI instance, never sent Content-Encoding on
	//     the git-receive-pack POST in either case — git's client-side
	//     gzip path (also present in the git binary) only fires when
	//     compressing would shrink the request, and a packfile is
	//     already zlib-deflated, so it never wins that comparison.
	//
	// No git client observed here sends a gzipped push, but the
	// reference server accepts one, and inflating one costs a
	// gzip.NewReader from the standard library — a small, permanent
	// accommodation is preferable to a 415 that would blame a client
	// for doing something git-http-backend itself allows. "x-gzip" is
	// accepted alongside "gzip" for the same reason: `strings` on the
	// same git-http-backend binary lists "x-gzip" right next to
	// "Content-Encoding: gzip" in its gzip-decompression path — it is
	// the legacy spelling of the identical encoding, not a distinct one,
	// and refusing it would be the same class of mistake this decision
	// exists to avoid. Anything other than absent, "identity", "gzip",
	// or "x-gzip" is still refused: those remain unrecognized, not
	// merely unlikely.
	var body io.Reader = r.Body
	switch enc := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))); enc {
	case "", "identity":
		// body already set to r.Body.
	case "gzip", "x-gzip":
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			writeRefusal(w, http.StatusBadRequest, refusal.RefuseWithCause(
				"invalid request body",
				"Content-Encoding: gzip was declared but the body is not a valid gzip stream",
				"send an uncompressed body or a correctly gzip-compressed one",
				err,
			))
			return
		}
		defer gz.Close()
		body = gz
	default:
		writeRefusal(w, http.StatusUnsupportedMediaType, refusal.Refuse(
			"unsupported content encoding",
			fmt.Sprintf("Content-Encoding %q is not supported", enc),
			"send the request uncompressed or gzip-compressed",
		))
		return
	}

	// actionForService (inforefs.go) is called here with the literal
	// "git-receive-pack" so spec/auth/v1 §3.2's service->action table
	// stays defined in exactly one function, rather than this handler
	// hardcoding auth.ActionWrite on its own account. The error branch is
	// unreachable for this literal, known-good value, but is handled
	// rather than ignored.
	_, _, action, err := actionForService("git-receive-pack")
	if err != nil {
		log.Printf("githttp: receive-pack: actionForService(git-receive-pack): %v", err)
		writeRefusal(w, http.StatusInternalServerError, refusal.Refuse(
			"receive-pack failed",
			"internal action mapping error",
			"contact the operator",
		))
		return
	}
	// required is the auth.Actions this request needs. WALD-52 owns the
	// 401 challenge and Basic/Bearer token parsing; this is the one
	// obvious insertion point for the Authorize call, before the exec
	// below. See WALD-39's ticket "Sequencing" section: this handler
	// lands with no authorization call at all, mirroring handleInfoRefs,
	// because there is no token to check with until WALD-52 parses
	// Authorization.
	required := auth.Actions{Write: action == auth.ActionWrite}
	_ = required

	path, err := h.store.RepoPath(repo)
	if err != nil {
		// Same mapping as handleInfoRefs: store.ErrStoreUnavailable is an
		// operator fault (5xx); everything else — a bad identifier, a
		// containment escape — is caller fault (4xx).
		if errors.Is(err, store.ErrStoreUnavailable) {
			log.Printf("githttp: receive-pack: repo path for %q: %v", repo, err)
			writeRefusal(w, http.StatusInternalServerError, refusal.RefuseWithCause(
				"repository unavailable",
				"the server could not resolve the repository path",
				"contact the operator",
				store.ErrStoreUnavailable,
			))
			return
		}
		writeRefusal(w, http.StatusBadRequest, err)
		return
	}

	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// A plain 404: this ticket does not wire in create-on-push
			// (see WALD-39's "Sequencing" section — that call needs a
			// token, which arrives with WALD-52). The §3.4 create-scope
			// refusal text lands there, not here.
			writeRefusal(w, http.StatusNotFound, refusal.RefuseWithCause(
				"repository not found",
				fmt.Sprintf("no repository named %q", repo),
				"check the repository identifier or push to create it once creation is wired in",
				store.ErrRepoNotFound,
			))
			return
		}
		log.Printf("githttp: receive-pack: stat repository path for %q: %v", repo, err)
		writeRefusal(w, http.StatusInternalServerError, refusal.RefuseWithCause(
			"repository unavailable",
			"the server could not access the repository",
			"contact the operator",
			store.ErrStoreUnavailable,
		))
		return
	}

	// The hook environment: an explicit, enumerable list, never the
	// server's own environment inherited wholesale. This is what the
	// pre-receive hook (WALD-43, dispatched by argv from the same
	// binary) uses to find its repository and its journal with no
	// config file of its own.
	env := []string{}
	if p := os.Getenv("PATH"); p != "" {
		env = append(env, "PATH="+p)
	}
	// Deliberately not forwarded: the request's Git-Protocol header.
	// WALD-38's probe found receive-pack's advertisement is
	// byte-identical whether or not GIT_PROTOCOL=version=2 is set, so
	// forwarding it here would change nothing observable except
	// dropping the v0 preamble — and would invalidate WALD-36's
	// receive-pack golden fixture for no demonstrated benefit. The safe
	// default is to leave receive-pack on v0 until something demonstrates
	// a reason to move it; do not re-add this without that evidence.
	env = append(env,
		"WALDEN_REPO="+repo,
		"WALDEN_DATA_DIR="+h.store.DataDir(),
	)
	// Set only when non-empty: an unset WALDEN_JOURNAL is the existing
	// signal for journal-less mode, and an empty one would be a third
	// state alongside "unset" and "a URL".
	if h.journalURL != "" {
		env = append(env, "WALDEN_JOURNAL="+h.journalURL)
	}
	// Forwarded only when set in the server's own environment: these are
	// exactly the names ARCHITECTURE.md's credential-resolution order
	// reads, and the hook — not this handler — is the process that PUTs
	// to object storage.
	for _, name := range []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"AWS_REGION",
		"AWS_DEFAULT_REGION",
	} {
		if v, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+v)
		}
	}
	// Deliberately not set: GIT_COMMITTER_NAME / GIT_COMMITTER_EMAIL,
	// which git-http-backend fills from the authenticated user. walden
	// has no identity model, and a reflog entry naming a person is
	// meaning in the storage layer (PHILOSOPHY.md: "no meaning in the
	// storage layer").
	//
	// Untouched on purpose: GIT_QUARANTINE_PATH and everything else git
	// sets for its own hooks. This handler builds an explicit env slice
	// rather than inheriting the server's environment, but it does not
	// touch what git itself injects into the child once started; nothing
	// here bypasses or relaxes the quarantine-until-pre-receive-exits-0
	// mechanism the durability handshake will stand on.

	// Binding to the request context means a client disconnect kills the
	// subprocess. Killing is not reaping, though — only Wait collects
	// its exit status and releases its pipes. See the waited/wait
	// closure below, same shape as handleInfoRefs.
	cmd := exec.CommandContext(r.Context(), "git", "receive-pack", "--stateless-rpc", path)
	cmd.Env = env
	cmd.Stdin = body
	cmd.WaitDelay = receivePackWaitDelay

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		writeRefusal(w, http.StatusInternalServerError, refusal.Refuse(
			"receive-pack failed",
			"could not open a pipe to the git subprocess",
			"check the server's git installation",
		))
		return
	}
	var stderrBuf bytes.Buffer
	cmd.Stderr = &boundedWriter{buf: &stderrBuf, limit: maxStderrCapture}

	if err := cmd.Start(); err != nil {
		writeRefusal(w, http.StatusInternalServerError, refusal.Refuse(
			"receive-pack failed",
			"could not start the git subprocess",
			"check the server's git installation",
		))
		return
	}

	// wait() is the single place that calls cmd.Wait(); the deferred call
	// is the backstop that reaps the child on any return path that did
	// not call wait() itself, and "waited" means an earlier explicit call
	// is never repeated by the defer. This is the same discipline
	// handleInfoRefs uses, and for the same reason: a leaked zombie per
	// aborted request was WALD-36's one major review finding. The
	// deferred wait is safe here only because cmd.Stdin is r.Body (or a
	// gzip reader wrapping it): an io.Copy failure on the response body
	// below implies the request's context has already been canceled, so
	// the child is either already exiting or about to be killed by that
	// cancellation rather than left running with nothing left to drain
	// its stdin.
	var waited bool
	wait := func() error {
		waited = true
		return cmd.Wait()
	}
	defer func() {
		if !waited {
			if err := wait(); err != nil {
				log.Printf("githttp: receive-pack: git receive-pack %q: %v (%s)", repo, err, strings.TrimSpace(stderrBuf.String()))
			}
		}
	}()

	// Peek before writing anything: if git exits non-zero having
	// produced no output at all, nothing has reached the client yet and
	// this can still be a clean 500 refusal instead of a half-written
	// response. Once this peek succeeds, the response is committed: git's
	// exit status is logged from here on and never turned into an HTTP
	// failure, which is the whole of this handler's headline promise.
	br := bufio.NewReader(stdout)
	_, peekErr := br.Peek(1)
	if peekErr != nil {
		// git has already exited (that is what made the peek fail) and
		// the refusal below is composed and ready — but cmd.Wait() will
		// not return until the stdin-copy goroutine os/exec started for
		// cmd.Stdin (body: r.Body, or a gzip.Reader wrapping it)
		// finishes, and that goroutine is blocked in a Read on r.Body
		// whenever the client announced a Content-Length and simply
		// stopped sending without closing the connection. git exiting
		// does not unblock it, and neither does receivePackWaitDelay
		// above: os/exec only forces closed the pipe end it owns once
		// its delay elapses, and a Read already parked in r.Body is
		// upstream of that pipe (proven both by reading go1.25's
		// os/exec source and by reproducing the hang standalone). The
		// one thing that does reach a Read already in flight on the
		// request body is a deadline on the request itself: setting one
		// in the past turns that Read into an immediate error, which
		// finishes the copy goroutine and lets Wait return right away
		// instead of waiting out however long the client stays silent.
		// SetReadDeadline's error is deliberately ignored — if this
		// ResponseWriter cannot support it, wait() below falls back to
		// receivePackWaitDelay's bound rather than hanging forever.
		_ = http.NewResponseController(w).SetReadDeadline(time.Now())
		if waitErr := wait(); waitErr != nil {
			log.Printf("githttp: receive-pack: git receive-pack %q: %v (%s)", repo, waitErr, strings.TrimSpace(stderrBuf.String()))
			writeRefusal(w, http.StatusInternalServerError, refusal.Refuse(
				"receive-pack failed",
				"git exited with an error before producing a response",
				"check the server log for the underlying git error",
			))
			return
		}
		// git exited 0 with no output at all; fall through and send an
		// empty 200. This is not expected of a real receive-pack, but
		// there is nothing to gate on: nothing failed.
	}

	w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "Fri, 01 Jan 1980 00:00:00 GMT")
	w.WriteHeader(http.StatusOK)

	// No Content-Length: the response is chunked and unbuffered, flushed
	// after every write, which is what lets sideband progress and a
	// hook's relayed stderr reach the client while it is still watching
	// rather than only once the handler returns.
	fw := flushWriter{w: w, rc: http.NewResponseController(w)}
	if peekErr == nil {
		if _, err := io.Copy(fw, br); err != nil {
			// The 200 and some bytes are already on the wire; the honest
			// move is to stop and log rather than append anything to a
			// half-written result. The deferred wait() above still reaps
			// the subprocess.
			log.Printf("githttp: receive-pack: writing result for %q: %v", repo, err)
			return
		}
	}
	if peekErr == nil {
		if err := wait(); err != nil {
			// Exactly the headline promise: git's non-zero exit (a
			// declined push, a hook rejection) is logged here and never
			// gates the response already sent above.
			log.Printf("githttp: receive-pack: git receive-pack %q exited with error after streaming: %v (%s)", repo, err, strings.TrimSpace(stderrBuf.String()))
		}
	}
	// When peekErr != nil, wait() was already called above (either in
	// the peek branch directly, or by falling through after it
	// succeeded with no output) — calling it again here would hit
	// os/exec's "Wait was already called" and log a git failure that
	// never happened, exactly mirroring handleInfoRefs's identical
	// guard in inforefs.go.
}

// flushWriter wraps an http.ResponseWriter so every Write is flushed
// immediately. Without this, sideband progress and a hook's relayed
// stderr would sit in a buffer until the handler returns instead of
// reaching the client as git produces them — a declined push would still
// arrive as `ng`, but the developer would not see it live.
type flushWriter struct {
	w  http.ResponseWriter
	rc *http.ResponseController
}

func (f flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if err != nil {
		return n, err
	}
	// Flush is best-effort: a ResponseWriter that cannot support it (or a
	// client that has already gone away) does not turn an otherwise
	// successful write into a copy failure.
	_ = f.rc.Flush()
	return n, nil
}
