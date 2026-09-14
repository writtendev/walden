package githttp

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/refusal"
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

// isReceivePackContentType reports whether v names receivePackContentType,
// ignoring any parameters (e.g. a charset) and case, per RFC 9110 §8.3.1 --
// matching isUploadPackContentType (uploadpack.go), the sibling route's
// answer to the identical question. Before this, the two routes disagreed:
// a legal "application/x-git-receive-pack-request; charset=utf-8" was 200
// on fetch and 415 on push.
func isReceivePackContentType(v string) bool {
	mediaType, _, err := mime.ParseMediaType(v)
	if err != nil {
		return false
	}
	return strings.EqualFold(mediaType, receivePackContentType)
}

// waitAfterStdoutSettled calls wait after first setting a read deadline in
// the past on w, so an os/exec stdin-copy goroutine still blocked reading
// the request body -- parked there because a client announced a larger
// Content-Length than it actually sent -- does not leave Wait blocked
// indefinitely. cmd.Wait cannot return until that goroutine does, and
// neither r.Context() (a merely silent client never cancels it) nor
// receivePackWaitDelay (its timer, per go1.25's os/exec, is created only
// after context cancellation -- see the comment on that constant) ever
// unblocks it on their own.
//
// Both of handleReceivePack's wait() call sites qualify to call this
// rather than wait() directly: each runs only once git's stdout side has
// already signalled it is done producing output -- a failed Peek (git has
// exited) or an exhausted br after a full io.Copy (git closed its stdout,
// which in --stateless-rpc mode means it is done or about to exit) -- so
// applying the deadline never races a read this handler still expects to
// succeed. It is not applied to the deferred backstop's own call: that
// one fires only when writing the response itself failed, which already
// implies the connection is going away.
//
// This is also safe to call whether or not the body actually needed it:
// once http.body has already returned io.EOF for a fully-drained body, a
// further Read is answered from its own byte-count bookkeeping without
// touching the connection at all, so an expired deadline set here touches
// nothing already finished. When the body was not fully drained, forcing
// the stuck Read to fail is the correct outcome regardless -- net/http
// will not reuse a connection whose request body was not fully consumed
// -- so this cannot turn a connection that should stay alive into one
// that does not; it can only make that unavoidable outcome arrive
// promptly instead of never. SetReadDeadline's own error is ignored: if
// this ResponseWriter cannot support it, wait() falls back to whatever
// bound cmd.WaitDelay still covers rather than failing loudly for
// something orthogonal to the wait it guards.
func waitAfterStdoutSettled(w http.ResponseWriter, wait func() error) error {
	_ = http.NewResponseController(w).SetReadDeadline(time.Now())
	return wait()
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

	if ct := r.Header.Get("Content-Type"); !isReceivePackContentType(ct) {
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
	// accept and inflate a gzip-encoded request body, and landed
	// requestBodyReader (uploadpack.go) to answer this question for both
	// RPC routes: it accepts absent, "identity", "gzip", or the legacy
	// "x-gzip" spelling git-http-backend's own binary treats as gzip's
	// alias, and refuses anything else with a one-line 415. Reusing it
	// here rather than re-deriving the same switch converges this
	// route's accept set with upload-pack's rather than settling the
	// question a second time.
	body, ok := requestBodyReader(w, r)
	if !ok {
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

	// resolveRepoDir (gitcmd.go) is the same RepoPath-then-stat sequence
	// WALD-38 already uses for info/refs and upload-pack, converged here
	// so a push to a repository that does not exist reads identically to
	// a fetch of one rather than the differently-worded 404 this file
	// used to compose by hand. Push-time repo creation is still not
	// wired in (that needs a token, which arrives with WALD-52 -- see
	// WALD-39's ticket "Sequencing" section); that is a behavior gap,
	// not a wording one, and this change does not touch it.
	path, ok := h.resolveRepoDir(w, "receive-pack", repo)
	if !ok {
		return
	}

	// The hook environment: an explicit, enumerable list, never the
	// server's own environment inherited wholesale. This is what the
	// pre-receive hook (WALD-43, dispatched by argv from the same
	// binary) uses to find its repository and its journal with no
	// config file of its own.
	// gitEnv (gitcmd.go) is the same PATH-only environment WALD-38 already
	// builds for the sibling routes; called with wantV2 always false
	// because, deliberately, receive-pack never forwards the request's
	// Git-Protocol header. WALD-38's probe found receive-pack's
	// advertisement is byte-identical whether or not GIT_PROTOCOL=version=2
	// is set, so forwarding it here would change nothing observable except
	// dropping the v0 preamble — and would invalidate WALD-36's
	// receive-pack golden fixture for no demonstrated benefit. The safe
	// default is to leave receive-pack on v0 until something demonstrates
	// a reason to move it; do not pass true here without that evidence.
	env := gitEnv(false)
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
		// the refusal below is composed and ready -- but cmd.Wait() will
		// not return until the stdin-copy goroutine os/exec started for
		// cmd.Stdin (body: r.Body, or a gzip.Reader wrapping it)
		// finishes, and that goroutine is blocked in a Read on r.Body
		// whenever the client announced a Content-Length and simply
		// stopped sending without closing the connection. git exiting
		// does not unblock it, and neither does receivePackWaitDelay
		// above (see that constant's comment) -- waitAfterStdoutSettled
		// is what reaches a Read already in flight on the request body,
		// finishing the copy goroutine and letting Wait return right
		// away instead of waiting out however long the client stays
		// silent.
		if waitErr := waitAfterStdoutSettled(w, wait); waitErr != nil {
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
	// after every write (newFlushingWriter, uploadpack.go), which is what
	// lets sideband progress and a hook's relayed stderr reach the client
	// while it is still watching rather than only once the handler
	// returns.
	if peekErr == nil {
		if _, err := io.Copy(newFlushingWriter(w), br); err != nil {
			// The 200 and some bytes are already on the wire; the honest
			// move is to stop and log rather than append anything to a
			// half-written result. The deferred wait() above still reaps
			// the subprocess.
			log.Printf("githttp: receive-pack: writing result for %q: %v", repo, err)
			return
		}
	}
	if peekErr == nil {
		// git's --stateless-rpc does not read its stdin to EOF: it reads
		// the commands and exactly the pack index-pack expects, reports,
		// and exits. io.Copy above returning nil means git's stdout hit
		// EOF, i.e. git is done -- but if the client over-declared its
		// Content-Length, the stdin-copy goroutine can still be parked
		// reading the request body at this exact moment, which is round
		// 2's finding: this trailing wait() had the identical hazard
		// round 1 fixed above, on the branch that runs after a
		// *successful* push instead of before a refusal.
		// waitAfterStdoutSettled closes it the same way.
		if err := waitAfterStdoutSettled(w, wait); err != nil {
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
