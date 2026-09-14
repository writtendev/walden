package githttp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/refusal"
	"github.com/writtendev/walden/internal/store"
)

// maxStderrCapture bounds how much of git's stderr this handler retains for
// the log line when an advertisement fails; the rest is discarded so a
// verbose or hostile subprocess cannot grow this handler's memory use.
const maxStderrCapture = 4096

// flushPkt is the pkt-line flush packet: the literal four bytes "0000",
// the smart-HTTP protocol's own framing for "no more data in this
// section."
var flushPkt = []byte("0000")

// pktLine encodes s as a single pkt-line: a four-hex-digit length prefix
// that counts itself, followed by s verbatim. This is framing, not
// negotiation — the only pkt-line walden constructs itself is the
// "# service=" preamble the smart-HTTP protocol requires the server, not
// git, to emit; git's own refs, capability list, and trailing flush come
// through untouched.
func pktLine(s string) []byte {
	return []byte(fmt.Sprintf("%04x%s", len(s)+4, s))
}

// actionForService maps a smart-HTTP service parameter to the git
// subcommand that produces its advertisement, the flag that asks that
// subcommand to only advertise refs, and the auth.Action a request for it
// requires, per spec/auth/v1/README.md section 3.2. walden serves smart
// HTTP only: any other value, including an absent one (a dumb-HTTP
// client), is refused.
//
// The advertise-refs flag differs between the two services, and each is
// given the one its own documentation publishes rather than a convenient
// alias. `git upload-pack -h` lists `--advertise-refs` in its usage
// synopsis, so that is upload-pack's documented interface. `git
// receive-pack -h` lists no advertise-refs flag at all — `--advertise-refs`
// happens to work there too, but only as an undocumented alias; the
// interface receive-pack's own man page publishes (and what
// git-http-backend itself execs for both services) is
// `--http-backend-info-refs`. A routine git security bump is free to drop
// an undocumented alias; it is not free to drop a documented flag.
func actionForService(service string) (subcommand, advertiseFlag string, action auth.Action, err error) {
	switch service {
	case "git-upload-pack":
		return "upload-pack", "--advertise-refs", auth.ActionRead, nil
	case "git-receive-pack":
		return "receive-pack", "--http-backend-info-refs", auth.ActionWrite, nil
	default:
		return "", "", "", refusal.Refuse(
			"unsupported service",
			fmt.Sprintf("service %q is not git-upload-pack or git-receive-pack", service),
			"walden serves git's smart HTTP protocol only",
		)
	}
}

// writeRefusal sends a refusal's single line as the entire response body,
// per PHILOSOPHY.md's "failures must be legible."
func writeRefusal(w http.ResponseWriter, status int, err error) {
	http.Error(w, err.Error(), status)
}

// boundedWriter caps how many bytes it retains from a stream, discarding
// the remainder while still reporting a full write so a caller such as
// exec's stderr plumbing never sees a short write.
type boundedWriter struct {
	buf   *bytes.Buffer
	limit int
}

func (b *boundedWriter) Write(p []byte) (int, error) {
	if remaining := b.limit - b.buf.Len(); remaining > 0 {
		if remaining > len(p) {
			remaining = len(p)
		}
		b.buf.Write(p[:remaining])
	}
	return len(p), nil
}

// handleInfoRefsMethodNotAllowed refuses any method other than GET for
// /{repo}/info/refs with a one-line 405.
//
// This exists because relying on net/http.ServeMux to produce that 405
// automatically — the original plan here — turned out not to hold: the
// mux only auto-generates 405 when no other registered pattern matches
// the path, and this handler's package also registers a "/" catch-all
// (githttp.go's handleRequest) that matches every path regardless of
// method. With that catch-all present, a non-GET request to this path
// falls through to it instead of getting a method-mismatch 405. Since the
// catch-all is out of this ticket's scope to change, this handler states
// the 405 rule directly: registerRoutes binds it to the same path pattern
// without a method, and net/http.ServeMux prefers the more specific
// "GET /{repo}/info/refs" registration for GET/HEAD, leaving every other
// method here.
func (h *Handler) handleInfoRefsMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	// RFC 9110 §15.5.6 makes this a MUST: a 405 response must name the
	// target resource's currently supported methods — and that list is
	// "GET, HEAD", not just "GET". net/http.ServeMux's GET-also-matches-HEAD
	// rule means a HEAD request to this path is routed to handleInfoRefs
	// (200, correct content type, empty body), so HEAD is genuinely
	// supported here even though this handler never sees it. Naming only
	// GET would tell the exact audience Allow exists for — proxies,
	// scanners, cache revalidation — that HEAD is unsupported, which can
	// turn a cheap conditional HEAD into a full GET (and a discarded git
	// exec) on their end.
	w.Header().Set("Allow", "GET, HEAD")
	writeRefusal(w, http.StatusMethodNotAllowed, refusal.Refuse(
		"method not allowed",
		fmt.Sprintf("%s is not supported for /{repo}/info/refs", r.Method),
		"use GET",
	))
}

// handleInfoRefs serves GET /{repo}/info/refs: git's smart-HTTP ref
// advertisement. Per ARCHITECTURE.md, walden wraps git rather than
// reimplementing it — the refs, the capability list, and the trailing
// flush all come out of the real git binary untouched.
func (h *Handler) handleInfoRefs(w http.ResponseWriter, r *http.Request) {
	repo := r.PathValue("repo")
	service := r.URL.Query().Get("service")

	subcommand, advertiseFlag, action, err := actionForService(service)
	if err != nil {
		writeRefusal(w, http.StatusForbidden, err)
		return
	}
	// action is the auth.Action this request requires. WALD-52 owns the
	// 401 challenge and the actual authorization check; this is the one
	// obvious insertion point for it, before the exec below.
	_ = action

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
			log.Printf("githttp: info/refs: repo path for %q: %v", repo, err)
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
			writeRefusal(w, http.StatusNotFound, refusal.RefuseWithCause(
				"repository not found",
				fmt.Sprintf("no repository named %q", repo),
				"check the repository identifier or create it with a push",
				store.ErrRepoNotFound,
			))
			return
		}
		// As above: log the full stat error (it names the absolute
		// repository path) and send the client a fixed one-liner.
		log.Printf("githttp: info/refs: stat repository path for %q: %v", repo, err)
		writeRefusal(w, http.StatusInternalServerError, refusal.RefuseWithCause(
			"repository unavailable",
			"the server could not access the repository",
			"contact the operator",
			store.ErrStoreUnavailable,
		))
		return
	}

	// An explicit, minimal environment rather than the server's own: just
	// PATH, so git can find anything it execs internally.
	//
	// Deliberately not forwarded: the request's Git-Protocol header. A v2
	// client that sees a v2 capability advertisement here would follow up
	// with `POST /{repo}/git-upload-pack` (command=ls-refs) to get the
	// actual ref list — an endpoint that does not exist until WALD-38.
	// Advertising a capability this server cannot yet complete is worse
	// than not advertising it: ignoring the header keeps git on v0/v1,
	// where this handler's own advertisement is the whole answer. Do not
	// re-add GIT_PROTOCOL forwarding here without WALD-38 landing first.
	env := []string{}
	if p := os.Getenv("PATH"); p != "" {
		env = append(env, "PATH="+p)
	}

	// Binding to the request context means a client disconnect kills the
	// subprocess. Killing is not reaping, though: only Wait collects its
	// exit status, closes the StdoutPipe read end, and releases the
	// stderr pipe. See the waited/wait closure below.
	cmd := exec.CommandContext(r.Context(), "git", subcommand, "--stateless-rpc", advertiseFlag, path)
	cmd.Env = env

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		writeRefusal(w, http.StatusInternalServerError, refusal.Refuse(
			"ref advertisement failed",
			"could not open a pipe to the git subprocess",
			"check the server's git installation",
		))
		return
	}
	var stderrBuf bytes.Buffer
	cmd.Stderr = &boundedWriter{buf: &stderrBuf, limit: maxStderrCapture}

	if err := cmd.Start(); err != nil {
		writeRefusal(w, http.StatusInternalServerError, refusal.Refuse(
			"ref advertisement failed",
			"could not start the git subprocess",
			"check the server's git installation",
		))
		return
	}

	// From here on the process has been started, so it must be reaped on
	// every exit path — including a client aborting mid-advertisement,
	// which cancels r.Context() and kills the child without waiting for
	// it. wait() is the single place that calls cmd.Wait(); the deferred
	// call is the backstop that catches any return this function takes
	// without having called wait() itself (the io.Copy error path is the
	// one that used to skip it entirely), and the "waited" guard means an
	// explicit call earlier in the function is never repeated by the
	// defer.
	var waited bool
	wait := func() error {
		waited = true
		return cmd.Wait()
	}
	defer func() {
		if !waited {
			if err := wait(); err != nil {
				log.Printf("githttp: info/refs: git %s %s %q: %v (%s)", subcommand, advertiseFlag, repo, err, strings.TrimSpace(stderrBuf.String()))
			}
		}
	}()

	// Peek before writing anything: if git exits non-zero having produced
	// no output at all, nothing has reached the client yet and this can
	// still be a clean refusal instead of a half-written response.
	br := bufio.NewReader(stdout)
	_, peekErr := br.Peek(1)
	if peekErr != nil {
		if waitErr := wait(); waitErr != nil {
			log.Printf("githttp: info/refs: git %s %s %q: %v (%s)", subcommand, advertiseFlag, repo, waitErr, strings.TrimSpace(stderrBuf.String()))
			writeRefusal(w, http.StatusInternalServerError, refusal.Refuse(
				"ref advertisement failed",
				"git exited with an error before producing an advertisement",
				"check the server log for the underlying git error",
			))
			return
		}
		// git exited 0 with an empty advertisement; fall through and
		// write the preamble alone.
	}

	w.Header().Set("Content-Type", fmt.Sprintf("application/x-%s-advertisement", service))
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "Fri, 01 Jan 1980 00:00:00 GMT")
	w.WriteHeader(http.StatusOK)

	body := io.MultiReader(
		bytes.NewReader(pktLine(fmt.Sprintf("# service=%s\n", service))),
		bytes.NewReader(flushPkt),
	)
	if peekErr == nil {
		body = io.MultiReader(body, br)
	}

	if _, err := io.Copy(w, body); err != nil {
		// Bytes are already on the wire; the honest move is to stop and
		// log rather than append a refusal into a half-written
		// advertisement. The deferred wait() above still reaps the
		// subprocess: this used to return here without ever calling
		// cmd.Wait(), which is exactly the leak round-1 review found.
		log.Printf("githttp: info/refs: writing advertisement for %q: %v", repo, err)
		return
	}
	if peekErr == nil {
		if err := wait(); err != nil {
			log.Printf("githttp: info/refs: git %s %s %q exited with error after streaming: %v (%s)", subcommand, advertiseFlag, repo, err, strings.TrimSpace(stderrBuf.String()))
		}
	}
}
