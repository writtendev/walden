package githttp

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strings"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/refusal"
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
// git, to emit under protocol v0/v1; git's own refs, capability list, and
// trailing flush come through untouched. Under protocol v2 this preamble
// is not emitted at all — see handleInfoRefs's wantV2 handling.
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

	path, ok := h.resolveRepoDir(w, repo)
	if !ok {
		return
	}

	// wantV2 mirrors git-http-backend's own negotiation: an exact match
	// on the Git-Protocol header, restricted to upload-pack. Verified
	// against git's own git-http-backend (git 2.50.1): under v2 the
	// advertisement is git's bare capability list with no "# service="
	// preamble at all, which is why the preamble below becomes
	// conditional on wantV2. A hypothetical "version=2:key=value" client,
	// or any value other than exactly "version=2", falls back to v0 —
	// a correct interoperable outcome, not a break.
	//
	// receive-pack never negotiates v2 here on purpose: its advertisement
	// is byte-identical with and without GIT_PROTOCOL (v2 carries no push
	// semantics), so forwarding it would only drop the preamble on a push
	// path WALD-38 cannot demonstrate end to end, for no gain. WALD-39
	// decides receive-pack's v2 behavior separately, with a working push
	// in hand.
	wantV2 := service == "git-upload-pack" && r.Header.Get("Git-Protocol") == "version=2"

	// Binding to the request context means a client disconnect kills the
	// subprocess. Killing is not reaping, though: only Wait collects its
	// exit status, closes the StdoutPipe read end, and releases the
	// stderr pipe. See the waited/wait closure below.
	cmd := exec.CommandContext(r.Context(), "git", subcommand, "--stateless-rpc", advertiseFlag, path)
	cmd.Env = gitEnv(wantV2)

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

	var parts []io.Reader
	if !wantV2 {
		parts = append(parts,
			bytes.NewReader(pktLine(fmt.Sprintf("# service=%s\n", service))),
			bytes.NewReader(flushPkt),
		)
	}
	if peekErr == nil {
		parts = append(parts, br)
	}
	body := io.MultiReader(parts...)

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
