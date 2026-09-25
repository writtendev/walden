package githttp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/writtendev/walden/internal/refusal"
	"github.com/writtendev/walden/internal/store"
)

// maxStderrCapture bounds how much of git's stderr is retained for the log line
// when an operation fails; the rest is discarded so a verbose or hostile
// subprocess cannot grow walden's memory use.
const maxStderrCapture = 4096

// gitWaitDelay bounds how long cmd.Wait may block after git's own exit and pipe
// closures have otherwise settled. Cancelling the request context kills the
// child (and its process group), but killing is not reaping: the stdin-copy
// goroutine os/exec starts for cmd.Stdin can still be blocked writing to a dead
// child's closed pipe. WaitDelay forces os/exec to close its pipe ends and let
// Wait return rather than hanging forever.
const gitWaitDelay = 5 * time.Second

// gitDrainGrace bounds how long waitSettled will wait for cmd.Wait to finish on
// its own before forcing an expired read deadline on the connection. On the
// healthy path (e.g. push succeeded and request body was fully drained), git
// has exited and stdin hit EOF, so wait() returns almost instantaneously —
// well within this grace period — leaving the keep-alive connection untouched.
// Only if wait() stalls (the client over-declared Content-Length and stopped
// sending) does the deadline fire to unblock the stuck body read.
const gitDrainGrace = 100 * time.Millisecond

// The PID-1 reaper we deliberately do not write:
//
// In containerized deployments, walden runs as PID 1, where the kernel
// reparents orphaned processes to it. A generic wait4(-1, WNOHANG) loop is the
// textbook answer for PID 1, but is the wrong answer here: it races os/exec's
// own bookkeeping and can reap a child out from under a handler's cmd.Wait().
//
// Instead of reaping orphaned grandchildren after the fact, walden prevents
// them from ever being orphaned: every git invocation runs in its own process
// group (Setpgid: true on Unix), and context cancellation sends SIGKILL to the
// negative PID (-pid), terminating the entire process group (git and any
// grandchildren it forked, such as pack-objects or index-pack) together.
// Because descendants are killed at the same time, they do not survive to
// reparent to PID 1, removing the need for a global PID-1 reaper.

// gitProc manages the execution, output streaming, and lifecycle of a git
// subprocess. It owns process lifetime and nothing else: it writes no HTTP
// response and decides no status code.
type gitProc struct {
	cmd         *exec.Cmd
	stdout      *bufio.Reader
	stderr      *bytes.Buffer
	releaseBody func()
	waited      bool
	waitErr     error
}

// wait is the single place cmd.Wait() is called, with a waited guard so a
// deferred backstop never double-waits.
func (p *gitProc) wait() error {
	if p.waited {
		return p.waitErr
	}
	p.waited = true
	p.waitErr = p.cmd.Wait()
	return p.waitErr
}

// release invokes the caller-supplied releaseBody (the SetReadDeadline(time.Now())
// call) before waiting, on the paths where the child is already gone and the body
// may not be drained.
func (p *gitProc) release() {
	if p.releaseBody != nil {
		p.releaseBody()
	}
}

// waitSettled calls wait(), but bounds how long it will block on an os/exec
// stdin-copy goroutine that is parked in Read on the request body because a
// client announced a larger Content-Length than it actually sent.
//
// Crucially, it does NOT set a read deadline immediately. Setting an expired
// read deadline on a connection whose body was fully drained causes net/http's
// background read on the socket to error and cancel the connection context,
// poisoning the connection for any subsequent keep-alive request.
//
// Instead, it gives wait() a short grace period (gitDrainGrace) to return on its
// own. For any healthy request where the body was fully sent, git has already
// exited and stdin hit EOF, so wait() returns almost instantaneously without
// ever touching the connection deadline. Only if wait() does not return within
// the grace period — indicating that the stdin copy goroutine is stuck reading
// missing body bytes — does it invoke release() to force an expired read deadline
// and unblock the stuck Read.
func (p *gitProc) waitSettled() error {
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- p.wait()
	}()

	select {
	case err := <-waitDone:
		return err
	case <-time.After(gitDrainGrace):
		p.release()
		return <-waitDone
	}
}

// startGit builds the exec.CommandContext, applies the environment (or gitEnv
// when nil), sets WaitDelay, sets the platform cancel hook for process-group
// termination, starts the subprocess, and returns a gitProc carrying the
// *bufio.Reader over stdout and the bounded stderr buffer.
func startGit(ctx context.Context, env []string, stdin io.Reader, releaseBody func(), args ...string) (*gitProc, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	if env != nil {
		cmd.Env = env
	} else {
		cmd.Env = gitEnv(false)
	}
	cmd.Stdin = stdin
	cmd.WaitDelay = gitWaitDelay
	setupProcessGroup(cmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderrBuf bytes.Buffer
	cmd.Stderr = &boundedWriter{buf: &stderrBuf, limit: maxStderrCapture}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	return &gitProc{
		cmd:         cmd,
		stdout:      bufio.NewReader(stdout),
		stderr:      &stderrBuf,
		releaseBody: releaseBody,
	}, nil
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

// flushingWriter wraps a ResponseWriter so every Write is immediately
// flushed to the connection. Without this, sideband progress on a long
// fetch or push sits in net/http's own buffering and the connection looks hung —
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

// gitEnv returns the explicit, minimal environment for a git subprocess
// this package execs: GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM pinned to
// /dev/null, so the child gets no system or global config at all, plus
// PATH, so git can find anything it execs internally, plus GIT_PROTOCOL
// when the caller has negotiated protocol v2. The value forwarded is
// always this package's own literal "GIT_PROTOCOL=version=2" — never a
// client's raw header value — so a client cannot use this to inject an
// arbitrary environment variable into the git child.
//
// The pin exists so walden's behavior does not depend on the machine it
// runs on: whatever the host's system or global git config happens to
// set, the child sees none of it. It says nothing about what a
// repository's own local config can do — that threat model is tracked
// separately, in WALD-131. The spelling is byte-identical to the one
// internal/store/repo.go already uses on CreateRepo's git init and on its
// own hook-path and git-dir probes, so the whole codebase is greppable
// for one string.
func gitEnv(wantV2 bool) []string {
	env := []string{"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null"}
	if p := os.Getenv("PATH"); p != "" {
		env = append(env, "PATH="+p)
	}
	if wantV2 {
		env = append(env, "GIT_PROTOCOL=version=2")
	}
	return env
}

// resolveRepoDir resolves repo to its bare repository directory on disk,
// asking store for both the path and the existence answer in one call
// rather than stat'ing the filesystem itself. route names the calling
// endpoint (e.g. "info/refs" or "upload-pack") for the operator log only:
// these refusals are deliberately path-free on the wire, so the log line
// is the only place an operator can tell which endpoint produced a given
// 500. On success it returns the path and true. On failure it writes a
// one-line refusal to w — mapping store.ErrStoreUnavailable to 500, every
// other RepoPath refusal to 400, and a missing repository to 404 — and
// returns false, telling the caller to stop.
func (h *Handler) resolveRepoDir(ctx context.Context, w http.ResponseWriter, route, repo string) (string, bool) {
	path, exists, err := h.store.ResolveRepo(ctx, repo)
	if err != nil {
		if errors.Is(err, store.ErrStoreUnavailable) {
			log.Printf("githttp: %s: resolve repo for %q: %v", route, repo, err)
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

	if !exists {
		writeRefusal(w, http.StatusNotFound, refusal.RefuseWithCause(
			"repository not found",
			fmt.Sprintf("no repository named %q", repo),
			"check the repository identifier or create it with a push",
			store.ErrRepoNotFound,
		))
		return "", false
	}

	return path, true
}
