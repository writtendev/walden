//go:build unix

package auth

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/writtendev/walden/internal/refusal"
)

// storeLock is an open handle to an advisory, cross-process exclusive lock on a sibling
// file. Releasing it is nothing more than closing the descriptor: the kernel drops an
// flock(2) lock automatically when the last descriptor referring to it closes, including
// when the holding process dies outright (SIGKILL, an OOM kill, a container stop that
// outruns its grace period).
//
// That is the reason this is flock rather than an O_CREATE|O_EXCL lockfile: a lockfile left
// behind by a dead process is a file an operator must find and remove by hand before the
// token CLI works again, and the refusal it produces cannot tell "another process is
// writing" from "something died three days ago" apart. flock has no such failure mode.
type storeLock struct {
	f *os.File
}

// storeLockPollInterval is how often acquireStoreLock retries a non-blocking flock attempt
// while it waits for ctx to still be live. flock(2) has no way to interrupt a blocking
// LOCK_EX wait from outside the blocked thread, so a plain blocking call cannot honor ctx at
// all -- a signal delivered while `walden serve` boot is waiting on tokens.lock inside
// EnsureAdminToken would otherwise be caught by signal.NotifyContext (dispatchServe, in
// cmd/walden/main.go) and then simply ignored until the lock happened to free up on its own.
// Polling with LOCK_NB trades a small, bounded latency between the lock actually freeing and
// this process noticing (at most one interval) for a wait that ctx can actually cancel.
const storeLockPollInterval = 20 * time.Millisecond

// acquireStoreLock blocks until it holds an exclusive lock on path, creating the file if
// necessary, or until ctx is done, whichever comes first. Concurrent writers therefore
// serialize rather than race or fail outright: a second `walden token create` invoked while
// another is in flight waits its turn instead of losing the first one's update -- but a
// caller whose ctx is cancelled while waiting (serve shutting down on SIGINT/SIGTERM) gets
// back ctx.Err() promptly instead of blocking until the lock happens to free up.
func acquireStoreLock(ctx context.Context, path string) (*storeLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, refusal.RefuseWithCause(
			"token store locked",
			fmt.Sprintf("cannot open lock file %s: %s", path, err.Error()),
			"verify the data directory is writable",
			ErrStoreUnavailable,
		)
	}

	ticker := time.NewTicker(storeLockPollInterval)
	defer ticker.Stop()
	for {
		flockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if flockErr == nil {
			return &storeLock{f: f}, nil
		}
		if flockErr != syscall.EWOULDBLOCK {
			f.Close()
			return nil, refusal.RefuseWithCause(
				"token store locked",
				fmt.Sprintf("cannot lock %s: %s", path, flockErr.Error()),
				"retry; another walden process may be writing the token store",
				ErrStoreUnavailable,
			)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, refusal.RefuseWithCause(
				"token store locked",
				fmt.Sprintf("waiting for %s: %s", path, ctx.Err().Error()),
				"another walden process is writing the token store; retry once it is not shutting down",
				ctx.Err(),
			)
		case <-ticker.C:
		}
	}
}

// release drops the lock. The kernel would do this on its own once f closes, but callers
// release explicitly so a long-lived process (walden serve) does not accumulate open
// descriptors across many mutations.
func (l *storeLock) release() error {
	return l.f.Close()
}
