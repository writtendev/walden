//go:build unix

package auth

import (
	"fmt"
	"os"
	"syscall"

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

// acquireStoreLock blocks until it holds an exclusive lock on path, creating the file if
// necessary. Concurrent writers therefore serialize rather than race or fail outright: a
// second `walden token create` invoked while another is in flight waits its turn instead of
// losing the first one's update.
func acquireStoreLock(path string) (*storeLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, refusal.RefuseWithCause(
			"token store locked",
			fmt.Sprintf("cannot open lock file %s: %s", path, err.Error()),
			"verify the data directory is writable",
			ErrStoreUnavailable,
		)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, refusal.RefuseWithCause(
			"token store locked",
			fmt.Sprintf("cannot lock %s: %s", path, err.Error()),
			"retry; another walden process may be writing the token store",
			ErrStoreUnavailable,
		)
	}
	return &storeLock{f: f}, nil
}

// release drops the lock. The kernel would do this on its own once f closes, but callers
// release explicitly so a long-lived process (walden serve) does not accumulate open
// descriptors across many mutations.
func (l *storeLock) release() error {
	return l.f.Close()
}
