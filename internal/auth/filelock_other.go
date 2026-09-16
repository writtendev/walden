//go:build !unix

package auth

import (
	"context"

	"github.com/writtendev/walden/internal/refusal"
)

// storeLock has no implementation outside unix. walden ships in a Linux container and is
// developed on darwin — both unix, both with flock(2) — so a portable cross-process locking
// layer has no user; refusing loudly here is the honest, small option AGENTS.md asks for
// over building one nothing in production needs.
type storeLock struct{}

// acquireStoreLock always refuses on a non-unix platform: there is no lock to take. ctx is
// accepted only to match the unix build's signature (see filelock_unix.go); it is never
// consulted since this always returns before there is anything to wait on.
func acquireStoreLock(ctx context.Context, path string) (*storeLock, error) {
	return nil, refusal.Refuse(
		"token store locked",
		"cross-process locking is only implemented for unix",
		"run walden on a unix platform (linux or darwin)",
	)
}

// release is a no-op: acquireStoreLock never returns a *storeLock on this platform.
func (l *storeLock) release() error { return nil }
