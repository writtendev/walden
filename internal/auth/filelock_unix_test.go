//go:build unix

package auth_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/auth"
)

// TestFileTokenStoreLockWaitCancelledRefusal pins the wording of the refusal
// acquireStoreLock (internal/auth/filelock_unix.go) produces when the ctx a
// caller passed in is cancelled while it is waiting on tokens.lock. In
// production the only caller that ever threads a cancellable ctx this deep
// is `walden serve` boot, whose ctx comes from signal.NotifyContext -- so
// this path is reached exactly when an operator signals serve (Ctrl-C,
// `docker stop`) while it is waiting for the token store lock during boot.
//
// Round 3 review on WALD-112's PR flagged the previous wording --
// "another walden process is writing the token store; retry once it is
// not shutting down" -- for blaming the wrong process: the process that is
// shutting down is this one, asked to stop by the operator's own signal,
// not whichever process holds the lock. The refusal now says truthfully
// that boot itself was interrupted.
func TestFileTokenStoreLockWaitCancelledRefusal(t *testing.T) {
	dataDir := t.TempDir()
	lockPath := filepath.Join(dataDir, "tokens.lock")

	// Hold tokens.lock from an independent file descriptor so
	// acquireStoreLock's non-blocking flock attempt inside CreateToken
	// keeps failing with EWOULDBLOCK and falls into its ctx-aware wait.
	holder, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("open lock file: %v", err)
	}
	defer holder.Close()
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatalf("flock: %v", err)
	}

	store := auth.NewFileTokenStore(dataDir)
	scopes, err := auth.ParseScopes([]string{"rwc:*"})
	if err != nil {
		t.Fatalf("ParseScopes: %v", err)
	}
	_, hash, err := auth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err = store.CreateToken(ctx, &auth.TokenRecord{
		TokenID:   "tok_lock_wait_cancelled",
		TokenHash: hash,
		Scopes:    scopes,
		CreatedAt: time.Now().UTC(),
	})
	if err == nil {
		t.Fatalf("expected CreateToken to be refused once ctx is cancelled while waiting on tokens.lock")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected error to wrap context.Canceled, got: %v", err)
	}

	got := err.Error()
	if strings.Contains(got, "\n") {
		t.Errorf("expected single-line refusal, got: %q", got)
	}

	want := "boot interrupted: stop signal received while waiting for " + lockPath + " (retry once the token store lock is free)"
	if got != want {
		t.Errorf("refusal wording = %q, want %q", got, want)
	}
	if strings.Contains(got, "another walden process") {
		t.Errorf("refusal must not blame another process for shutting down, got: %q", got)
	}
}
