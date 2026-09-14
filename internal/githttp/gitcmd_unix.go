//go:build unix

package githttp

import (
	"errors"
	"os/exec"
	"syscall"
)

// setupProcessGroup configures cmd to run in its own process group, and sets
// cmd.Cancel to SIGKILL the entire process group when the context is cancelled.
//
// walden runs as PID 1 in a container. When git forks child processes (such as
// git-pack-objects during upload-pack or git-index-pack and hooks during
// receive-pack), standard exec.CommandContext kills only the immediate git
// process on context cancellation. Without process group termination, those
// grandchildren survive, reparent to PID 1 (walden), and become orphaned.
//
// Setting Setpgid: true puts the child in a new process group whose PGID equals
// its PID. cmd.Cancel sends SIGKILL to -pid (the process group). If the process
// group has already exited by the time Cancel runs, syscall.Kill returns ESRCH
// (or EPERM on Darwin/BSD); Cancel returns nil so these do not surface as a
// phantom error from Wait.
func setupProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.EPERM) {
			return nil
		}
		return err
	}
}
