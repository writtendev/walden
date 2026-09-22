//go:build unix

package store

import (
	"errors"
	"os/exec"
	"syscall"
)

// setupProcessGroup configures cmd to run in its own process group, and sets
// cmd.Cancel to SIGKILL the entire process group when the context is
// cancelled.
//
// It is githttp's setupProcessGroup, for the reason that one exists: walden
// runs as PID 1 in a container, where killing only the immediate child leaves
// any grandchild it forked to reparent onto walden and never be reaped.
// Setpgid puts the child in its own group and Cancel signals -pid, so the
// whole group goes together and nothing survives to be orphaned. ESRCH (EPERM
// on darwin and the BSDs) means the group was already gone, which is not an
// error worth surfacing out of Wait.
//
// The two copies cannot be one: githttp imports store, so store importing
// githttp would be a cycle, and AGENTS.md's layout rule says no package
// imports another in one.
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
