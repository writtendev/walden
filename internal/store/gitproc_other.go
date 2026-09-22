//go:build !unix

package store

import "os/exec"

// setupProcessGroup is a no-op outside unix: it leaves os/exec's default
// process cancellation in place.
func setupProcessGroup(cmd *exec.Cmd) {
}
