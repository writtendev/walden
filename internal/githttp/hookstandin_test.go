package githttp_test

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testHookDirectiveFile is the file a test writes into a bare repository to
// tell the stand-in hook below how to behave on that repository's next
// push. Its absence means "accept the push".
const testHookDirectiveFile = "walden-test-hook"

// TestMain lets this test binary stand in for the walden binary when git
// runs it as a repository's pre-receive hook.
//
// store.EnsureHook installs hooks/pre-receive as a symlink to
// os.Executable(), which under `go test` is this binary — so every real
// `git push` in this package now execs it. A Go test binary exec'd with no
// arguments runs its entire suite, which would re-enter this package's own
// tests as a subprocess of git, pushing again from inside each one.
// Dispatching on argv[0] before anything else is how the real binary keeps
// one program serving two jobs (cmd/walden/main.go); this is that same
// mechanism in test clothing.
func TestMain(m *testing.M) {
	if filepath.Base(os.Args[0]) == "pre-receive" {
		os.Exit(runStandInHook())
	}
	os.Exit(m.Run())
}

// runStandInHook is the pre-receive hook every push in this package now
// runs. It reads its instructions from the pushed-to repository's
// walden-test-hook file — git runs a hook with the repository as its
// working directory — rather than from a hook script of its own, because a
// script at hooks/pre-receive is precisely what store.EnsureHook refuses:
// an operator's own pre-receive there means walden's never runs.
//
// One directive per line:
//
//	decline <message>   write message to stderr and exit non-zero
//	env <path>          write the hook's environment to path, KEY=VALUE per line
//
// With no directive file it drains stdin and exits 0, accepting the push.
func runStandInHook() int {
	_, _ = io.Copy(io.Discard, os.Stdin)

	raw, err := os.ReadFile(testHookDirectiveFile)
	if errors.Is(err, fs.ErrNotExist) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "stand-in hook: %v\n", err)
		return 1
	}

	code := 0
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		verb, arg, _ := strings.Cut(line, " ")
		switch verb {
		case "decline":
			fmt.Fprintln(os.Stderr, arg)
			code = 1
		case "env":
			if err := os.WriteFile(arg, []byte(strings.Join(os.Environ(), "\n")+"\n"), 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "stand-in hook: %v\n", err)
				code = 1
			}
		default:
			fmt.Fprintf(os.Stderr, "stand-in hook: unknown directive %q\n", line)
			code = 1
		}
	}
	return code
}

// writeHookDirective writes directives into barePath for the stand-in hook
// to read on the next push. It replaces the installHook helper that wrote a
// shell script to hooks/pre-receive: walden owns that path now, and a
// regular file sitting at it is refused rather than run.
func writeHookDirective(t *testing.T, barePath string, directives ...string) {
	t.Helper()

	path := filepath.Join(barePath, testHookDirectiveFile)
	if err := os.WriteFile(path, []byte(strings.Join(directives, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write hook directive: %v", err)
	}
}
