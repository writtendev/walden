// Tests for `walden rotate-key` (WALD-31): dispatch, the journal-less
// refusal, and a full round trip against a fake object storage endpoint.
package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/store/storetest"
)

// TestRunRotateKeyAgainstFakeEndpoint mints a genesis identity through
// runServe (WALD-28), then rotates it through `walden rotate-key`: one line
// naming the retired and active keys, exit 0 -- "how to know it worked"
// item 6's first half.
func TestRunRotateKeyAgainstFakeEndpoint(t *testing.T) {
	dataDir := t.TempDir()
	setJournalCreds(t)
	fake := storetest.New(t)
	journalURL := journalTestJournalURL(fake)

	var bootStdout, bootStderr bytes.Buffer
	if err := runServe(cancelledContext(), []string{
		"--data-dir", dataDir,
		"--listen", "127.0.0.1:0",
		"--journal", journalURL,
	}, &bootStdout, &bootStderr); err != nil {
		t.Fatalf("runServe (mint) failed: %v", err)
	}
	minted := extractIdentityLine(t, bootStdout.String(), "minted")

	var stdout, stderr bytes.Buffer
	if err := runRotateKey([]string{
		"--data-dir", dataDir,
		"--journal", journalURL,
	}, &stdout, &stderr); err != nil {
		t.Fatalf("runRotateKey failed: %v", err)
	}

	out := stdout.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly one line of output, got %d: %q", len(lines), out)
	}
	line := lines[0]
	if !strings.HasPrefix(line, "key rotated: retired ") {
		t.Errorf("output %q does not start with the expected prefix", line)
	}
	if !strings.Contains(line, minted) {
		t.Errorf("output %q does not name the minted key %q as retired", line, minted)
	}
	if !strings.Contains(line, "active ed25519:") {
		t.Errorf("output %q does not name a new active key", line)
	}
}

// TestRunRotateKeyNoJournalRefuses covers "how to know it worked" item 6's
// second half: with no journal configured, rotate-key refuses in one line
// rather than trying to touch a data directory with nothing to rotate.
func TestRunRotateKeyNoJournalRefuses(t *testing.T) {
	t.Setenv("WALDEN_JOURNAL", "")
	dataDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	err := runRotateKey([]string{"--data-dir", dataDir}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "journal") {
		t.Errorf("refusal does not mention the journal: %q", err.Error())
	}
}

// TestRunRotateKeyEmptyJournalFlagRefuses mirrors config.Load's own
// treatment of an explicit but empty --journal: fs.Visit proves the
// operator typed the flag, so this must name the empty flag explicitly
// rather than silently falling through to the generic "no journal
// configured" refusal meant for an unset knob (round 1 minor finding —
// this is the exact behavior the pre-fix version of this test's own
// comment claimed without asserting).
func TestRunRotateKeyEmptyJournalFlagRefuses(t *testing.T) {
	dataDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	err := runRotateKey([]string{"--data-dir", dataDir, "--journal", ""}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "empty value") {
		t.Errorf("refusal does not name the explicitly empty --journal flag: %q", err.Error())
	}
	if strings.Contains(err.Error(), "no journal configured") {
		t.Errorf("refusal fell through to the generic no-journal-configured message: %q", err.Error())
	}
}

// TestRunRotateKeyWhitespaceJournalFlagRefuses covers the same knob's other
// dropped refusal (round 1 minor finding): a --journal value that is
// present but only whitespace must be told apart from both an unset flag
// (journal-less mode) and an explicitly empty one, the way
// config.go's refuseWhitespaceJournal already tells `walden serve` apart.
func TestRunRotateKeyWhitespaceJournalFlagRefuses(t *testing.T) {
	dataDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	err := runRotateKey([]string{"--data-dir", dataDir, "--journal", "   "}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "whitespace") {
		t.Errorf("refusal does not name the whitespace-only --journal value: %q", err.Error())
	}
	if strings.Contains(err.Error(), "no journal configured") {
		t.Errorf("refusal fell through to the generic no-journal-configured message: %q", err.Error())
	}
}

// TestRunRotateKeyWhitespaceJournalEnvRefuses covers the same refusal
// reached through WALDEN_JOURNAL instead of --journal, the route
// `walden rotate-key --journal "$UNSET_VAR"` actually takes when the
// variable is set but blank -- the exact operator mistake the round 1
// finding named.
func TestRunRotateKeyWhitespaceJournalEnvRefuses(t *testing.T) {
	t.Setenv("WALDEN_JOURNAL", "   ")
	dataDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	err := runRotateKey([]string{"--data-dir", dataDir}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "whitespace") {
		t.Errorf("refusal does not name the whitespace-only WALDEN_JOURNAL value: %q", err.Error())
	}
	if strings.Contains(err.Error(), "no journal configured") {
		t.Errorf("refusal fell through to the generic no-journal-configured message: %q", err.Error())
	}
}

// TestRunRotateKeyIgnoresUnrelatedConfigValidation is round 2's minor
// finding: threading --journal through config.Load also inherits
// Config.Validate, which checks --listen, --auth-trust, and --data-dir --
// three knobs rotate-key neither binds nor reads back out of the *Config
// it gets. Reproduces the finding's own repro (WALDEN_LISTEN=8080, a
// stray port with no host that Validate rejects, and a whitespace-only
// WALDEN_AUTH_TRUST) against a real rotation end to end: neither should
// block a key rotation with a refusal about a knob this command never
// uses.
func TestRunRotateKeyIgnoresUnrelatedConfigValidation(t *testing.T) {
	dataDir := t.TempDir()
	setJournalCreds(t)
	fake := storetest.New(t)
	journalURL := journalTestJournalURL(fake)

	var bootStdout, bootStderr bytes.Buffer
	if err := runServe(cancelledContext(), []string{
		"--data-dir", dataDir,
		"--listen", "127.0.0.1:0",
		"--journal", journalURL,
	}, &bootStdout, &bootStderr); err != nil {
		t.Fatalf("runServe (mint) failed: %v", err)
	}

	t.Setenv("WALDEN_LISTEN", "8080")
	t.Setenv("WALDEN_AUTH_TRUST", "   ")

	var stdout, stderr bytes.Buffer
	if err := runRotateKey([]string{
		"--data-dir", dataDir,
		"--journal", journalURL,
	}, &stdout, &stderr); err != nil {
		t.Fatalf("runRotateKey refused over an unrelated listen/auth-trust config value: %v", err)
	}
	if !strings.HasPrefix(stdout.String(), "key rotated: retired ") {
		t.Errorf("output %q does not start with the expected prefix", stdout.String())
	}
}

// TestRunUsageListsRotateKey covers "how to know it worked" item 6's third
// clause: `walden help` lists rotate-key.
func TestRunUsageListsRotateKey(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"walden", "help"}, strings.NewReader(""), &stdout, &stderr); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if !strings.Contains(stdout.String(), "rotate-key") {
		t.Errorf("usage output does not mention rotate-key:\n%s", stdout.String())
	}
}

// TestRunDispatchesRotateKey covers the top-level argv dispatch case
// (main.go's switch), not just calling runRotateKey directly.
func TestRunDispatchesRotateKey(t *testing.T) {
	t.Setenv("WALDEN_JOURNAL", "")
	dataDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	err := run(context.Background(), []string{"walden", "rotate-key", "--data-dir", dataDir}, strings.NewReader(""), &stdout, &stderr)
	if err == nil {
		t.Fatal("expected a refusal (no journal configured), got nil")
	}
}
