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
// operator typed the flag, so this must not silently fall through to
// "no journal configured" and it must not panic on an empty URL either.
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
}

// TestRunUsageListsRotateKey covers "how to know it worked" item 6's third
// clause: `walden help` lists rotate-key.
func TestRunUsageListsRotateKey(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"walden", "help"}, &stdout, &stderr); err != nil {
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
	err := run(context.Background(), []string{"walden", "rotate-key", "--data-dir", dataDir}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected a refusal (no journal configured), got nil")
	}
}
