package main

import (
	"bytes"
	"context"
	"errors"
	"go/parser"
	"go/token"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/store"
	"github.com/writtendev/walden/internal/store/storetest"
)

// cancelledContext returns a context that is already done, so a caller
// (like runServe's own goroutine that closes the listener on ctx.Done())
// observes it as immediately cancelled. Note this must never be threaded
// into githttp.AssertGitFloor: exec.CommandContext refuses to even start
// a subprocess against an already-done context, which is exactly why
// runServe uses context.Background() for that one preflight check
// instead of the ctx it is otherwise threaded through with.
func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestRunUsageAndVersion(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		useTempDataDir bool
		wantErr        bool
		wantOutSub     string
		wantErrSub     string
	}{
		{
			name:           "empty-args-defaults-to-serve",
			args:           []string{},
			useTempDataDir: true,
			wantErr:        false,
			wantOutSub:     "walden server starting",
		},
		{
			name:           "default-serve-when-single-arg",
			args:           []string{"walden"},
			useTempDataDir: true,
			wantErr:        false,
			wantOutSub:     "walden server starting",
		},
		{
			name:           "serve-subcommand",
			args:           []string{"walden", "serve"},
			useTempDataDir: true,
			wantErr:        false,
			wantOutSub:     "walden server starting",
		},
		{
			name:       "serve-print-config-default",
			args:       []string{"walden", "serve", "--print-config"},
			wantErr:    false,
			wantOutSub: "data-dir: /data\njournal: (disabled)\nauth-trust: (builtin)\nlisten: :8470",
		},
		{
			name:       "serve-print-config-custom-flags",
			args:       []string{"walden", "serve", "--data-dir", "/custom/data", "--listen", ":9090", "--print-config"},
			wantErr:    false,
			wantOutSub: "data-dir: /custom/data\njournal: (disabled)\nauth-trust: (builtin)\nlisten: :9090",
		},
		{
			name:       "serve-direct-flag-print-config",
			args:       []string{"walden", "--print-config"},
			wantErr:    false,
			wantOutSub: "data-dir: /data\njournal: (disabled)\nauth-trust: (builtin)\nlisten: :8470",
		},
		{
			name:       "serve-invalid-listen-flag",
			args:       []string{"walden", "serve", "--listen", "not-a-port"},
			wantErr:    true,
			wantErrSub: "invalid listen:",
		},
		{
			name:       "serve-empty-journal-flag",
			args:       []string{"walden", "serve", "--journal", "", "--print-config"},
			wantErr:    true,
			wantErrSub: "invalid journal:",
		},
		{
			name:       "version",
			args:       []string{"walden", "version"},
			wantErr:    false,
			wantOutSub: "walden dev",
		},
		{
			name:       "version-flag",
			args:       []string{"walden", "--version"},
			wantErr:    false,
			wantOutSub: "walden dev",
		},
		{
			name:       "version-short-flag",
			args:       []string{"walden", "-v"},
			wantErr:    false,
			wantOutSub: "walden dev",
		},
		{
			name:       "help",
			args:       []string{"walden", "help"},
			wantErr:    false,
			wantOutSub: "Usage:",
		},
		{
			name:       "help-flag",
			args:       []string{"walden", "--help"},
			wantErr:    false,
			wantOutSub: "Usage:",
		},
		{
			name:       "help-short-flag",
			args:       []string{"walden", "-h"},
			wantErr:    false,
			wantOutSub: "Usage:",
		},
		{
			name:       "unknown-command",
			args:       []string{"walden", "invalid-command"},
			wantErr:    true,
			wantErrSub: "unknown command: invalid-command (run 'walden help' for usage)",
		},
		{
			name:    "pre-receive-argv0-base",
			args:    []string{"pre-receive"},
			wantErr: false,
		},
		{
			name:    "pre-receive-argv0-path",
			args:    []string{"/data/repos/my-repo.git/hooks/pre-receive"},
			wantErr: false,
		},
		{
			name:    "pre-receive-subcommand",
			args:    []string{"walden", "pre-receive"},
			wantErr: false,
		},
		{
			name:       "token-missing-subcommand",
			args:       []string{"walden", "token"},
			wantErr:    true,
			wantErrSub: "missing token subcommand",
		},
		{
			name:           "token-create",
			args:           []string{"walden", "token", "create"},
			useTempDataDir: true,
			wantErr:        false,
			wantOutSub:     "walden_",
		},
		{
			name:           "token-list",
			args:           []string{"walden", "token", "list"},
			useTempDataDir: true,
			wantErr:        false,
			wantOutSub:     "ID",
		},
		{
			name:           "token-revoke-missing-id",
			args:           []string{"walden", "token", "revoke"},
			useTempDataDir: true,
			wantErr:        true,
			wantErrSub:     "missing token id: no token id specified",
		},
		{
			name:       "token-unknown-subcommand",
			args:       []string{"walden", "token", "bogus"},
			wantErr:    true,
			wantErrSub: "unknown token subcommand: bogus (expected create, list, or revoke)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.useTempDataDir {
				t.Setenv("WALDEN_DATA_DIR", t.TempDir())
				// Only the serve cases in this table reach the listener;
				// 127.0.0.1:0 keeps them from racing each other (or a
				// concurrent test) for the default :8470 port.
				t.Setenv("WALDEN_LISTEN_ADDR", "127.0.0.1:0")
			}
			var stdout, stderr bytes.Buffer
			err := run(cancelledContext(), tt.args, strings.NewReader(""), &stdout, &stderr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("run(%v) error = %v, wantErr %v", tt.args, err, tt.wantErr)
			}
			if tt.wantErr && tt.wantErrSub != "" {
				if !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Errorf("run(%v) error = %q, expected substring %q", tt.args, err.Error(), tt.wantErrSub)
				}
			}
			if tt.wantOutSub != "" {
				if !strings.Contains(stdout.String(), tt.wantOutSub) {
					t.Errorf("run(%v) stdout = %q, expected substring %q", tt.args, stdout.String(), tt.wantOutSub)
				}
			}
		})
	}
}

func TestRunServeOutputIncludesGitVersion(t *testing.T) {
	t.Setenv("WALDEN_DATA_DIR", t.TempDir())
	var stdout, stderr bytes.Buffer
	err := runServe(cancelledContext(), []string{"--listen", "127.0.0.1:0"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runServe failed: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "walden server starting on 127.0.0.1:") {
		t.Errorf("expected listen address in output, got %q", out)
	}
	if !strings.Contains(out, "git: ") {
		t.Errorf("expected git version in output, got %q", out)
	}
}

func TestRunServeGitFloorRefusal(t *testing.T) {
	tmpDir := t.TempDir()
	fakeGit := filepath.Join(tmpDir, "git")

	script := "#!/bin/sh\necho 'git version 2.20.0'\n"
	if err := os.WriteFile(fakeGit, []byte(script), 0o755); err != nil {
		t.Fatalf("failed to write fake git script: %v", err)
	}

	origPath := os.Getenv("PATH")
	t.Setenv("PATH", tmpDir)
	defer os.Setenv("PATH", origPath)

	var stdout, stderr bytes.Buffer
	err := runServe(context.Background(), nil, &stdout, &stderr)
	if err == nil {
		t.Fatalf("expected runServe to fail when git is below floor, got success")
	}

	expectedSub := "git version 2.20.0 is below supported floor 2.40.0 (walden requires git >= 2.40.0)"
	if !strings.Contains(err.Error(), expectedSub) {
		t.Errorf("expected error %q to contain %q", err.Error(), expectedSub)
	}
}

// TestSingleBinaryInCodebase asserts that cmd/walden is the only package main in the codebase,
// ensuring there are no separate companion binaries or sidecars.
func TestSingleBinaryInCodebase(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()

	var mainPkgs []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == ".claude" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		file, err := parser.ParseFile(fset, path, nil, parser.PackageClauseOnly)
		if err != nil {
			return err
		}

		if file.Name.Name == "main" {
			dir := filepath.Dir(path)
			relDir, relErr := filepath.Rel(root, dir)
			if relErr != nil {
				relDir = dir
			}
			mainPkgs = append(mainPkgs, relDir)
		}
		return nil
	})

	if err != nil {
		t.Fatalf("error checking for main packages: %v", err)
	}

	// Deduplicate package directories
	uniqueMainDirs := make(map[string]bool)
	for _, dir := range mainPkgs {
		uniqueMainDirs[dir] = true
	}

	if len(uniqueMainDirs) != 1 || !uniqueMainDirs["cmd/walden"] {
		t.Errorf("expected exactly one main package at 'cmd/walden', got: %v", mainPkgs)
	}
}

// TestBinaryArgvDispatch builds the actual walden executable and exercises
// argv dispatch, symlink execution, flags, and --print-config end-to-end.
func TestBinaryArgvDispatch(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "walden")

	// Build the real binary
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\nOutput: %s", err, string(out))
	}

	// Create symlink for pre-receive hook personality
	hookPath := filepath.Join(tmpDir, "pre-receive")
	if err := os.Symlink(binPath, hookPath); err != nil {
		t.Fatalf("failed to create pre-receive symlink: %v", err)
	}

	tests := []struct {
		name       string
		cmdPath    string
		args       []string
		env        []string
		wantExit0  bool
		wantOutSub string
		wantErrSub string
		// wantErrNot are strings stderr must not contain: the credentials
		// out of a journal URL, and the fragments a leak arrives in.
		wantErrNot []string
	}{
		{
			name:       "direct-version",
			cmdPath:    binPath,
			args:       []string{"version"},
			wantExit0:  true,
			wantOutSub: "walden dev",
		},
		{
			name:       "direct-help",
			cmdPath:    binPath,
			args:       []string{"help"},
			wantExit0:  true,
			wantOutSub: "Usage:",
		},
		{
			name:       "direct-token-create",
			cmdPath:    binPath,
			args:       []string{"token", "create"},
			env:        append(os.Environ(), "WALDEN_DATA_DIR="+t.TempDir()),
			wantExit0:  true,
			wantOutSub: "walden_",
		},
		{
			name:       "direct-unknown-command",
			cmdPath:    binPath,
			args:       []string{"nonexistent"},
			wantExit0:  false,
			wantErrSub: "unknown command: nonexistent",
		},
		{
			name:       "direct-token-missing-subcmd",
			cmdPath:    binPath,
			args:       []string{"token"},
			wantExit0:  false,
			wantErrSub: "missing token subcommand",
		},
		{
			name:      "symlink-pre-receive",
			cmdPath:   hookPath,
			args:      []string{},
			wantExit0: true,
		},
		{
			name:      "subcommand-pre-receive",
			cmdPath:   binPath,
			args:      []string{"pre-receive"},
			wantExit0: true,
		},
		{
			name:       "serve-print-config-flags",
			cmdPath:    binPath,
			args:       []string{"serve", "--data-dir", "/test/cache", "--journal", "s3://my-bucket/w", "--listen", ":8888", "--print-config"},
			wantExit0:  true,
			wantOutSub: "data-dir: /test/cache\njournal: (configured)\nauth-trust: (builtin)\nlisten: :8888",
		},
		{
			name:       "serve-print-config-env",
			cmdPath:    binPath,
			args:       []string{"serve", "--print-config"},
			env:        append(os.Environ(), "WALDEN_DATA_DIR=/env/dir", "WALDEN_LISTEN_ADDR=:7777"),
			wantExit0:  true,
			wantOutSub: "data-dir: /env/dir\njournal: (disabled)\nauth-trust: (builtin)\nlisten: :7777",
		},
		{
			name:       "serve-invalid-config-flag-exits-error",
			cmdPath:    binPath,
			args:       []string{"serve", "--listen", ":invalid-port"},
			wantExit0:  false,
			wantErrSub: "walden: invalid listen:",
		},
		{
			// The journal URL is resolved at boot, so a malformed one
			// stops walden now rather than on the first push.
			name:       "serve-malformed-journal-exits-error",
			cmdPath:    binPath,
			args:       []string{"serve", "--journal", "ftp://example.org/my-bucket"},
			wantExit0:  false,
			wantErrSub: "walden: invalid journal: unsupported URL scheme \"ftp\"",
		},
		{
			// --print-config resolves the location but not the
			// credentials, so a URL can be checked on a machine that
			// holds no secrets.
			name:      "serve-print-config-resolved-journal",
			cmdPath:   binPath,
			args:      []string{"serve", "--journal", "https://storage.googleapis.com/my-bucket/walden", "--print-config"},
			wantExit0: true,
			wantOutSub: "journal-provider: Google Cloud Storage\n" +
				"journal-endpoint: https://storage.googleapis.com\n" +
				"journal-region: auto\n" +
				"journal-bucket: my-bucket\n" +
				"journal-prefix: walden\n" +
				"journal-style: path",
		},
		{
			// Config.String() does not render the journal URL. Printing
			// it meant a second, weaker copy of guardCredentials living
			// in internal/config, and that copy half-redacted a password
			// holding an unencoded '/'. The location an operator needs
			// comes from Journal.String(), past the one gate.
			name:      "serve-print-config-withholds-the-journal-url",
			cmdPath:   binPath,
			args:      []string{"serve", "--journal", "http://minioadmin:p@ss/w0rd@minio.internal:9000/my-bucket/walden", "--print-config"},
			wantExit0: false,
			// The relocated '@' is refused by the gate, and nothing of
			// the URL is echoed on the way out.
			wantErrSub: "walden: invalid journal: URL has an '@' after its credentials end; it is not echoed because it may carry credentials",
			wantErrNot: []string{"p@ss", "ss/w0rd", "w0rd", "minio.internal"},
		},
		{
			// The access key ID is a public identifier and --print-config
			// prints it on purpose, built from the resolved
			// Credentials.AccessKeyID rather than by re-rendering the URL.
			// The secret stays forbidden.
			name:       "serve-print-config-prints-key-id-not-secret",
			cmdPath:    binPath,
			args:       []string{"serve", "--journal", "s3://AKIAEXAMPLE:topsecret@my-bucket/walden", "--print-config"},
			wantExit0:  true,
			wantOutSub: "journal-credentials: WALDEN_JOURNAL URL\njournal-access-key-id: AKIAEXAMPLE",
			wantErrNot: []string{"topsecret"},
		},
		{
			// --print-config names where the credentials come from, so it
			// cannot report an unresolved journal that would in fact boot.
			// It names the source, never the secret, and calling
			// ParseJournalURL rather than ResolveJournal means it never
			// reads the environment's access key ID either.
			name:    "serve-print-config-names-the-credential-source",
			cmdPath: binPath,
			args:    []string{"serve", "--journal", "s3://my-bucket/walden", "--print-config"},
			env: append(os.Environ(),
				"AWS_ACCESS_KEY_ID=AKIAEXAMPLE",
				"AWS_SECRET_ACCESS_KEY=topsecret",
			),
			wantExit0:  true,
			wantOutSub: "journal-credentials: AWS_ACCESS_KEY_ID",
			wantErrNot: []string{"AKIAEXAMPLE", "topsecret"},
		},
		{
			// A self-hosted endpoint written as s3://host:port silently
			// resolved to a bucket named "minio.local" at Amazon.
			name:       "serve-s3-scheme-with-port-exits-error",
			cmdPath:    binPath,
			args:       []string{"serve", "--journal", "s3://minio.local:9000/my-bucket/walden"},
			wantExit0:  false,
			wantErrSub: "walden: invalid journal: s3:// URL carries a port, but s3:// always addresses AWS",
		},
		{
			// The whole point of the boot-path resolution is that a
			// journal URL never reaches an operator's log. An unencoded
			// '/' in the secret ends the authority before the '@', so
			// net/url reports no error and moves the rest of the secret
			// into the prefix, where the refusal used to quote it.
			name:       "serve-relocated-credentials-are-not-echoed",
			cmdPath:    binPath,
			args:       []string{"serve", "--journal", "s3://PUBLICKEYIDEXAMPLE:/zzTOPSECRETzz@bucket/prefix"},
			wantExit0:  false,
			wantErrSub: "walden: invalid journal: URL has an '@' after its credentials end; it is not echoed because it may carry credentials",
			wantErrNot: []string{"zzTOPSECRETzz", "zzT", "PUBLICKEYIDEXAMPLE"},
		},
		{
			// A trailing newline is what a file-backed Kubernetes secret
			// or a .env line gives you, and it is the likeliest cause of
			// a "malformed" journal URL. It is trimmed, not refused.
			name:    "serve-print-config-trims-the-journal-url",
			cmdPath: binPath,
			// Config.String() no longer echoes the URL, so the proof that
			// the trim happened is that the padded value resolved.
			args:      []string{"serve", "--journal", " s3://my-bucket/walden\n", "--print-config"},
			wantExit0: true,
			wantOutSub: "journal: (configured)\n" +
				"auth-trust: (builtin)\n" +
				"listen: :8470\n" +
				"journal-provider: AWS S3\n" +
				"journal-endpoint: https://s3.us-east-1.amazonaws.com\n" +
				"journal-region: us-east-1\n" +
				"journal-bucket: my-bucket",
		},
		{
			// The other half of the trim: a value that is nothing but
			// whitespace was trimmed away to unset, and walden booted
			// journal-less and silent. A secret file holding one newline
			// is a mistake, not a decision to run without durability.
			name:       "serve-whitespace-only-journal-exits-error",
			cmdPath:    binPath,
			args:       []string{"serve"},
			env:        append(os.Environ(), "WALDEN_JOURNAL=   "),
			wantExit0:  false,
			wantErrSub: "walden: invalid journal: value is only whitespace",
		},
		{
			name:       "serve-whitespace-only-journal-flag-exits-error",
			cmdPath:    binPath,
			args:       []string{"serve", "--journal", "\n", "--print-config"},
			wantExit0:  false,
			wantErrSub: "walden: invalid journal: value is only whitespace",
		},
		{
			// FIPS endpoints are mandatory for GovCloud and FedRAMP, and
			// the modifier sits where the legacy s3-<region> form puts
			// the region. This booted and signed with region "fips".
			name:       "serve-print-config-fips-endpoint-region",
			cmdPath:    binPath,
			args:       []string{"serve", "--journal", "https://s3-fips.us-east-1.amazonaws.com/my-bucket/walden", "--print-config"},
			wantExit0:  true,
			wantOutSub: "journal-region: us-east-1",
		},
		{
			// One accelerate endpoint fronts every region, so there is no
			// region to read and no default that is not a guess.
			name:       "serve-accelerate-endpoint-exits-error",
			cmdPath:    binPath,
			args:       []string{"serve", "--journal", "https://s3-accelerate.amazonaws.com/my-bucket/walden"},
			wantExit0:  false,
			wantErrSub: "walden: invalid journal: endpoint host \"s3-accelerate.amazonaws.com\" fronts every region and names none",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(tt.cmdPath, tt.args...)
			if tt.env != nil {
				cmd.Env = tt.env
			}
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			if tt.wantExit0 && err != nil {
				t.Fatalf("command %s %v failed unexpectedly: %v\nstderr: %s", tt.cmdPath, tt.args, err, stderr.String())
			}
			if !tt.wantExit0 && err == nil {
				t.Fatalf("command %s %v succeeded, expected failure", tt.cmdPath, tt.args)
			}
			if tt.wantOutSub != "" && !strings.Contains(stdout.String(), tt.wantOutSub) {
				t.Errorf("stdout = %q, want substring %q", stdout.String(), tt.wantOutSub)
			}
			if tt.wantErrSub != "" && !strings.Contains(stderr.String(), tt.wantErrSub) {
				t.Errorf("stderr = %q, want substring %q", stderr.String(), tt.wantErrSub)
			}
			for _, leak := range tt.wantErrNot {
				if strings.Contains(stdout.String(), leak) || strings.Contains(stderr.String(), leak) {
					t.Errorf("output leaked %q: stdout %q, stderr %q", leak, stdout.String(), stderr.String())
				}
			}
		})
	}
}

// TestBinaryPreReceiveRealTriplesExitsZero drives the actual walden binary
// as git's pre-receive hook through the pre-receive symlink (WALD-43),
// with WALDEN_REPO/WALDEN_DATA_DIR naming a repository that really exists
// on disk and a well-formed ref update triple on stdin. It must exit 0
// with no output at all: a green pre-receive is silent, and WALD-43 stops
// deliberately short of journaling anything.
func TestBinaryPreReceiveRealTriplesExitsZero(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "walden")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	hookPath := filepath.Join(tmpDir, "pre-receive")
	if err := os.Symlink(binPath, hookPath); err != nil {
		t.Fatalf("symlink pre-receive hook: %v", err)
	}

	dataDir := t.TempDir()
	repoPath := filepath.Join(dataDir, "hookrepo.git")
	if out, err := exec.Command("git", "init", "-q", "--bare", "--initial-branch=main", repoPath).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v\n%s", err, out)
	}

	cmd := exec.Command(hookPath)
	cmd.Env = append(os.Environ(), "WALDEN_REPO=hookrepo", "WALDEN_DATA_DIR="+dataDir)
	cmd.Stdin = strings.NewReader("0000000000000000000000000000000000000000 4b825dc642cb6eb9a060e54bf8d69288fbee4904 refs/heads/main\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("pre-receive exited non-zero: %v\nstderr: %s", err, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("expected no stdout, got %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("expected no stderr, got %q", stderr.String())
	}
}

// TestBinaryPreReceiveMalformedLineRefuses drives the actual walden binary
// as the pre-receive hook with a stdin line that cannot be split into
// old_oid/new_oid/ref: it must exit 1 and print exactly one line on
// stderr, per AGENTS.md's "every operator-facing refusal is one line".
func TestBinaryPreReceiveMalformedLineRefuses(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "walden")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	hookPath := filepath.Join(tmpDir, "pre-receive")
	if err := os.Symlink(binPath, hookPath); err != nil {
		t.Fatalf("symlink pre-receive hook: %v", err)
	}

	cmd := exec.Command(hookPath)
	cmd.Stdin = strings.NewReader("not-a-valid-pre-receive-line\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err == nil {
		t.Fatalf("expected pre-receive to exit non-zero for a malformed line")
	}
	if stdout.Len() != 0 {
		t.Errorf("expected no stdout, got %q", stdout.String())
	}
	errOut := strings.TrimRight(stderr.String(), "\n")
	const wantPrefix = "walden: pre-receive refused:"
	if !strings.HasPrefix(errOut, wantPrefix) {
		t.Errorf("stderr = %q, want prefix %q", errOut, wantPrefix)
	}
	if strings.Contains(errOut, "\n") {
		t.Errorf("expected a single-line refusal, got: %q", stderr.String())
	}
}

// TestDockerfilePinsAndEntrypoint parses Dockerfile and asserts pinning and configuration rules.
func TestDockerfilePinsAndEntrypoint(t *testing.T) {
	dockerfilePath := filepath.Join("..", "..", "Dockerfile")
	content, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatalf("failed to read Dockerfile: %v", err)
	}

	dockerfile := string(content)

	// Assert FROM lines have pinned sha256 digests
	fromLines := []string{}
	for _, line := range strings.Split(dockerfile, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "FROM ") {
			fromLines = append(fromLines, trimmed)
		}
	}

	if len(fromLines) < 2 {
		t.Fatalf("expected multi-stage build with at least 2 FROM lines, found %d", len(fromLines))
	}

	// Assert builder stage has pinned digest
	if !strings.Contains(fromLines[0], "@sha256:") {
		t.Errorf("builder FROM line %q does not pin image by @sha256: digest", fromLines[0])
	}

	// Assert runtime stage has pinned git image digest
	if !strings.Contains(fromLines[1], "alpine/git:2.47.2@sha256:") {
		t.Errorf("runtime FROM line %q does not pin alpine/git:2.47.2 by @sha256: digest", fromLines[1])
	}

	// Assert ENTRYPOINT is ["walden", "serve"]
	if !strings.Contains(dockerfile, `ENTRYPOINT ["walden", "serve"]`) {
		t.Errorf("Dockerfile missing expected ENTRYPOINT [\"walden\", \"serve\"]")
	}

	// Assert VOLUME is ["/data"]
	if !strings.Contains(dockerfile, `VOLUME ["/data"]`) {
		t.Errorf("Dockerfile missing expected VOLUME [\"/data\"]")
	}

	// Assert EXPOSE 8470
	if !strings.Contains(dockerfile, `EXPOSE 8470`) {
		t.Errorf("Dockerfile missing expected EXPOSE 8470")
	}
}

// TestConfigImportsNothingInternal verifies the architectural rule that
// internal/config must import no internal packages.
func TestConfigImportsNothingInternal(t *testing.T) {
	configDir := filepath.Join("..", "..", "internal", "config")
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, configDir, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("failed to parse config package: %v", err)
	}

	for _, pkg := range pkgs {
		for filename, file := range pkg.Files {
			if strings.HasSuffix(filename, "_test.go") {
				continue
			}
			for _, imp := range file.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				if strings.Contains(path, "github.com/writtendev/walden/internal") {
					t.Errorf("file %s imports internal package %q; config must import nothing internal", filename, path)
				}
			}
		}
	}
}

// TestNoExternalDependencies verifies that the codebase only uses Go standard library packages.
func TestNoExternalDependencies(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == ".claude" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}

		for _, imp := range file.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			// Standard library packages do not have a dot in the first path element
			firstElem := strings.Split(importPath, "/")[0]
			if strings.Contains(firstElem, ".") && !strings.HasPrefix(importPath, "github.com/writtendev/walden") {
				t.Errorf("file %s imports external dependency %q; no external dependencies are permitted", path, importPath)
			}
		}
		return nil
	})

	if err != nil {
		t.Fatalf("error checking dependencies: %v", err)
	}
}

// TestGoModNoExternalDependencies verifies that go.mod contains no external dependencies.
func TestGoModNoExternalDependencies(t *testing.T) {
	goModPath := filepath.Join("..", "..", "go.mod")
	data, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("failed to read go.mod: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	inRequireBlock := false
	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if trimmed == "require (" {
			inRequireBlock = true
			t.Errorf("go.mod:%d: unauthorized require block found; no external dependencies permitted", lineNum+1)
			continue
		}
		if inRequireBlock {
			if trimmed == ")" {
				inRequireBlock = false
			} else {
				t.Errorf("go.mod:%d: unauthorized require entry %q found; no external dependencies permitted", lineNum+1, trimmed)
			}
			continue
		}
		if strings.HasPrefix(trimmed, "require ") {
			t.Errorf("go.mod:%d: unauthorized require directive %q found; no external dependencies permitted", lineNum+1, trimmed)
		}
	}
}

// TestNoStackTraceOrWrappedChainToOperator asserts that all CLI error paths produce
// a single-line refusal and never emit stack traces, panics, or multiline error dumps to stderr.
func TestNoStackTraceOrWrappedChainToOperator(t *testing.T) {
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "walden")

	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\nOutput: %s", err, string(out))
	}

	invalidInvocations := []struct {
		name string
		args []string
	}{
		{
			name: "unknown-subcommand",
			args: []string{"nonexistent-cmd"},
		},
		{
			name: "token-missing-subcommand",
			args: []string{"token"},
		},
		{
			name: "token-unknown-subcommand",
			args: []string{"token", "invalid-subcmd"},
		},
	}

	for _, tc := range invalidInvocations {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(binPath, tc.args...)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			if err == nil {
				t.Fatalf("expected command %v to fail, but it exited 0", tc.args)
			}

			errOutput := stderr.String()
			if errOutput == "" {
				t.Fatalf("expected stderr output for failed command %v, got empty", tc.args)
			}

			// Must be prefixed by "walden: "
			if !strings.HasPrefix(errOutput, "walden: ") {
				t.Errorf("stderr = %q, expected prefix 'walden: '", errOutput)
			}

			// Must be strictly one line (excluding trailing newline)
			trimmed := strings.TrimRight(errOutput, "\r\n")
			if strings.Contains(trimmed, "\n") || strings.Contains(trimmed, "\r") {
				t.Errorf("operator error for %v contains multiple lines:\n%s", tc.args, errOutput)
			}

			// Must not contain stack trace signatures or panics
			forbiddenSignatures := []string{
				"goroutine ",
				"panic:",
				"runtime.",
				".go:",
				"[running]:",
			}
			for _, sig := range forbiddenSignatures {
				if strings.Contains(errOutput, sig) {
					t.Errorf("operator error contains forbidden stack trace / internal artifact %q: %q", sig, errOutput)
				}
			}
		})
	}
}

// TestRefusalConventionFormat asserts that all refusals produced by walden
// follow the standard format: "<what>: <why> (<fix>)".
func TestRefusalConventionFormat(t *testing.T) {
	errUnknown := run(context.Background(), []string{"walden", "invalid"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if errUnknown == nil {
		t.Fatal("expected error")
	}
	errStr := errUnknown.Error()
	if !strings.Contains(errStr, ": ") || !strings.Contains(errStr, "(") || !strings.HasSuffix(errStr, ")") {
		t.Errorf("refusal format mismatch: %q (expected '<what>: <why> (<fix>)')", errStr)
	}

	errToken := run(context.Background(), []string{"walden", "token"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if errToken == nil {
		t.Fatal("expected error")
	}
	tokenErrStr := errToken.Error()
	if !strings.Contains(tokenErrStr, ": ") || !strings.Contains(tokenErrStr, "(") || !strings.HasSuffix(tokenErrStr, ")") {
		t.Errorf("refusal format mismatch: %q (expected '<what>: <why> (<fix>)')", tokenErrStr)
	}
}

func TestServeFirstBootMintsAdminToken(t *testing.T) {
	dataDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	err := runServe(cancelledContext(), []string{"--data-dir", dataDir, "--listen", "127.0.0.1:0"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runServe failed: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "admin token: walden_") {
		t.Fatalf("expected stdout to contain 'admin token: walden_', got:\n%s", out)
	}
	if !strings.Contains(out, "walden server starting on 127.0.0.1:") {
		t.Errorf("expected server starting line in output, got:\n%s", out)
	}

	// Verify order: admin token printed before server starting line
	adminIdx := strings.Index(out, "admin token: ")
	startIdx := strings.Index(out, "walden server starting on")
	if adminIdx >= startIdx {
		t.Errorf("expected admin token line before server start line, got adminIdx=%d, startIdx=%d", adminIdx, startIdx)
	}

	// Extract token
	var token string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "admin token: ") {
			token = strings.TrimPrefix(line, "admin token: ")
			break
		}
	}
	if token == "" {
		t.Fatalf("failed to extract admin token from output")
	}

	// Verify tokens.json file exists
	tokensFile := filepath.Join(dataDir, "tokens.json")
	if _, err := os.Stat(tokensFile); err != nil {
		t.Fatalf("expected tokens.json to exist: %v", err)
	}

	store := auth.NewFileTokenStore(dataDir)
	rec, err := store.GetTokenByID(context.Background(), auth.AdminTokenID)
	if err != nil {
		t.Fatalf("failed to get admin token from store: %v", err)
	}
	if rec.TokenHash != auth.HashToken(token) {
		t.Errorf("token hash in store %q != HashToken(%q) = %q", rec.TokenHash, token, auth.HashToken(token))
	}
	if rec.Revoked {
		t.Errorf("expected admin token to not be revoked")
	}

	// Verify the minted token grants rwc:* permissions
	authorizer := auth.NewBuiltinAuthorizer(store)
	ctx := context.Background()
	for _, repo := range []string{"alpha", "bravo-repo"} {
		if err := authorizer.Authorize(ctx, token, auth.Actions{Read: true, Write: true, Create: true}, repo); err != nil {
			t.Errorf("expected rwc:* authorization to succeed for %q, got: %v", repo, err)
		}
	}
}

func TestServeSecondBootDoesNotMintOrPrint(t *testing.T) {
	dataDir := t.TempDir()

	// Boot 1
	var stdout1, stderr1 bytes.Buffer
	if err := runServe(cancelledContext(), []string{"--data-dir", dataDir, "--listen", "127.0.0.1:0"}, &stdout1, &stderr1); err != nil {
		t.Fatalf("first runServe failed: %v", err)
	}
	if !strings.Contains(stdout1.String(), "admin token: walden_") {
		t.Fatalf("first runServe expected admin token line")
	}

	tokensFile := filepath.Join(dataDir, "tokens.json")
	initialContent, err := os.ReadFile(tokensFile)
	if err != nil {
		t.Fatalf("failed to read tokens.json: %v", err)
	}

	// Boot 2
	var stdout2, stderr2 bytes.Buffer
	if err := runServe(cancelledContext(), []string{"--data-dir", dataDir, "--listen", "127.0.0.1:0"}, &stdout2, &stderr2); err != nil {
		t.Fatalf("second runServe failed: %v", err)
	}
	if strings.Contains(stdout2.String(), "admin token: ") {
		t.Errorf("second runServe should not output admin token, got:\n%s", stdout2.String())
	}
	if !strings.Contains(stdout2.String(), "walden server starting on 127.0.0.1:") {
		t.Errorf("second runServe missing server start line, got:\n%s", stdout2.String())
	}

	secondContent, err := os.ReadFile(tokensFile)
	if err != nil {
		t.Fatalf("failed to read tokens.json after second boot: %v", err)
	}
	if string(initialContent) != string(secondContent) {
		t.Errorf("tokens.json changed after second boot:\nInitial: %s\nSecond: %s", initialContent, secondContent)
	}
}

func TestServeDelegatedModeDoesNotMint(t *testing.T) {
	dataDir := t.TempDir()
	_, pub, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}
	trustKey := journal.FormatPublicKey(pub)

	var stdout, stderr bytes.Buffer
	err = runServe(cancelledContext(), []string{"--data-dir", dataDir, "--auth-trust", trustKey, "--listen", "127.0.0.1:0"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runServe with auth-trust failed: %v", err)
	}

	if strings.Contains(stdout.String(), "admin token: ") {
		t.Errorf("delegated mode must not mint or print admin token, got:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "walden server starting on 127.0.0.1:") {
		t.Errorf("delegated mode missing server start line, got:\n%s", stdout.String())
	}

	tokensFile := filepath.Join(dataDir, "tokens.json")
	if _, err := os.Stat(tokensFile); !os.IsNotExist(err) {
		t.Errorf("tokens.json should not exist in delegated mode, stat err: %v", err)
	}
}

func TestServePrintConfigDoesNotMint(t *testing.T) {
	dataDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	err := runServe(context.Background(), []string{"--data-dir", dataDir, "--print-config"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runServe --print-config failed: %v", err)
	}

	if strings.Contains(stdout.String(), "admin token: ") {
		t.Errorf("--print-config must not mint or print admin token, got:\n%s", stdout.String())
	}

	tokensFile := filepath.Join(dataDir, "tokens.json")
	if _, err := os.Stat(tokensFile); !os.IsNotExist(err) {
		t.Errorf("tokens.json should not exist after --print-config, stat err: %v", err)
	}
}

// TestServeConcurrentBootSingleToken exercises 16 concurrent `walden serve` boots against the
// same data directory to confirm the tokens.lock-guarded admin-token race resolves to exactly
// one minted token. It cannot use cancelledContext() the way every other boot test in this
// file does: acquireStoreLock (internal/auth/filelock_unix.go) now honors ctx while it waits
// on tokens.lock, so a real SIGINT/SIGTERM during that wait aborts boot instead of being
// silently swallowed until the lock frees up. An already-cancelled context would make whichever
// goroutines lose the race for the lock abort with ctx.Err() instead of waiting their turn,
// which is a different thing than what this test probes. Each goroutine instead gets its own
// bounded-but-live context: generous enough that lock contention among 16 local flock waiters
// (each polling at storeLockPollInterval) never legitimately times out, but still bounded so a
// regression here fails the test instead of hanging it.
func TestServeConcurrentBootSingleToken(t *testing.T) {
	dataDir := t.TempDir()
	const concurrency = 16

	var wg sync.WaitGroup
	wg.Add(concurrency)

	outputs := make([]string, concurrency)
	errs := make([]error, concurrency)

	for i := 0; i < concurrency; i++ {
		idx := i
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var stdout, stderr bytes.Buffer
			errs[idx] = runServe(ctx, []string{"--data-dir", dataDir, "--listen", "127.0.0.1:0"}, &stdout, &stderr)
			outputs[idx] = stdout.String()
		}()
	}

	wg.Wait()

	adminTokenCount := 0
	var mintedToken string
	for i := 0; i < concurrency; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d failed: %v", i, errs[i])
		}
		if !strings.Contains(outputs[i], "walden server starting on 127.0.0.1:") {
			t.Errorf("goroutine %d missing server starting line: %q", i, outputs[i])
		}
		if strings.Contains(outputs[i], "admin token: ") {
			adminTokenCount++
			for _, line := range strings.Split(outputs[i], "\n") {
				if strings.HasPrefix(line, "admin token: ") {
					mintedToken = strings.TrimPrefix(line, "admin token: ")
				}
			}
		}
	}

	if adminTokenCount != 1 {
		t.Fatalf("expected exactly 1 admin token printed, got %d", adminTokenCount)
	}
	if !strings.HasPrefix(mintedToken, "walden_") {
		t.Errorf("expected minted token prefix 'walden_', got %q", mintedToken)
	}

	store := auth.NewFileTokenStore(dataDir)
	tokens, err := store.ListTokens(context.Background())
	if err != nil {
		t.Fatalf("failed to list tokens: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("expected exactly 1 token in store, got %d", len(tokens))
	}
	if tokens[0].TokenID != auth.AdminTokenID {
		t.Errorf("token ID in store = %q, want %q", tokens[0].TokenID, auth.AdminTokenID)
	}
	if tokens[0].TokenHash != auth.HashToken(mintedToken) {
		t.Errorf("token hash in store = %q, want %q", tokens[0].TokenHash, auth.HashToken(mintedToken))
	}
}

func TestServeDataDirCreationFailure(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(tmpFile, []byte("x"), 0600); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	invalidDataDir := filepath.Join(tmpFile, "cannot_mkdir")

	var stdout, stderr bytes.Buffer
	err := runServe(context.Background(), []string{"--data-dir", invalidDataDir}, &stdout, &stderr)
	if err == nil {
		t.Fatalf("expected runServe to fail when data dir cannot be created")
	}
	if !errors.Is(err, auth.ErrStoreUnavailable) {
		t.Errorf("expected error to wrap ErrStoreUnavailable, got: %v", err)
	}
	errStr := err.Error()
	if strings.Contains(errStr, "\n") {
		t.Errorf("expected single-line error, got: %q", errStr)
	}
}

// TestServeInvalidTrustKeyRefuses asserts that a malformed --auth-trust
// value refuses in one line and mints nothing: auth.NewAuthorizer is the
// only place the auth mode is decided, and its refusal must reach the
// operator before the built-in token path is ever considered.
func TestServeInvalidTrustKeyRefuses(t *testing.T) {
	dataDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	err := runServe(context.Background(), []string{"--data-dir", dataDir, "--auth-trust", "not-a-valid-key"}, &stdout, &stderr)
	if err == nil {
		t.Fatalf("expected runServe to refuse an invalid auth-trust key")
	}
	errStr := err.Error()
	if strings.Contains(errStr, "\n") {
		t.Errorf("expected single-line error, got: %q", errStr)
	}

	tokensFile := filepath.Join(dataDir, "tokens.json")
	if _, statErr := os.Stat(tokensFile); !os.IsNotExist(statErr) {
		t.Errorf("tokens.json should not exist after an invalid auth-trust refusal, stat err: %v", statErr)
	}
}

// TestServeListenInUseRefuses asserts that a busy listen address is a
// one-line refusal naming the --listen knob, returned promptly (binding
// happens before minting), with no tokens.json left behind.
func TestServeListenInUseRefuses(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to hold a listener: %v", err)
	}
	defer held.Close()

	dataDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	err = runServe(context.Background(), []string{"--data-dir", dataDir, "--listen", held.Addr().String()}, &stdout, &stderr)
	if err == nil {
		t.Fatalf("expected runServe to refuse a listen address already in use")
	}
	if !strings.Contains(err.Error(), "listen") || !strings.Contains(err.Error(), "--listen") {
		t.Errorf("expected refusal naming the listen knob, got: %v", err)
	}
	if strings.Contains(err.Error(), "\n") {
		t.Errorf("expected single-line error, got: %q", err.Error())
	}

	tokensFile := filepath.Join(dataDir, "tokens.json")
	if _, statErr := os.Stat(tokensFile); !os.IsNotExist(statErr) {
		t.Errorf("tokens.json should not exist after a listen refusal, stat err: %v", statErr)
	}
}

// TestServeJournalWarning asserts the loud, exactly-once warning
// ARCHITECTURE.md promises for journal-less mode, and its absence once a
// journal is configured.
func TestServeJournalWarning(t *testing.T) {
	const warning = "walden: WARNING: journal-less mode: WALDEN_JOURNAL is unset, so durability is this disk alone"

	t.Run("unset", func(t *testing.T) {
		dataDir := t.TempDir()
		var stdout, stderr bytes.Buffer
		err := runServe(cancelledContext(), []string{"--data-dir", dataDir, "--listen", "127.0.0.1:0"}, &stdout, &stderr)
		if err != nil {
			t.Fatalf("runServe failed: %v", err)
		}
		out := stderr.String()
		if strings.Count(out, warning) != 1 {
			t.Errorf("expected the journal-less warning exactly once on stderr, got:\n%s", out)
		}
	})

	t.Run("configured", func(t *testing.T) {
		dataDir := t.TempDir()
		t.Setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "topsecret")
		t.Setenv("AWS_REGION", "us-east-1")

		// A real s3:// journal would now reach the boot-time compare-and-
		// swap probe (WALD-23), which would in turn make a real network
		// request. Pointed at a local fake that honours If-None-Match
		// instead, so this test - which is about the journal-less warning,
		// not the probe - stays offline.
		fake := storetest.New(t)
		journalURL := fake.URL() + "/" + fake.Bucket() + "/prefix"

		var stdout, stderr bytes.Buffer
		err := runServe(cancelledContext(), []string{
			"--data-dir", dataDir,
			"--listen", "127.0.0.1:0",
			"--journal", journalURL,
		}, &stdout, &stderr)
		if err != nil {
			t.Fatalf("runServe failed: %v", err)
		}
		if strings.Contains(stderr.String(), "journal-less mode") {
			t.Errorf("expected no journal-less warning when journal is configured, got:\n%s", stderr.String())
		}
	})
}

// TestServeProbeRefusesProviderLacksCAS asserts the boot-level shape of the
// WALD-23 probe's refusal (spec/journal/v1 section 11.5 item 6): a backend
// that ignores If-None-Match: * makes runServe return the one-line
// RefuseProviderLacksCAS refusal naming the endpoint's host[:port] (this
// fake's host is unrecognised, so it never resolves to a known provider
// name), and boot stops before os.MkdirAll ever runs - the data directory
// must not exist afterward. Moving the probe below os.MkdirAll/net.Listen,
// dropping the `journal != nil` guard's effect on this path, or dropping
// the probe's `return err` would all let dataDir come into existence, which
// is exactly what this test's final assertion catches.
func TestServeProbeRefusesProviderLacksCAS(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "topsecret")
	t.Setenv("AWS_REGION", "us-east-1")

	fake := storetest.New(t)
	fake.Inject(storetest.Rule{
		Op: storetest.OpPutIfAbsent, Call: 1, Count: 2,
		Fault: storetest.Fault{IgnoreCondition: true},
	})
	journalURL := fake.URL() + "/" + fake.Bucket() + "/prefix"

	var stdout, stderr bytes.Buffer
	err := runServe(cancelledContext(), []string{
		"--data-dir", dataDir,
		"--listen", "127.0.0.1:0",
		"--journal", journalURL,
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("runServe succeeded, want a refusal (the fake does not honour If-None-Match)")
	}
	if !errors.Is(err, journal.ErrCASNotSupported) {
		t.Errorf("errors.Is(err, journal.ErrCASNotSupported) = false, err = %v", err)
	}
	host := strings.TrimPrefix(fake.URL(), "http://")
	want := journal.RefuseProviderLacksCAS(host).Error()
	if err.Error() != want {
		t.Errorf("runServe error:\n got: %s\nwant: %s", err.Error(), want)
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}

	if _, statErr := os.Stat(dataDir); !os.IsNotExist(statErr) {
		t.Errorf("data dir %s must not exist after a boot refused by the probe (which must run before os.MkdirAll), stat err = %v", dataDir, statErr)
	}
}

// TestServeProbePrintConfigMakesNoRequest asserts --print-config never
// reaches the boot-time probe: it resolves the journal's location but exits
// before the `if journal != nil` probe block, so it never makes a single
// request to the bucket even when a --journal is given. A regression that
// hoisted the probe ahead of the --print-config return, or ran it
// regardless of printConfig, would show up here as a nonzero call count.
func TestServeProbePrintConfigMakesNoRequest(t *testing.T) {
	dataDir := t.TempDir()
	fake := storetest.New(t)
	journalURL := fake.URL() + "/" + fake.Bucket() + "/prefix"

	var stdout, stderr bytes.Buffer
	err := runServe(context.Background(), []string{
		"--data-dir", dataDir,
		"--journal", journalURL,
		"--print-config",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runServe --print-config failed: %v", err)
	}

	if calls := fake.Calls(); len(calls) != 0 {
		t.Errorf("--print-config made %d request(s) to the journal bucket, want 0: %+v", len(calls), calls)
	}
}

// TestServeProbeCleanupFailureIsWarning asserts a failed probe-cleanup
// DELETE surfaces as exactly one `walden: WARNING: journal probe cleanup:`
// line on stderr, never a refusal, and boot continues past it (the probe
// itself passes: the fake otherwise honours If-None-Match).
func TestServeProbeCleanupFailureIsWarning(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "topsecret")
	t.Setenv("AWS_REGION", "us-east-1")

	fake := storetest.New(t)
	fake.Inject(storetest.Rule{
		Op: storetest.OpDelete, Call: 1,
		Fault: storetest.Fault{Status: http.StatusForbidden, Code: "AccessDenied"},
	})
	journalURL := fake.URL() + "/" + fake.Bucket() + "/prefix"

	var stdout, stderr bytes.Buffer
	err := runServe(cancelledContext(), []string{
		"--data-dir", dataDir,
		"--listen", "127.0.0.1:0",
		"--journal", journalURL,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runServe failed: %v", err)
	}

	const wantPrefix = "walden: WARNING: journal probe cleanup:"
	out := stderr.String()
	if got := strings.Count(out, wantPrefix); got != 1 {
		t.Errorf("expected exactly one %q line on stderr, got %d:\n%s", wantPrefix, got, out)
	}

	if !strings.Contains(stdout.String(), "walden server starting on") {
		t.Errorf("expected boot to continue past the cleanup warning and bind, got stdout:\n%s", stdout.String())
	}
}

// journalTestJournalURL builds a --journal value pointing at fake, styled on
// TestServeJournalWarning and TestServeProbeRefusesProviderLacksCAS.
func journalTestJournalURL(fake *storetest.Fake) string {
	return fake.URL() + "/" + fake.Bucket() + "/prefix"
}

// setJournalCreds sets the AWS-conventional environment variables
// ResolveJournal reads credentials and region from, the same three every
// other journal-backed runServe test in this file sets.
func setJournalCreds(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "topsecret")
	t.Setenv("AWS_REGION", "us-east-1")
}

// extractIdentityLine finds the "journal identity <outcome>: <key>" line
// runServe prints (WALD-28) and returns the key. It fails the test if no
// such line is present.
func extractIdentityLine(t *testing.T, out, outcome string) string {
	t.Helper()
	prefix := "journal identity " + outcome + ": "
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	t.Fatalf("expected a line with prefix %q, got:\n%s", prefix, out)
	return ""
}

// TestServeJournalPrintsMintedIdentity covers WALD-28: a first boot against
// an empty journal mints a signing identity, prints it before the server
// starting line (the same ordering TestServeFirstBootMintsAdminToken checks
// for the admin token), and leaves a signing.key behind.
func TestServeJournalPrintsMintedIdentity(t *testing.T) {
	dataDir := t.TempDir()
	setJournalCreds(t)
	fake := storetest.New(t)
	journalURL := journalTestJournalURL(fake)

	var stdout, stderr bytes.Buffer
	err := runServe(cancelledContext(), []string{
		"--data-dir", dataDir,
		"--listen", "127.0.0.1:0",
		"--journal", journalURL,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runServe failed: %v", err)
	}

	out := stdout.String()
	key := extractIdentityLine(t, out, "minted")
	if !strings.HasPrefix(key, "ed25519:") {
		t.Errorf("minted identity key = %q, want an ed25519: key", key)
	}
	if strings.Contains(out, "journal identity adopted:") {
		t.Errorf("first boot must not also print an adopted identity line, got:\n%s", out)
	}

	identityIdx := strings.Index(out, "journal identity minted:")
	startIdx := strings.Index(out, "walden server starting on")
	if identityIdx == -1 || startIdx == -1 || identityIdx >= startIdx {
		t.Errorf("expected the identity line before the server starting line, got:\n%s", out)
	}

	if _, err := os.Stat(journal.SigningKeyPath(dataDir)); err != nil {
		t.Errorf("expected %s to exist after a mint: %v", journal.SigningKeyPath(dataDir), err)
	}
}

// TestServeJournalSecondBootAdoptsIdentity covers WALD-28: a second boot
// against the same data directory and journal adopts the identity the
// first boot minted (same key, "adopted" rather than "minted") and writes
// no new object to the bucket.
func TestServeJournalSecondBootAdoptsIdentity(t *testing.T) {
	dataDir := t.TempDir()
	setJournalCreds(t)
	fake := storetest.New(t)
	journalURL := journalTestJournalURL(fake)
	args := []string{"--data-dir", dataDir, "--listen", "127.0.0.1:0", "--journal", journalURL}

	var stdout1, stderr1 bytes.Buffer
	if err := runServe(cancelledContext(), args, &stdout1, &stderr1); err != nil {
		t.Fatalf("first runServe failed: %v", err)
	}
	minted := extractIdentityLine(t, stdout1.String(), "minted")
	keysAfterFirst := len(fake.Keys())

	var stdout2, stderr2 bytes.Buffer
	if err := runServe(cancelledContext(), args, &stdout2, &stderr2); err != nil {
		t.Fatalf("second runServe failed: %v", err)
	}
	adopted := extractIdentityLine(t, stdout2.String(), "adopted")
	if strings.Contains(stdout2.String(), "journal identity minted:") {
		t.Errorf("second boot must not print a minted identity line, got:\n%s", stdout2.String())
	}

	if adopted != minted {
		t.Errorf("adopted key %q != minted key %q", adopted, minted)
	}
	if keysAfterSecond := len(fake.Keys()); keysAfterSecond != keysAfterFirst {
		t.Errorf("second boot changed the object count in the bucket: %d -> %d", keysAfterFirst, keysAfterSecond)
	}
}

// TestServeJournalWipedDataDirRefusesAdopt covers WALD-28: a data directory
// wiped between boots (PHILOSOPHY.md's "the disk is a cache") against a
// journal that already holds a genesis record must adopt, not mint — and an
// instance with no local signing key cannot adopt, so it refuses in one
// line and binds no port.
func TestServeJournalWipedDataDirRefusesAdopt(t *testing.T) {
	dataDir := t.TempDir()
	setJournalCreds(t)
	fake := storetest.New(t)
	journalURL := journalTestJournalURL(fake)
	args := []string{"--data-dir", dataDir, "--listen", "127.0.0.1:0", "--journal", journalURL}

	var stdout1, stderr1 bytes.Buffer
	if err := runServe(cancelledContext(), args, &stdout1, &stderr1); err != nil {
		t.Fatalf("first runServe failed: %v", err)
	}

	if err := os.RemoveAll(dataDir); err != nil {
		t.Fatalf("failed to wipe data dir: %v", err)
	}

	var stdout2, stderr2 bytes.Buffer
	err := runServe(cancelledContext(), args, &stdout2, &stderr2)
	if err == nil {
		t.Fatal("expected a refusal after wiping the data directory, got nil")
	}
	if !errors.Is(err, journal.ErrSigningKeyUnavailable) {
		t.Errorf("expected errors.Is(err, journal.ErrSigningKeyUnavailable), got %v", err)
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("refusal is not a single line: %q", err.Error())
	}
	if strings.Contains(stdout2.String(), "walden server starting on") {
		t.Errorf("expected boot to stop before binding, got stdout:\n%s", stdout2.String())
	}
}

// TestServeJournalLessBootWritesNoSigningKey covers WALD-28: journal-less
// mode never calls EnsureGenesis — the identity is born with the journal,
// and there is no journal to be born with — so it must leave no
// signing.key behind.
func TestServeJournalLessBootWritesNoSigningKey(t *testing.T) {
	dataDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if err := runServe(cancelledContext(), []string{"--data-dir", dataDir, "--listen", "127.0.0.1:0"}, &stdout, &stderr); err != nil {
		t.Fatalf("runServe failed: %v", err)
	}
	if strings.Contains(stdout.String(), "journal identity") {
		t.Errorf("journal-less boot must not print an identity line, got:\n%s", stdout.String())
	}
	if _, err := os.Stat(journal.SigningKeyPath(dataDir)); !os.IsNotExist(err) {
		t.Errorf("expected no signing.key in journal-less mode, stat err = %v", err)
	}
}

// TestServeFirstBootWithJournalJournalsAdminToken covers WALD-33: when a
// journal is configured, the first-boot admin token is journaled to
// _meta -- a token_create record at seq 1, right after genesis's own seq
// 0 -- before it is written to tokens.json, and a second boot (the local
// store is no longer empty) mints and journals nothing further.
func TestServeFirstBootWithJournalJournalsAdminToken(t *testing.T) {
	dataDir := t.TempDir()
	setJournalCreds(t)
	fake := storetest.New(t)
	journalURL := journalTestJournalURL(fake)

	var stdout, stderr bytes.Buffer
	if err := runServe(cancelledContext(), []string{
		"--data-dir", dataDir,
		"--listen", "127.0.0.1:0",
		"--journal", journalURL,
	}, &stdout, &stderr); err != nil {
		t.Fatalf("runServe failed: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "admin token: walden_") {
		t.Fatalf("expected stdout to contain 'admin token: walden_', got:\n%s", out)
	}
	var token string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "admin token: ") {
			token = strings.TrimPrefix(line, "admin token: ")
			break
		}
	}
	if token == "" {
		t.Fatal("failed to extract admin token from output")
	}

	j, err := store.ResolveJournal(journalURL, os.LookupEnv)
	if err != nil {
		t.Fatalf("ResolveJournal: %v", err)
	}
	c := store.NewClient(j)
	chain, table, err := c.ReplayMetaTable(context.Background())
	if err != nil {
		t.Fatalf("ReplayMetaTable: %v", err)
	}
	if chain.LastMetaSeq() != 1 {
		t.Errorf("LastMetaSeq() = %d, want 1 (genesis at 0, the admin token_create at 1)", chain.LastMetaSeq())
	}
	row, ok := table.Row(auth.AdminTokenID)
	if !ok {
		t.Fatal("the journal's rebuilt token table does not hold the admin token")
	}
	if row.TokenHash != auth.HashToken(token) {
		t.Errorf("journaled token hash %q != HashToken(printed token) = %q", row.TokenHash, auth.HashToken(token))
	}
	if row.Revoked {
		t.Error("the admin token came back revoked")
	}
	if got, want := strings.Join(row.Scopes, ","), "rwc:*"; got != want {
		t.Errorf("journaled scopes = %q, want %q", got, want)
	}

	// Second boot: the local store already holds a token, so
	// EnsureAdminToken mints nothing further and _meta gains no further
	// record.
	var stdout2, stderr2 bytes.Buffer
	if err := runServe(cancelledContext(), []string{
		"--data-dir", dataDir,
		"--listen", "127.0.0.1:0",
		"--journal", journalURL,
	}, &stdout2, &stderr2); err != nil {
		t.Fatalf("second runServe failed: %v", err)
	}
	if strings.Contains(stdout2.String(), "admin token:") {
		t.Errorf("second boot must not mint or print an admin token, got:\n%s", stdout2.String())
	}
	chain2, _, err := c.ReplayMetaTable(context.Background())
	if err != nil {
		t.Fatalf("ReplayMetaTable after second boot: %v", err)
	}
	if chain2.LastMetaSeq() != 1 {
		t.Errorf("LastMetaSeq() after second boot = %d, want 1 (unchanged: no further token record written)", chain2.LastMetaSeq())
	}
}

// TestServeSecondBootWithLostTokensJSONDoesNotDoublyJournalAdminToken
// reproduces round 1 finding 1 on WALD-33: the admin-token journalFn
// (main.go) used to skip the uniqueness pre-check against the journal's
// rebuilt table that runTokenCreate (token.go) already ran for `walden
// token create`, so a second first-boot mint — here, tokens.json lost
// between two boots, the exact "restore onto an empty disk" scenario the
// plan calls out — appended a second token_create for the constant id
// auth.AdminTokenID and poisoned every future replay under spec section
// 8.1 rule 10 ("refusal: replay failed: token create at seq 2 reuses
// token id admin"), permanently, short of hand-editing the bucket.
//
// The fix must leave a working path forward rather than trade one dead
// end for another: boot 2 must still succeed (bind and serve) even
// though the local store is empty and the journal cannot honor another
// admin mint, and boot 3 (and every later one) must keep working too —
// nothing about this journal may become permanently unreplayable.
func TestServeSecondBootWithLostTokensJSONDoesNotDoublyJournalAdminToken(t *testing.T) {
	dataDir := t.TempDir()
	setJournalCreds(t)
	fake := storetest.New(t)
	journalURL := journalTestJournalURL(fake)
	args := []string{"--data-dir", dataDir, "--listen", "127.0.0.1:0", "--journal", journalURL}

	var stdout1, stderr1 bytes.Buffer
	if err := runServe(cancelledContext(), args, &stdout1, &stderr1); err != nil {
		t.Fatalf("boot 1 failed: %v", err)
	}
	if !strings.Contains(stdout1.String(), "admin token: walden_") {
		t.Fatalf("boot 1: expected an admin token to be printed, got:\n%s", stdout1.String())
	}

	j, err := store.ResolveJournal(journalURL, os.LookupEnv)
	if err != nil {
		t.Fatalf("ResolveJournal: %v", err)
	}
	c := store.NewClient(j)
	chainAfterBoot1, tableAfterBoot1, err := c.ReplayMetaTable(context.Background())
	if err != nil {
		t.Fatalf("ReplayMetaTable after boot 1: %v", err)
	}
	if chainAfterBoot1.LastMetaSeq() != 1 {
		t.Fatalf("LastMetaSeq() after boot 1 = %d, want 1 (genesis at 0, admin token_create at 1)", chainAfterBoot1.LastMetaSeq())
	}
	rowAfterBoot1, ok := tableAfterBoot1.Row(auth.AdminTokenID)
	if !ok {
		t.Fatal("boot 1: the journal's rebuilt token table does not hold the admin token")
	}

	// The exact reproduction the round 1 finding probed: tokens.json is
	// lost (a restore onto an empty disk mints today's local id from
	// scratch the same way; deleting the file after a successful boot is
	// the simplest way to put the local store back in that same empty
	// state without wiping the signing key boot 2 also needs to adopt
	// the journal's existing genesis record).
	if err := os.Remove(filepath.Join(dataDir, "tokens.json")); err != nil {
		t.Fatalf("failed to remove tokens.json: %v", err)
	}

	var stdout2, stderr2 bytes.Buffer
	if err := runServe(cancelledContext(), args, &stdout2, &stderr2); err != nil {
		t.Fatalf("boot 2 failed: %v (this must not brick the journal or refuse boot)", err)
	}
	if strings.Contains(stdout2.String(), "admin token:") {
		t.Errorf("boot 2: expected no admin token to be minted or printed once the journal already holds one, got stdout:\n%s", stdout2.String())
	}
	if !strings.Contains(stderr2.String(), "already holds a token_create") {
		t.Errorf("boot 2: expected a WARNING naming the journal's existing admin token_create, got stderr:\n%s", stderr2.String())
	}

	chainAfterBoot2, tableAfterBoot2, err := c.ReplayMetaTable(context.Background())
	if err != nil {
		t.Fatalf("ReplayMetaTable after boot 2: %v", err)
	}
	if chainAfterBoot2.LastMetaSeq() != 1 {
		t.Fatalf("LastMetaSeq() after boot 2 = %d, want 1 unchanged (no second token_create for id %q)", chainAfterBoot2.LastMetaSeq(), auth.AdminTokenID)
	}
	rowAfterBoot2, ok := tableAfterBoot2.Row(auth.AdminTokenID)
	if !ok {
		t.Fatal("boot 2: the journal's rebuilt token table lost the admin token")
	}
	if rowAfterBoot2.TokenHash != rowAfterBoot1.TokenHash {
		t.Errorf("boot 2: admin token hash in the journal changed from %q to %q; a second token_create landed", rowAfterBoot1.TokenHash, rowAfterBoot2.TokenHash)
	}

	// The disaster-recovery path the ticket exists to make work: boot 3
	// (and by extension every subsequent boot, token command, and
	// restore against this bucket) must keep working, not refuse forever
	// the way the un-fixed code did from the second boot on.
	var stdout3, stderr3 bytes.Buffer
	if err := runServe(cancelledContext(), args, &stdout3, &stderr3); err != nil {
		t.Fatalf("boot 3 failed: %v (the journal must not be permanently bricked)", err)
	}
	if !strings.Contains(stdout3.String(), "walden server starting on") {
		t.Errorf("boot 3: expected a normal boot to reach the server-starting line, got stdout:\n%s", stdout3.String())
	}
}
