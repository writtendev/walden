package main

import (
	"bytes"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunUsageAndVersion(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantErr    bool
		wantOutSub string
		wantErrSub string
	}{
		{
			name:       "empty-args-defaults-to-serve",
			args:       []string{},
			wantErr:    false,
			wantOutSub: "walden server starting",
		},
		{
			name:       "default-serve-when-single-arg",
			args:       []string{"walden"},
			wantErr:    false,
			wantOutSub: "walden server starting",
		},
		{
			name:       "serve-subcommand",
			args:       []string{"walden", "serve"},
			wantErr:    false,
			wantOutSub: "walden server starting",
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
			name:       "token-create",
			args:       []string{"walden", "token", "create"},
			wantErr:    false,
			wantOutSub: "walden token create: not yet implemented",
		},
		{
			name:       "token-list",
			args:       []string{"walden", "token", "list"},
			wantErr:    false,
			wantOutSub: "walden token list: not yet implemented",
		},
		{
			name:       "token-revoke",
			args:       []string{"walden", "token", "revoke"},
			wantErr:    false,
			wantOutSub: "walden token revoke: not yet implemented",
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
			var stdout, stderr bytes.Buffer
			err := run(tt.args, &stdout, &stderr)
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
	var stdout, stderr bytes.Buffer
	err := runServe(nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runServe failed: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "walden server starting on :8470") {
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
	err := runServe(nil, &stdout, &stderr)
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
			wantExit0:  true,
			wantOutSub: "walden token create: not yet implemented",
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
			name:       "serve-journal-provider-without-cas-exits-error",
			cmdPath:    binPath,
			args:       []string{"serve", "--journal", "https://s3.eu-central-1.wasabisys.com/my-bucket/walden"},
			wantExit0:  false,
			wantErrSub: "walden: invalid journal: Wasabi does not support compare-and-swap",
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
			wantErrSub: "walden: invalid journal: URL is malformed; it is not echoed because it may carry credentials",
			wantErrNot: []string{"p@ss", "ss/w0rd", "w0rd", "minio.internal"},
		},
		{
			name:       "serve-print-config-journal-url-is-not-printed",
			cmdPath:    binPath,
			args:       []string{"serve", "--journal", "s3://AKIAEXAMPLE:topsecret@my-bucket/walden", "--print-config"},
			wantExit0:  true,
			wantOutSub: "journal: (configured)",
			wantErrNot: []string{"topsecret", "AKIAEXAMPLE"},
		},
		{
			// --print-config names where the credentials come from, so it
			// cannot report an unresolved journal that would in fact boot.
			// It names the source, never the secret.
			name:    "serve-print-config-names-the-credential-source",
			cmdPath: binPath,
			args:    []string{"serve", "--journal", "s3://my-bucket/walden", "--print-config"},
			env: append(os.Environ(),
				"AWS_ACCESS_KEY_ID=AKIAEXAMPLE",
				"AWS_SECRET_ACCESS_KEY=topsecret",
			),
			wantExit0:  true,
			wantOutSub: "journal-credentials: AWS_ACCESS_KEY_ID",
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
			wantErrSub: "walden: invalid journal: URL is malformed; it is not echoed because it may carry credentials",
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
		{
			// A root-anchored FQDN must not walk past the provider table
			// and the compare-and-swap gate behind it.
			name:       "serve-journal-root-anchored-fqdn-without-cas-exits-error",
			cmdPath:    binPath,
			args:       []string{"serve", "--journal", "https://s3.wasabisys.com./my-bucket/walden"},
			wantExit0:  false,
			wantErrSub: "walden: invalid journal: Wasabi does not support compare-and-swap",
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
	errUnknown := run([]string{"walden", "invalid"}, &bytes.Buffer{}, &bytes.Buffer{})
	if errUnknown == nil {
		t.Fatal("expected error")
	}
	errStr := errUnknown.Error()
	if !strings.Contains(errStr, ": ") || !strings.Contains(errStr, "(") || !strings.HasSuffix(errStr, ")") {
		t.Errorf("refusal format mismatch: %q (expected '<what>: <why> (<fix>)')", errStr)
	}

	errToken := run([]string{"walden", "token"}, &bytes.Buffer{}, &bytes.Buffer{})
	if errToken == nil {
		t.Fatal("expected error")
	}
	tokenErrStr := errToken.Error()
	if !strings.Contains(tokenErrStr, ": ") || !strings.Contains(tokenErrStr, "(") || !strings.HasSuffix(tokenErrStr, ")") {
		t.Errorf("refusal format mismatch: %q (expected '<what>: <why> (<fix>)')", tokenErrStr)
	}
}
