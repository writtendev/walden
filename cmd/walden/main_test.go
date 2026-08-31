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
			wantErrSub: "missing token subcommand (create, list, revoke)",
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
			wantOutSub: "data-dir: /test/cache\njournal: s3://my-bucket/w\nauth-trust: (builtin)\nlisten: :8888",
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
		})
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
