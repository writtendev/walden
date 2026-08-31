package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunUsageAndVersion(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "version",
			args:    []string{"walden", "version"},
			wantErr: false,
		},
		{
			name:    "help",
			args:    []string{"walden", "help"},
			wantErr: false,
		},
		{
			name:    "serve",
			args:    []string{"walden", "serve"},
			wantErr: false,
		},
		{
			name:    "unknown",
			args:    []string{"walden", "invalid-command"},
			wantErr: true,
		},
		{
			name:    "pre-receive-argv0",
			args:    []string{"/path/to/pre-receive"},
			wantErr: false,
		},
		{
			name:    "pre-receive-subcommand",
			args:    []string{"walden", "pre-receive"},
			wantErr: false,
		},
		{
			name:    "token-missing-subcommand",
			args:    []string{"walden", "token"},
			wantErr: true,
		},
		{
			name:    "token-create",
			args:    []string{"walden", "token", "create"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := run(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("run(%v) error = %v, wantErr %v", tt.args, err, tt.wantErr)
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
