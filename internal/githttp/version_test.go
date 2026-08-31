package githttp_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/githttp"
)

func TestParseGitVersionOutput(t *testing.T) {
	tests := []struct {
		name       string
		output     string
		wantVer    string
		wantErr    bool
		wantErrSub string
	}{
		{
			name:    "standard-alpine-version",
			output:  "git version 2.47.2\n",
			wantVer: "2.47.2",
			wantErr: false,
		},
		{
			name:    "apple-git-format",
			output:  "git version 2.50.1 (Apple Git-155)\n",
			wantVer: "2.50.1",
			wantErr: false,
		},
		{
			name:    "windows-git-format",
			output:  "git version 2.40.0.windows.1",
			wantVer: "2.40.0.windows.1",
			wantErr: false,
		},
		{
			name:    "release-candidate",
			output:  "git version 2.48.0-rc1",
			wantVer: "2.48.0-rc1",
			wantErr: false,
		},
		{
			name:       "invalid-prefix",
			output:     "custom-git 2.47.2",
			wantErr:    true,
			wantErrSub: "unexpected git version output format",
		},
		{
			name:       "empty-version",
			output:     "git version ",
			wantErr:    true,
			wantErrSub: "empty version string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := githttp.ParseGitVersionOutput(tt.output)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseGitVersionOutput(%q) error = %v, wantErr %v", tt.output, err, tt.wantErr)
			}
			if tt.wantErr {
				if tt.wantErrSub != "" && !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Errorf("error %q does not contain expected substring %q", err.Error(), tt.wantErrSub)
				}
				return
			}
			if got != tt.wantVer {
				t.Errorf("ParseGitVersionOutput(%q) = %q, want %q", tt.output, got, tt.wantVer)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		v1      string
		v2      string
		want    int
		wantErr bool
	}{
		{"2.47.2", "2.40.0", 1, false},
		{"2.40.0", "2.47.2", -1, false},
		{"2.40.0", "2.40.0", 0, false},
		{"2.40.1", "2.40.0", 1, false},
		{"2.39.9", "2.40.0", -1, false},
		{"3.0.0", "2.47.2", 1, false},
		{"1.9.5", "2.40.0", -1, false},
		{"2.40.0.windows.1", "2.40.0", 0, false},
		{"2.40.1.windows.1", "2.40.0", 1, false},
		{"2.48.0-rc1", "2.40.0", 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.v1+"_vs_"+tt.v2, func(t *testing.T) {
			got, err := githttp.CompareVersions(tt.v1, tt.v2)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CompareVersions(%q, %q) error = %v, wantErr %v", tt.v1, tt.v2, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
			}
		})
	}
}

func TestAssertGitFloorAgainstHost(t *testing.T) {
	ctx := context.Background()
	ver, err := githttp.AssertGitFloor(ctx, githttp.MinGitVersion)
	if err != nil {
		t.Fatalf("AssertGitFloor failed on host: %v", err)
	}
	if ver == "" {
		t.Errorf("expected non-empty version string")
	}
}

func TestAssertGitFloorRefusal(t *testing.T) {
	ctx := context.Background()

	// Create a fake script in temp directory that outputs an old version
	tmpDir := t.TempDir()
	fakeGit := filepath.Join(tmpDir, "git")

	script := "#!/bin/sh\necho 'git version 2.20.0'\n"
	if err := os.WriteFile(fakeGit, []byte(script), 0o755); err != nil {
		t.Fatalf("failed to write fake git script: %v", err)
	}

	_, err := githttp.AssertGitFloorPath(ctx, fakeGit, "2.40.0")
	if err == nil {
		t.Fatalf("expected error for git below floor, got nil")
	}

	expectedSub := "git version 2.20.0 is below supported floor 2.40.0 (walden requires git >= 2.40.0)"
	if !strings.Contains(err.Error(), expectedSub) {
		t.Errorf("expected error %q to contain %q", err.Error(), expectedSub)
	}

	// Test non-existent path
	_, err = githttp.AssertGitFloorPath(ctx, filepath.Join(tmpDir, "nonexistent-git"), "2.40.0")
	if err == nil {
		t.Fatalf("expected error for non-existent git, got nil")
	}
	expectedNotFound := "git not found in PATH (walden requires git >= 2.40.0)"
	if !strings.Contains(err.Error(), expectedNotFound) {
		t.Errorf("expected error %q to contain %q", err.Error(), expectedNotFound)
	}
}
