package githttp_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/store"
)

// gitForTest execs git with the allowlist environment walden's own children
// get, so a repository built here is one walden's git would have built and no
// developer's ~/.gitconfig reaches it.
func gitForTest(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = []string{"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null"}
	if p := os.Getenv("PATH"); p != "" {
		cmd.Env = append(cmd.Env, "PATH="+p)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

// placeOperatorRepo puts a bare repository at path by execing git directly —
// never through store.CreateRepo. That is the case this file is about: a
// repository that reached the data volume by a route walden had no part in, a
// restored backup or a migration off another server, bringing its own config.
// It is the same way hookpresence_test.go builds the damage it pins.
func placeOperatorRepo(t *testing.T, path string) {
	t.Helper()
	gitForTest(t, "", "init", "--bare", "--template=", "--initial-branch=main", path)
}

// donorWithACommit builds a repository holding one real commit, outside the
// data directory, and returns its objects directory. An alternate has to have
// something to contribute for git to consult it at all.
func donorWithACommit(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	donor := filepath.Join(root, "donor.git")
	gitForTest(t, "", "init", "--bare", "--template=", "--initial-branch=main", donor)

	work := filepath.Join(root, "work")
	gitForTest(t, "", "init", "--template=", "--initial-branch=main", work)
	if err := os.WriteFile(filepath.Join(work, "f"), []byte("contents\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	gitForTest(t, work, "add", "f")
	gitForTest(t, work, "-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-m", "one")
	gitForTest(t, work, "push", donor, "main")

	return filepath.Join(donor, "objects")
}

// markerCommand writes a shell script that creates markerPath when run, and
// returns the script's path. It is how the test observes whether the
// repository's own config got a command executed: a status code cannot tell a
// refusal that happened before the exec from one that happened after it, and
// only the second is a fix.
func markerCommand(t *testing.T, dir, markerPath string) string {
	t.Helper()
	script := filepath.Join(dir, "marker.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntouch "+markerPath+"\n"), 0o700); err != nil {
		t.Fatalf("WriteFile(%q): %v", script, err)
	}
	return script
}

// TestOperatorPlacedRepoConfigNeverExecutes drives WALD-131's demonstrated
// defect end to end, which is how it was found: an operator-placed repository
// on the data volume whose own config names a command for git to run, hit with
// a real authenticated request through the handler.
//
// The marker file is the test. A status-code assertion alone passes against a
// "fix" that refuses after the exec, which is no fix at all — so every entry
// point asserts that the command did not run, not merely that the request was
// refused.
//
// All four entry points are driven, deliberately, although on the versions
// measured only one of them executes the command today: `git receive-pack`
// consults an alternate's refs when advertising and `git upload-pack` does
// not, so the reachable route is the receive-pack ref advertisement — which
// inforefs.go authorizes as auth.ActionWrite, a w-scoped token rather than an
// r-scoped one. Verified on git 2.47.2 (the image's pin) and 2.54.0 on Alpine
// Linux and 2.50.1 (Apple Git-155) on macOS, by running both subcommands with
// --advertise-refs --stateless-rpc against exactly this repository state: the
// marker appeared for receive-pack on all three and for upload-pack on none,
// and appeared for neither once the alternates file was removed.
//
// Which subcommand reaches which key is precisely the thing that moves between
// git releases, though, so nothing here concludes that the other three routes
// are safe. They are asserted so that a git that widens the set is caught by a
// test rather than in production.
func TestOperatorPlacedRepoConfigNeverExecutes(t *testing.T) {
	tests := []struct {
		name string
		// place writes the hostile config into the repository at repoPath,
		// pointing the command at script.
		place func(t *testing.T, repoPath, script string)
	}{
		{
			name: "in the repository's own config",
			place: func(t *testing.T, repoPath, script string) {
				t.Helper()
				appendToRepoConfig(t, repoPath, "[core]\n\talternateRefsCommand = "+script+"\n")
			},
		},
		{
			// The required case. `git config --list --local` does not expand
			// include.path and `git config --local --get` reports an included
			// key as unset while it is in full effect, so a check built on
			// --local would pass the case above and fail open on this one.
			// internal/store's TestVouchProbeExpandsIncludePath pins the
			// mechanical half; this pins that the handler refuses it.
			name: "pulled in by an include.path",
			place: func(t *testing.T, repoPath, script string) {
				t.Helper()
				included := filepath.Join(repoPath, "included.cfg")
				if err := os.WriteFile(included, []byte("[core]\n\talternateRefsCommand = "+script+"\n"), 0o600); err != nil {
					t.Fatalf("WriteFile(%q): %v", included, err)
				}
				appendToRepoConfig(t, repoPath, "[include]\n\tpath = included.cfg\n")
			},
		},
		{
			// $GIT_DIR/config.worktree, which git reports at scope `worktree`
			// and which --local does not consult at any setting.
			name: "set in config.worktree",
			place: func(t *testing.T, repoPath, script string) {
				t.Helper()
				appendToRepoConfig(t, repoPath, "[extensions]\n\tworktreeConfig = true\n")
				wt := filepath.Join(repoPath, "config.worktree")
				if err := os.WriteFile(wt, []byte("[core]\n\talternateRefsCommand = "+script+"\n"), 0o600); err != nil {
					t.Fatalf("WriteFile(%q): %v", wt, err)
				}
			},
		},
	}

	alternateObjects := donorWithACommit(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, route := range repoExistenceRoutes {
				t.Run(route.name, func(t *testing.T) {
					dataDir := t.TempDir()
					s := store.New(dataDir)

					const repo = "restored"
					path, err := s.RepoPath(repo)
					if err != nil {
						t.Fatalf("RepoPath(%q): %v", repo, err)
					}
					placeOperatorRepo(t, path)

					// The marker lives outside the repository and outside the
					// data directory, so nothing walden does to either can
					// create or remove it.
					observe := t.TempDir()
					marker := filepath.Join(observe, "COMMAND-RAN")
					tt.place(t, path, markerCommand(t, observe, marker))

					// An alternate for the advertisement to consult. Without
					// one git never asks the alternate's refs of anything, so
					// the test would pass for the wrong reason.
					info := filepath.Join(path, "objects", "info")
					if err := os.MkdirAll(info, 0o700); err != nil {
						t.Fatalf("MkdirAll(%q): %v", info, err)
					}
					if err := os.WriteFile(filepath.Join(info, "alternates"), []byte(alternateObjects+"\n"), 0o600); err != nil {
						t.Fatalf("WriteFile alternates: %v", err)
					}

					h, tok := newTestHandler(t, s, "")
					status, body := doRepoExistenceRequest(h, tok, repo, route)

					// The assertion that matters, first: whatever walden
					// answered, the repository's command did not run.
					if _, err := os.Stat(marker); err == nil {
						t.Fatalf("%s: the repository's own config got a command executed (status %d) — "+
							"a refusal that happens after the exec is not a fix", route.name, status)
					} else if !os.IsNotExist(err) {
						t.Fatalf("Stat(%q): %v", marker, err)
					}

					if status != 500 {
						t.Errorf("status = %d, want 500 — the repository resolved fine and walden will not serve it", status)
					}
					if !strings.Contains(body, "repository config unvouched") {
						t.Errorf("body does not name the refusal: %q", body)
					}
					// One line, where "one line" means one line and its
					// terminator: http.Error appends the newline.
					if strings.Contains(strings.TrimSuffix(body, "\n"), "\n") {
						t.Errorf("refusal is not one line: %q", body)
					}
					// The house convention: the refusal names the
					// repository's own config key, never a server path and
					// never the config value.
					if strings.Contains(body, dataDir) || strings.Contains(body, observe) {
						t.Errorf("refusal carries a server path onto the wire: %q", body)
					}
				})
			}
		})
	}
}

// TestWaldenCreatedRepoStillServes is the control, and it is what stops the
// check above from being satisfied by a walden that refuses everything.
// A repository walden created must serve all four entry points exactly as it
// did before this check existed.
func TestWaldenCreatedRepoStillServes(t *testing.T) {
	s := store.New(t.TempDir())
	createRepoForTest(t, s, "healthy")
	h, tok := newTestHandler(t, s, "")

	for _, route := range repoExistenceRoutes {
		status, body := doRepoExistenceRequest(h, tok, "healthy", route)
		if status != 200 {
			t.Errorf("%s: status = %d, want 200 for a repository walden created: %q", route.name, status, body)
		}
		if strings.Contains(body, "unvouched") {
			t.Errorf("%s: walden refused a repository it created itself: %q", route.name, body)
		}
	}
}

// appendToRepoConfig appends raw text to a repository's config file rather
// than going through `git config`, because an operator-placed repository's
// config is a file that travelled with it, not one walden or this test wrote
// key by key.
func appendToRepoConfig(t *testing.T, repoPath, text string) {
	t.Helper()
	cfg := filepath.Join(repoPath, "config")
	f, err := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile(%q): %v", cfg, err)
	}
	defer f.Close()
	if _, err := f.WriteString(text); err != nil {
		t.Fatalf("WriteString(%q): %v", cfg, err)
	}
}
