package store_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/store"
)

// gitInitBare initializes a bare repository at path by execing git directly,
// with the same environment and the same explicitly empty template
// store.CreateRepo uses — so a repository built here is the repository
// CreateRepo would have built, and a test about the allowlist is not quietly
// measuring a different git invocation.
func gitInitBare(t *testing.T, path string, extra ...string) {
	t.Helper()
	args := append([]string{"init", "--bare", "--template="}, extra...)
	args = append(args, "--initial-branch=main", path)
	cmd := exec.Command("git", args...)
	cmd.Env = gitProbeEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

// gitProbeEnv is VouchRepoConfig's allowlist environment, so a test's own
// exec cannot see a system or global config the server's child would not.
func gitProbeEnv() []string {
	env := []string{"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null"}
	if p := os.Getenv("PATH"); p != "" {
		env = append(env, "PATH="+p)
	}
	return env
}

// probeKeys asks git the question VouchRepoConfig asks of repoPath and returns
// the scope/key pairs it printed.
func probeKeys(t *testing.T, repoPath string) [][2]string {
	t.Helper()
	args := append([]string{"-C", repoPath}, store.VouchProbeArgsForTest()...)
	cmd := exec.Command("git", args...)
	cmd.Env = gitProbeEnv()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	fields := strings.Split(string(out), "\x00")
	if n := len(fields); n == 0 || fields[n-1] != "" {
		t.Fatalf("git printed a config listing that is not NUL-terminated: %q", out)
	}
	fields = fields[:len(fields)-1]
	if len(fields)%2 != 0 {
		t.Fatalf("git printed %d config fields, which do not pair into scopes and keys: %q", len(fields), out)
	}
	var pairs [][2]string
	for i := 0; i < len(fields); i += 2 {
		pairs = append(pairs, [2]string{fields[i], fields[i+1]})
	}
	return pairs
}

// TestInitBareKeysAreAllowlisted is the drift test, and it is what makes the
// allowlist safe to compile in.
//
// initBareConfigKeys claims to be the keys `git init --bare` writes. Nothing
// in walden enforces that claim; this does, by running the real git on this
// machine and holding its output against the constant. A git version that
// starts writing a key walden does not list — a new default ref format, say —
// turns this test red here and in CI, where it is one line to read and one
// line to fix, instead of refusing in production every repository walden
// creates for itself.
//
// It asserts a subset in one direction only, deliberately. The allowlist is
// permitted to carry keys this git does not write: core.ignorecase and
// core.precomposeunicode appear on macOS and not on Linux, and
// extensions.objectformat and extensions.refstorage appear only under format
// flags walden does not pass. Requiring equality would make the test fail on
// whichever platform it was not written on, which is the failure mode that
// gets a test deleted rather than fixed.
func TestInitBareKeysAreAllowlisted(t *testing.T) {
	allowed := store.InitBareConfigKeysForTest()
	scopes := store.VouchedScopesForTest()

	// The format variants are included because walden passes neither flag
	// today: if a future git defaults to one of them, `git init --bare`
	// starts writing that key and this test is where that shows up.
	for _, tt := range []struct {
		name  string
		extra []string
	}{
		{name: "default"},
		{name: "object-format-sha256", extra: []string{"--object-format=sha256"}},
		{name: "ref-format-reftable", extra: []string{"--ref-format=reftable"}},
		{name: "ref-format-files", extra: []string{"--ref-format=files"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "repo.git")
			gitInitBare(t, path, tt.extra...)

			sawVouchedScope := false
			for _, pair := range probeKeys(t, path) {
				scope, key := pair[0], pair[1]
				if _, ok := scopes[scope]; !ok {
					continue
				}
				sawVouchedScope = true
				if _, ok := allowed[key]; !ok {
					t.Errorf("git init --bare wrote %s at scope %s, which is not in initBareConfigKeys — "+
						"walden would refuse every repository it creates; add the key there, having checked it is inert",
						key, scope)
				}
			}
			if !sawVouchedScope {
				t.Errorf("git printed no keys at a vouched scope for a fresh bare repository — "+
					"the probe or the scope filter no longer describes this git (%s)", gitVersionForTest(t))
			}
		})
	}
}

// gitVersionForTest names the git under test, so a failure above says which
// binary disagreed rather than leaving the next reader to guess.
func gitVersionForTest(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "--version").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// TestVouchRepoConfigAcceptsWhatCreateRepoWrote is the other half of the
// drift test: a repository walden created must be one walden will serve.
// Without it, the allowlist could be correct about `git init --bare` and
// still wrong about CreateRepo, which adds a hook and a publishing rename
// around that init.
func TestVouchRepoConfigAcceptsWhatCreateRepoWrote(t *testing.T) {
	s := store.New(t.TempDir())
	if err := s.CreateRepo(context.Background(), "repo"); err != nil {
		t.Fatalf("CreateRepo: %v", err)
	}
	path, err := s.RepoPath("repo")
	if err != nil {
		t.Fatalf("RepoPath: %v", err)
	}
	if err := s.VouchRepoConfig(context.Background(), path); err != nil {
		t.Fatalf("VouchRepoConfig on a repository walden just created: %v", err)
	}
}

// unvouchedTestKey is a key that is plainly inert, so these tests are about
// the allowlist's shape rather than about any particular key's powers:
// anything outside initBareConfigKeys refuses, dangerous or not. walden
// deliberately keeps no list of keys that are dangerous, so its tests do not
// need one either.
const unvouchedTestKey = "walden.unvouchedtestkey"

// TestVouchRepoConfigRefusesUnvouchedKey drives the check against the three
// ways a repository-scope key reaches git — written into the repository's own
// config, pulled in by an include.path, and set in config.worktree — and
// asserts each refuses in one line, names a key, and wraps the sentinel.
//
// Two of the three refuse on the directive that enables the key rather than on
// the key itself, which is the honest result and is why wantKey is spelled out
// per case instead of being the same key three times: include.path and
// extensions.worktreeConfig are themselves outside the allowlist, git prints
// them before what they pull in, and the first unvouched key is the one
// reported. An allowlist catching the enabling directive is the shape working
// as intended — but it also means this test alone does not prove the probe
// expands includes at all, so TestVouchProbeExpandsIncludePath asserts that
// separately.
func TestVouchRepoConfigRefusesUnvouchedKey(t *testing.T) {
	tests := []struct {
		name    string
		place   func(t *testing.T, repoPath string)
		wantKey string
	}{
		{
			name: "in the repository's own config",
			place: func(t *testing.T, repoPath string) {
				t.Helper()
				appendToFile(t, filepath.Join(repoPath, "config"), "[walden]\n\tunvouchedTestKey = x\n")
			},
			wantKey: unvouchedTestKey,
		},
		{
			name: "pulled in by an include.path",
			place: func(t *testing.T, repoPath string) {
				t.Helper()
				writeFile(t, filepath.Join(repoPath, "included.cfg"), "[walden]\n\tunvouchedTestKey = x\n")
				appendToFile(t, filepath.Join(repoPath, "config"), "[include]\n\tpath = included.cfg\n")
			},
			wantKey: "include.path",
		},
		{
			name: "set in config.worktree",
			place: func(t *testing.T, repoPath string) {
				t.Helper()
				appendToFile(t, filepath.Join(repoPath, "config"), "[extensions]\n\tworktreeConfig = true\n")
				writeFile(t, filepath.Join(repoPath, "config.worktree"), "[walden]\n\tunvouchedTestKey = x\n")
			},
			wantKey: "extensions.worktreeconfig",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Placed by a route other than CreateRepo, which is the whole
			// case: a repository restored from a backup or migrated off
			// another server arrives with a config walden had no part in.
			path := filepath.Join(t.TempDir(), "repo.git")
			gitInitBare(t, path)
			tt.place(t, path)

			err := store.New(filepath.Dir(path)).VouchRepoConfig(context.Background(), path)
			if err == nil {
				t.Fatalf("VouchRepoConfig accepted a repository whose config sets %s", unvouchedTestKey)
			}
			if !errors.Is(err, store.ErrRepoConfigUnvouched) {
				t.Errorf("error does not wrap ErrRepoConfigUnvouched: %v", err)
			}
			if !strings.Contains(err.Error(), tt.wantKey) {
				t.Errorf("refusal does not name %s: %v", tt.wantKey, err)
			}
			if strings.Contains(err.Error(), "\n") {
				t.Errorf("refusal is not one line: %q", err.Error())
			}
			// The refusal names the key and nothing else the repository
			// holds: not the value, which --name-only never read, and not
			// the file the key came from.
			if strings.Contains(err.Error(), "included.cfg") || strings.Contains(err.Error(), path) {
				t.Errorf("refusal names something on disk: %v", err)
			}
		})
	}
}

// TestVouchProbeExpandsIncludePath is the assertion that pins the probe to
// --show-scope, and it is the difference between a check and a decoration.
//
// `git config --list --local` does not expand include.path: it prints the
// include directive and not the keys the included file sets, and `git config
// --local --get` of such a key exits 1 as though it were unset while that key
// is in full effect for every other git command. An audit built on --local
// therefore fails open. `--list --show-scope` does expand includes and labels
// what it finds `local`.
//
// Verified here against whatever git is on this machine, and reproduced by
// hand on 2.47.2 and 2.54.0 (Alpine Linux) and 2.50.1 (Apple Git-155). Both
// halves are asserted, because the one that would silently stop being true is
// the --show-scope half.
func TestVouchProbeExpandsIncludePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repo.git")
	gitInitBare(t, path)
	writeFile(t, filepath.Join(path, "included.cfg"), "[walden]\n\tunvouchedTestKey = x\n")
	appendToFile(t, filepath.Join(path, "config"), "[include]\n\tpath = included.cfg\n")

	found := false
	for _, pair := range probeKeys(t, path) {
		if pair[1] == unvouchedTestKey {
			found = true
			if pair[0] != "local" {
				t.Errorf("included key reported at scope %q, want local — the scope filter would skip it", pair[0])
			}
		}
	}
	if !found {
		t.Fatalf("the probe did not report %s, so it is not expanding include.path on %s — "+
			"this check would fail open", unvouchedTestKey, gitVersionForTest(t))
	}

	// The other half: the narrower --local listing this probe deliberately
	// does not use cannot see the key at all. If this ever starts failing,
	// git has changed and the probe's comment needs rewriting — but the
	// probe itself is still the safe one.
	args := []string{"-C", path, "config", "--list", "--local", "--name-only"}
	cmd := exec.Command("git", args...)
	cmd.Env = gitProbeEnv()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	if strings.Contains(string(out), unvouchedTestKey) {
		t.Errorf("--list --local reported %s on %s; the probe's reason for using --show-scope needs rewriting",
			unvouchedTestKey, gitVersionForTest(t))
	}
}

// TestVouchRepoConfigRefusesMissingRepository pins the no-fail-open rule: a
// probe that cannot answer refuses, and does so without claiming the
// repository was clean.
func TestVouchRepoConfigRefusesMissingRepository(t *testing.T) {
	dir := t.TempDir()
	err := store.New(dir).VouchRepoConfig(context.Background(), filepath.Join(dir, "nothing-here.git"))
	if err == nil {
		t.Fatal("VouchRepoConfig accepted a path with no repository at it")
	}
	if !errors.Is(err, store.ErrRepoConfigUnvouched) {
		t.Errorf("error does not wrap ErrRepoConfigUnvouched: %v", err)
	}
	if strings.Contains(err.Error(), dir) {
		t.Errorf("probe-failure refusal carries a server path onto the wire: %v", err)
	}
}

// TestFirstUnvouchedKeyFraming drives the parser against the framing git
// actually produces and against outputs it must not read as "clean".
//
// The vouched output below is the exact bytes `git config --list --show-scope
// --name-only -z` printed for a freshly initialized bare repository on git
// 2.47.2 and 2.54.0 (Alpine Linux); the unknown-scope entries in the macOS
// case are the ones Apple Git 2.50.1 prints from the Command Line Tools
// gitconfig even with GIT_CONFIG_SYSTEM=/dev/null, which is why the scope
// filter is explicit rather than "everything git reports must be
// allowlisted".
func TestFirstUnvouchedKeyFraming(t *testing.T) {
	tests := []struct {
		name    string
		out     string
		wantKey string
		wantErr bool
	}{
		{
			name: "fresh bare repository on linux",
			out:  "local\x00core.repositoryformatversion\x00local\x00core.filemode\x00local\x00core.bare\x00",
		},
		{
			name: "fresh bare repository on macos, unknown scope ignored",
			out: "unknown\x00credential.helper\x00unknown\x00init.defaultbranch\x00" +
				"local\x00core.repositoryformatversion\x00local\x00core.filemode\x00local\x00core.bare\x00" +
				"local\x00core.ignorecase\x00local\x00core.precomposeunicode\x00",
		},
		{
			name:    "key at local scope",
			out:     "local\x00core.bare\x00local\x00walden.extra\x00",
			wantKey: "walden.extra",
		},
		{
			name:    "key at worktree scope",
			out:     "local\x00core.bare\x00worktree\x00walden.extra\x00",
			wantKey: "walden.extra",
		},
		{
			name: "system and global scopes are not a repository's to carry",
			out:  "system\x00walden.extra\x00global\x00walden.other\x00local\x00core.bare\x00",
		},
		{
			name:    "empty output has not answered",
			out:     "",
			wantErr: true,
		},
		{
			name:    "unterminated output",
			out:     "local\x00core.bare",
			wantErr: true,
		},
		{
			name:    "odd field count",
			out:     "local\x00core.bare\x00local\x00",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := store.FirstUnvouchedKeyForTest([]byte(tt.out))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("got key %q, nil error; want an error — an unreadable listing must not read as clean", key)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if key != tt.wantKey {
				t.Errorf("key = %q, want %q", key, tt.wantKey)
			}
		})
	}
}

// TestVouchRepoConfigBoundsTheReportedKey pins that a subsection name out of a
// repository's own config file cannot grow the one-line refusal without bound.
// Section and variable names are git's own and short; what sits between them is
// arbitrary text the repository supplied.
//
// It also pins the remedy: an elided key cannot be handed to `git config
// --unset`, so the refusal that elides one must not print that command.
func TestVouchRepoConfigBoundsTheReportedKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repo.git")
	gitInitBare(t, path)
	long := strings.Repeat("a", 4096)
	appendToFile(t, filepath.Join(path, "config"), "[walden \""+long+"\"]\n\tkey = x\n")

	err := store.New(filepath.Dir(path)).VouchRepoConfig(context.Background(), path)
	if err == nil {
		t.Fatal("VouchRepoConfig accepted a repository carrying an absurdly long key")
	}
	msg := err.Error()
	if len(msg) > 512 {
		t.Errorf("refusal is %d bytes; the reported key was not bounded", len(msg))
	}
	if strings.Contains(msg, "git config --unset") {
		t.Errorf("refusal prints an unset command for an elided key, which would not work: %v", err)
	}
	if !strings.Contains(msg, "walden.") {
		t.Errorf("refusal lost the key's leading section: %v", err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

func appendToFile(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile(%q): %v", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("WriteString(%q): %v", path, err)
	}
}
