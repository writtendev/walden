package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/store"
)

// Two well-formed SHA-1 OIDs shared with internal/journal/reftx_test.go's
// TestValidateRefUpdate fixtures, so a reader who has seen one has seen
// both.
const (
	testOldOID = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
	testNewOID = "8a65c6d3715c0e1e92d6e3e5362e49c7198cfb60"
)

func TestParseRefUpdatesAcceptance(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []journal.RefUpdate
	}{
		{
			name: "empty input yields zero updates",
			in:   "",
			want: nil,
		},
		{
			name: "creation (zero old_oid)",
			in:   journal.ZeroOID40 + " " + testNewOID + " refs/heads/main\n",
			want: []journal.RefUpdate{{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: testNewOID}},
		},
		{
			name: "update",
			in:   testOldOID + " " + testNewOID + " refs/heads/main\n",
			want: []journal.RefUpdate{{Ref: "refs/heads/main", OldOID: testOldOID, NewOID: testNewOID}},
		},
		{
			name: "deletion (zero new_oid)",
			in:   testOldOID + " " + journal.ZeroOID40 + " refs/heads/feature\n",
			want: []journal.RefUpdate{{Ref: "refs/heads/feature", OldOID: testOldOID, NewOID: journal.ZeroOID40}},
		},
		{
			name: "several lines at once",
			in: journal.ZeroOID40 + " " + testNewOID + " refs/heads/main\n" +
				testOldOID + " " + journal.ZeroOID40 + " refs/heads/feature\n",
			want: []journal.RefUpdate{
				{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: testNewOID},
				{Ref: "refs/heads/feature", OldOID: testOldOID, NewOID: journal.ZeroOID40},
			},
		},
		{
			name: "ref name with non-ASCII bytes preserved byte-for-byte",
			in:   journal.ZeroOID40 + " " + testNewOID + " refs/heads/föö-bär\n",
			want: []journal.RefUpdate{{Ref: "refs/heads/föö-bär", OldOID: journal.ZeroOID40, NewOID: testNewOID}},
		},
		{
			// journal.ValidateOID accepts uppercase hex by design --
			// TestMarshalRefTxLowercasesWithoutMutatingCaller
			// (internal/journal/reftx_test.go) confirms uppercase OIDs are
			// valid input, lowercased only at marshal time. This is
			// acceptance, not a refusal; OID case handling itself is
			// WALD-109's, not this ticket's.
			name: "uppercase OID is accepted, case preserved",
			in:   strings.ToUpper(journal.ZeroOID40) + " " + strings.ToUpper(testNewOID) + " refs/heads/main\n",
			want: []journal.RefUpdate{{
				Ref:    "refs/heads/main",
				OldOID: strings.ToUpper(journal.ZeroOID40),
				NewOID: strings.ToUpper(testNewOID),
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRefUpdates(strings.NewReader(tt.in))
			if err != nil {
				t.Fatalf("parseRefUpdates(%q) error = %v", tt.in, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("parseRefUpdates(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("update[%d] = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestParseRefUpdatesRefusals(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantSub string
	}{
		{
			name:    "too few fields: no space at all",
			in:      "onefield\n",
			wantSub: "malformed line",
		},
		{
			name:    "too few fields: only one space",
			in:      journal.ZeroOID40 + " " + testNewOID + "\n",
			wantSub: "malformed line",
		},
		{
			name:    "too many fields: an unescaped extra space lands in the ref and fails as an illegal character",
			in:      journal.ZeroOID40 + " " + testNewOID + " refs/heads/ma in\n",
			wantSub: "invalid ref name",
		},
		{
			name:    "short OID",
			in:      "abcd " + testNewOID + " refs/heads/main\n",
			wantSub: "invalid old_oid",
		},
		{
			name:    "long OID",
			in:      strings.Repeat("a", 41) + " " + testNewOID + " refs/heads/main\n",
			wantSub: "invalid old_oid",
		},
		{
			name:    "mismatched OID lengths",
			in:      journal.ZeroOID40 + " " + journal.ZeroOID64 + " refs/heads/main\n",
			wantSub: "mismatched lengths",
		},
		{
			name:    "illegal ref name",
			in:      journal.ZeroOID40 + " " + testNewOID + " refs/heads/../escape\n",
			wantSub: "invalid ref name",
		},
		{
			name: "duplicate ref",
			in: journal.ZeroOID40 + " " + testNewOID + " refs/heads/main\n" +
				testNewOID + " " + testOldOID + " refs/heads/main\n",
			wantSub: "duplicate ref update",
		},
		{
			name:    "no-op triple",
			in:      testOldOID + " " + testOldOID + " refs/heads/main\n",
			wantSub: "no-op ref update",
		},
		{
			// git receive-pack runs pre-receive before its own
			// "funny refname" check, so this line reaches the hook
			// verbatim. bufio.ScanLines would have dropped the '\r' and
			// handed back "refs/heads/ev" -- a ref name the client never
			// sent, which ValidateRefName then accepts. Keeping the byte
			// lets ValidateRefName refuse it, which is spec §5.2's
			// byte-preservation invariant doing its job.
			name:    "trailing carriage return stays in the ref name and is refused",
			in:      journal.ZeroOID40 + " " + testNewOID + " refs/heads/ev\r\n",
			wantSub: "byte 0x0d",
		},
		{
			name:    "a line past the scanner's buffer",
			in:      journal.ZeroOID40 + " " + testNewOID + " refs/heads/" + strings.Repeat("x", bufio.MaxScanTokenSize) + "\n",
			wantSub: "reading stdin",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseRefUpdates(strings.NewReader(tt.in))
			if err == nil {
				t.Fatalf("parseRefUpdates succeeded, want a refusal containing %q", tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantSub)
			}
			if strings.Contains(err.Error(), "\n") {
				t.Errorf("expected a single-line refusal, got: %q", err.Error())
			}
		})
	}
}

// TestParseRefUpdatesDoesNotCollapseCarriageReturnOntoItsTwin pins the
// second consequence of splitting with bufio.ScanLines: "refs/heads/x" and
// "refs/heads/x\r" are different ref names, and dropping the '\r' made them
// the same map key, so the push was refused for a duplicate ref it did not
// contain. The refusal must name the real cause -- the control byte in the
// second ref -- not a duplicate.
func TestParseRefUpdatesDoesNotCollapseCarriageReturnOntoItsTwin(t *testing.T) {
	in := journal.ZeroOID40 + " " + testNewOID + " refs/heads/x\n" +
		testOldOID + " " + journal.ZeroOID40 + " refs/heads/x\r\n"

	_, err := parseRefUpdates(strings.NewReader(in))
	if err == nil {
		t.Fatal("parseRefUpdates succeeded, want a refusal for the control byte")
	}
	if strings.Contains(err.Error(), "duplicate ref update") {
		t.Errorf("refused as a duplicate ref, which mis-states the cause: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "byte 0x0d") {
		t.Errorf("error = %q, want it to name the carriage return", err.Error())
	}
}

// lookupEnvFrom builds the injected lookupEnv resolveHook takes out of a
// plain map, the same shape os.LookupEnv itself has.
func lookupEnvFrom(vals map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		v, ok := vals[key]
		return v, ok
	}
}

// initBareRepo creates a bare repository at the path store.New(dataDir)
// resolves repo to, so resolveHook's RepoExists check finds it.
func initBareRepo(t *testing.T, dataDir, repo string) string {
	t.Helper()
	path, err := store.New(dataDir).RepoPath(repo)
	if err != nil {
		t.Fatalf("RepoPath(%q): %v", repo, err)
	}
	if out, err := exec.Command("git", "init", "-q", "--bare", path).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare %s: %v\n%s", path, err, out)
	}
	return path
}

func TestResolveHookResolvesFromTheThreeWaldenNamesOnly(t *testing.T) {
	dataDir := t.TempDir()
	const repo = "repo"
	repoPath := initBareRepo(t, dataDir, repo)

	updates := []journal.RefUpdate{{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: testNewOID}}
	lookup := lookupEnvFrom(map[string]string{
		"WALDEN_REPO":     repo,
		"WALDEN_DATA_DIR": dataDir,
	})

	req, err := resolveHook(context.Background(), lookup, updates)
	if err != nil {
		t.Fatalf("resolveHook: %v", err)
	}
	if req.Repo != repo {
		t.Errorf("Repo = %q, want %q", req.Repo, repo)
	}
	if req.DataDir != dataDir {
		t.Errorf("DataDir = %q, want %q", req.DataDir, dataDir)
	}
	if req.RepoPath != repoPath {
		t.Errorf("RepoPath = %q, want %q", req.RepoPath, repoPath)
	}
	// An unset WALDEN_JOURNAL yields Journal == nil rather than an error --
	// this is journal-less mode, not a missing-config refusal.
	if req.Journal != nil {
		t.Errorf("expected nil Journal in journal-less mode, got %+v", req.Journal)
	}
	if len(req.Updates) != 1 || req.Updates[0] != updates[0] {
		t.Errorf("Updates = %+v, want %+v", req.Updates, updates)
	}
}

func TestResolveHookRefusals(t *testing.T) {
	dataDir := t.TempDir()
	const repo = "repo"
	initBareRepo(t, dataDir, repo)

	updates := []journal.RefUpdate{{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: testNewOID}}

	tests := []struct {
		name    string
		env     map[string]string
		wantSub string
		wantIs  error
	}{
		{
			name:    "missing repo",
			env:     map[string]string{"WALDEN_DATA_DIR": dataDir},
			wantSub: "WALDEN_REPO",
		},
		{
			name:    "missing data dir",
			env:     map[string]string{"WALDEN_REPO": repo},
			wantSub: "WALDEN_DATA_DIR",
		},
		{
			name:    "invalid identifier",
			env:     map[string]string{"WALDEN_REPO": "../escape", "WALDEN_DATA_DIR": dataDir},
			wantSub: "invalid repository identifier",
			wantIs:  auth.ErrInvalidRepo,
		},
		{
			name:    "absent repo directory",
			env:     map[string]string{"WALDEN_REPO": "does-not-exist", "WALDEN_DATA_DIR": dataDir},
			wantSub: "does not exist",
			wantIs:  store.ErrRepoNotFound,
		},
		{
			name: "malformed WALDEN_JOURNAL",
			env: map[string]string{
				"WALDEN_REPO":     repo,
				"WALDEN_DATA_DIR": dataDir,
				"WALDEN_JOURNAL":  "ftp://example.org/bucket",
			},
			wantSub: "invalid journal",
		},
		{
			// Objects landed somewhere walden is not looking. Journaling
			// nothing for them would be a guess, so this refuses.
			name: "GIT_OBJECT_DIRECTORY without GIT_QUARANTINE_PATH",
			env: map[string]string{
				"WALDEN_REPO":          repo,
				"WALDEN_DATA_DIR":      dataDir,
				"GIT_OBJECT_DIRECTORY": "/somewhere/else/objects",
			},
			wantSub: "GIT_OBJECT_DIRECTORY",
		},
		{
			name: "quarantine outside the repository",
			env: map[string]string{
				"WALDEN_REPO":         repo,
				"WALDEN_DATA_DIR":     dataDir,
				"GIT_QUARANTINE_PATH": filepath.Join(dataDir, "elsewhere", "objects", "tmp_objdir-incoming-x"),
			},
			wantSub: "resolves outside the repository",
		},
		{
			name: "quarantine escaping the repository with ..",
			env: map[string]string{
				"WALDEN_REPO":         repo,
				"WALDEN_DATA_DIR":     dataDir,
				"GIT_QUARANTINE_PATH": filepath.Join(dataDir, "repo.git", "objects", "..", "..", "tmp_objdir-incoming-x"),
			},
			wantSub: "resolves outside the repository",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolveHook(context.Background(), lookupEnvFrom(tt.env), updates)
			if err == nil {
				t.Fatalf("resolveHook succeeded, want a refusal containing %q", tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantSub)
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("errors.Is(err, %v) = false, err = %v", tt.wantIs, err)
			}
			if strings.Contains(err.Error(), "\n") {
				t.Errorf("expected a single-line refusal, got: %q", err.Error())
			}
		})
	}
}

// TestResolveHookQuarantine covers the three cases resolveQuarantine
// recognizes and no fourth (WALD-44). The two refusals -- an object
// directory with no quarantine path, and a quarantine resolving outside
// the repository -- are cases in TestResolveHookRefusals above.
func TestResolveHookQuarantine(t *testing.T) {
	dataDir := t.TempDir()
	const repo = "repo"
	repoPath := initBareRepo(t, dataDir, repo)

	updates := []journal.RefUpdate{{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: testNewOID}}

	t.Run("cleaned-and-absolute", func(t *testing.T) {
		// git's own spelling: GIT_DIR is ".", so the path it exports has
		// a "/./" in the middle of it. Cleaning is what removes it.
		sep := string(os.PathSeparator)
		gitSpelling := repoPath + sep + "." + sep + filepath.Join("objects", "tmp_objdir-incoming-AbCdEf")
		want := filepath.Join(repoPath, "objects", "tmp_objdir-incoming-AbCdEf")

		req, err := resolveHook(context.Background(), lookupEnvFrom(map[string]string{
			"WALDEN_REPO":          repo,
			"WALDEN_DATA_DIR":      dataDir,
			"GIT_QUARANTINE_PATH":  gitSpelling,
			"GIT_OBJECT_DIRECTORY": gitSpelling,
		}), updates)
		if err != nil {
			t.Fatalf("resolveHook: %v", err)
		}
		if req.Quarantine != want {
			t.Errorf("Quarantine = %q, want %q", req.Quarantine, want)
		}
		if strings.Contains(req.Quarantine, sep+"."+sep) {
			t.Errorf("Quarantine %q still carries git's \"/./\" spelling", req.Quarantine)
		}
	})

	t.Run("repository-that-is-itself-a-symlink", func(t *testing.T) {
		// store.RepoPath resolves the data directory but leaves the
		// "<repo>.git" leaf as written, so <dataDir>/link.git pointing at
		// a sibling inside the data directory is a shape it deliberately
		// permits. git reports the quarantine directory under the
		// resolved path -- it derives GIT_QUARANTINE_PATH from getcwd()
		// after chdir -- so a lexical containment test against the
		// unresolved leaf would refuse every push to that repository
		// (round 1 finding 2).
		linkDir := t.TempDir()
		target := initBareRepo(t, linkDir, "real")
		if err := os.Symlink(target, filepath.Join(linkDir, "link.git")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		quarantine := filepath.Join(target, "objects", "tmp_objdir-incoming-AbCdEf")

		req, err := resolveHook(context.Background(), lookupEnvFrom(map[string]string{
			"WALDEN_REPO":         "link",
			"WALDEN_DATA_DIR":     linkDir,
			"GIT_QUARANTINE_PATH": quarantine,
		}), updates)
		if err != nil {
			t.Fatalf("resolveHook: %v", err)
		}
		if req.Quarantine != quarantine {
			t.Errorf("Quarantine = %q, want %q", req.Quarantine, quarantine)
		}
	})

	t.Run("neither-variable-set-is-a-delete-only-push", func(t *testing.T) {
		req, err := resolveHook(context.Background(), lookupEnvFrom(map[string]string{
			"WALDEN_REPO":     repo,
			"WALDEN_DATA_DIR": dataDir,
		}), updates)
		if err != nil {
			t.Fatalf("resolveHook: %v", err)
		}
		if req.Quarantine != "" {
			t.Errorf("Quarantine = %q, want empty: a delete-only push gets no quarantine directory at all", req.Quarantine)
		}
	})

	t.Run("divergent-object-directory-is-not-an-equality-check", func(t *testing.T) {
		// githooks(5) names GIT_QUARANTINE_PATH as the variable a
		// pre-receive hook reads, so it is the single authority here. A
		// future git spelling GIT_OBJECT_DIRECTORY differently must not
		// turn into a refused push.
		quarantine := filepath.Join(repoPath, "objects", "tmp_objdir-incoming-x")
		req, err := resolveHook(context.Background(), lookupEnvFrom(map[string]string{
			"WALDEN_REPO":          repo,
			"WALDEN_DATA_DIR":      dataDir,
			"GIT_QUARANTINE_PATH":  quarantine,
			"GIT_OBJECT_DIRECTORY": filepath.Join(repoPath, "objects"),
		}), updates)
		if err != nil {
			t.Fatalf("resolveHook: %v", err)
		}
		if req.Quarantine != quarantine {
			t.Errorf("Quarantine = %q, want %q", req.Quarantine, quarantine)
		}
	})
}

// zeroObjectPack is the 32-byte packfile git's index-pack writes when a
// push moves a ref to an object the repository already holds: "PACK",
// version 2, object count 0, then the 20-byte trailing checksum.
// Confirmed against git 2.50.1 by pushing a ref to an existing object
// with receive.unpackLimit=0.
func zeroObjectPack() []byte {
	return append([]byte{'P', 'A', 'C', 'K', 0, 0, 0, 2, 0, 0, 0, 0}, make([]byte, 20)...)
}

// realPackfile builds an actual git packfile holding more than one object
// -- a commit and its tree -- by driving the real git binary, so
// captureSegment and the hook tests below run against bytes git wrote
// rather than bytes this suite invented.
func realPackfile(t *testing.T) []byte {
	t.Helper()
	work := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "Test"},
		{"commit", "-q", "--allow-empty", "-m", "packed"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = work
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}

	list := exec.Command("git", "rev-list", "--objects", "--all")
	list.Dir = work
	objects, err := list.Output()
	if err != nil {
		t.Fatalf("git rev-list --objects --all: %v", err)
	}

	packObjects := exec.Command("git", "pack-objects", "--stdout", "-q")
	packObjects.Dir = work
	packObjects.Stdin = bytes.NewReader(objects)
	pack, err := packObjects.Output()
	if err != nil {
		t.Fatalf("git pack-objects --stdout: %v", err)
	}
	count, err := journal.PackfileObjectCount(pack)
	if err != nil {
		t.Fatalf("git pack-objects produced something that is not a packfile: %v", err)
	}
	if count < 2 {
		t.Fatalf("git pack-objects produced object count %d, want at least 2", count)
	}
	return pack
}

// TestCaptureSegment covers every shape a quarantine directory reaches the
// hook in. A nil file means "this push has no segment to journal", which
// is three distinct situations and an error in none of them.
func TestCaptureSegment(t *testing.T) {
	pack := realPackfile(t)

	// setup writes one case's quarantine tree under root and returns the
	// GIT_QUARANTINE_PATH value for it; an empty return means the push
	// had no quarantine directory at all.
	tests := []struct {
		name     string
		setup    func(t *testing.T, root string) string
		wantSize int64
		wantSub  string // non-empty: expect a refusal naming this
	}{
		{
			name:  "no quarantine directory at all",
			setup: func(t *testing.T, root string) string { return "" },
		},
		{
			name: "quarantine with no pack directory",
			setup: func(t *testing.T, root string) string {
				return mkQuarantine(t, root)
			},
		},
		{
			name: "pack directory holding nothing",
			setup: func(t *testing.T, root string) string {
				q := mkQuarantine(t, root)
				mkdirAll(t, filepath.Join(q, "pack"))
				return q
			},
		},
		{
			name: "pack directory holding only index-pack's siblings",
			setup: func(t *testing.T, root string) string {
				q := mkQuarantine(t, root)
				dir := filepath.Join(q, "pack")
				mkdirAll(t, dir)
				for _, name := range []string{"pack-abc.idx", "pack-abc.keep", "pack-abc.rev"} {
					writeFile(t, filepath.Join(dir, name), []byte("not a pack"))
				}
				return q
			},
		},
		{
			// The failure this whole change exists to prevent, and the
			// only runtime detection behind the receive.unpackLimit=0
			// knob: git's default unpackLimit writes a small push into
			// loose objects and leaves pack/ empty, which must refuse
			// rather than journal "this push introduced no objects"
			// (round 1 finding 1). Deleting this case deletes the
			// detection with it.
			name: "loose objects beside an empty pack directory refuse",
			setup: func(t *testing.T, root string) string {
				q := mkQuarantine(t, root)
				mkdirAll(t, filepath.Join(q, "pack"))
				mkLooseObject(t, q)
				return q
			},
			wantSub: "loose objects",
		},
		{
			// Same shape, reached through the other branch: git creates
			// pack/ lazily, so an unpacked push may leave no pack/ at all.
			name: "loose objects with no pack directory refuse",
			setup: func(t *testing.T, root string) string {
				q := mkQuarantine(t, root)
				mkLooseObject(t, q)
				return q
			},
			wantSub: "loose objects",
		},
		{
			// GIT_QUARANTINE_PATH naming a directory that is not there:
			// git creates it before running the hook, so walden cannot
			// see what this push received and does not guess that it
			// received nothing.
			name: "an unreadable quarantine directory refuses",
			setup: func(t *testing.T, root string) string {
				return filepath.Join(root, "objects", "tmp_objdir-incoming-gone")
			},
			wantSub: "cannot read the quarantine directory",
		},
		{
			name: "zero-object pack is no segment",
			setup: func(t *testing.T, root string) string {
				q := mkQuarantine(t, root)
				dir := filepath.Join(q, "pack")
				mkdirAll(t, dir)
				writeFile(t, filepath.Join(dir, "pack-abc.pack"), zeroObjectPack())
				return q
			},
		},
		{
			name: "a real pack is captured whole",
			setup: func(t *testing.T, root string) string {
				q := mkQuarantine(t, root)
				dir := filepath.Join(q, "pack")
				mkdirAll(t, dir)
				writeFile(t, filepath.Join(dir, "pack-abc.pack"), pack)
				writeFile(t, filepath.Join(dir, "pack-abc.idx"), []byte("ignored"))
				writeFile(t, filepath.Join(dir, "pack-abc.keep"), nil)
				return q
			},
			wantSize: int64(len(pack)),
		},
		{
			name: "two packs are a refusal naming the count",
			setup: func(t *testing.T, root string) string {
				q := mkQuarantine(t, root)
				dir := filepath.Join(q, "pack")
				mkdirAll(t, dir)
				writeFile(t, filepath.Join(dir, "pack-abc.pack"), pack)
				writeFile(t, filepath.Join(dir, "pack-def.pack"), pack)
				return q
			},
			wantSub: "2 packfiles",
		},
		{
			name: "a pack too short to be one is a refusal",
			setup: func(t *testing.T, root string) string {
				q := mkQuarantine(t, root)
				dir := filepath.Join(q, "pack")
				mkdirAll(t, dir)
				writeFile(t, filepath.Join(dir, "pack-abc.pack"), []byte("PACK\x00\x00\x00\x02"))
				return q
			},
			wantSub: "header",
		},
		{
			name: "a pack with the wrong magic is a refusal",
			setup: func(t *testing.T, root string) string {
				q := mkQuarantine(t, root)
				dir := filepath.Join(q, "pack")
				mkdirAll(t, dir)
				bad := zeroObjectPack()
				copy(bad, "KCAP")
				writeFile(t, filepath.Join(dir, "pack-abc.pack"), bad)
				return q
			},
			wantSub: "invalid header magic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &hookRequest{Quarantine: tt.setup(t, t.TempDir())}

			f, size, err := captureSegment(req)
			if f != nil {
				defer f.Close()
			}

			if tt.wantSub != "" {
				if err == nil {
					t.Fatalf("captureSegment succeeded, want a refusal containing %q", tt.wantSub)
				}
				if !strings.Contains(err.Error(), tt.wantSub) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.wantSub)
				}
				if strings.ContainsAny(err.Error(), "\n\r") {
					t.Errorf("expected a single-line refusal, got: %q", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("captureSegment: %v", err)
			}
			if tt.wantSize == 0 {
				if f != nil {
					t.Fatalf("captureSegment returned a file, want nil: there is nothing to journal")
				}
				return
			}
			if f == nil {
				t.Fatal("captureSegment returned no file, want the captured pack")
			}
			if size != tt.wantSize {
				t.Errorf("size = %d, want %d", size, tt.wantSize)
			}
			// Readable from offset 0 through ReadAt: that is the
			// io.ReaderAt contract AppendSegment relies on, and the bytes
			// must be the pack's, verbatim.
			got := make([]byte, size)
			if _, err := f.ReadAt(got, 0); err != nil {
				t.Fatalf("ReadAt: %v", err)
			}
			if !bytes.Equal(got, pack) {
				t.Errorf("captured bytes differ from the packfile on disk")
			}
		})
	}
}

// mkQuarantine creates a directory shaped like the one git exports as
// GIT_QUARANTINE_PATH and returns its path.
func mkQuarantine(t *testing.T, root string) string {
	t.Helper()
	dir := filepath.Join(root, "objects", "tmp_objdir-incoming-AbCdEf")
	mkdirAll(t, dir)
	return dir
}

// mkLooseObject writes one loose object into a quarantine directory the
// way git does when it unpacks a push instead of packing it: a file under
// the two-hex-character fan-out directory named for the first byte of its
// object id. The bytes are irrelevant -- walden counts what git left, it
// never opens an object -- but the layout is not.
func mkLooseObject(t *testing.T, quarantine string) {
	t.Helper()
	dir := filepath.Join(quarantine, "3c")
	mkdirAll(t, dir)
	writeFile(t, filepath.Join(dir, "79adf14db2a78562dba199b1b044f986a48a9c"), []byte("zlib-compressed object"))
}

func mkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", dir, err)
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}
