package main

import (
	"bufio"
	"context"
	"errors"
	"os/exec"
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
