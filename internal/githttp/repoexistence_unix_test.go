//go:build unix

package githttp_test

import (
	"net/http"
	"strings"
	"syscall"
	"testing"

	"github.com/writtendev/walden/internal/store"
)

// TestRepoExistenceFIFOAgreesAcrossEntryPoints extends
// TestRepoExistenceAgreesAcrossEntryPoints (repoexistence_test.go) with the
// FIFO state done-when #2 names alongside the regular file and dangling
// symlink already covered there. It needs syscall.Mkfifo, which does not
// build portably outside unix; guarded with //go:build unix, matching
// export_unix_test.go and uploadpack_unix_test.go's existing precedent.
func TestRepoExistenceFIFOAgreesAcrossEntryPoints(t *testing.T) {
	dataDir := t.TempDir()
	s := store.New(dataDir)
	const repo = "fifotarget"
	path, err := s.RepoPath(repo)
	if err != nil {
		t.Fatalf("RepoPath(%q): %v", repo, err)
	}
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Fatalf("Mkfifo(%q): %v", path, err)
	}

	h, tok := newTestHandler(t, s, "")

	type result struct {
		route  string
		status int
		body   string
	}
	var results []result
	for _, route := range repoExistenceRoutes {
		status, body := doRepoExistenceRequest(h, tok, repo, route)
		results = append(results, result{route.name, status, body})

		if status != http.StatusInternalServerError {
			t.Errorf("%s: status = %d, want %d", route.name, status, http.StatusInternalServerError)
		}
		if strings.Contains(body, dataDir) {
			t.Errorf("%s: response body contains the data directory path %q: %q", route.name, dataDir, body)
		}
	}

	for i := 1; i < len(results); i++ {
		if results[i].status != results[0].status {
			t.Errorf("%s status = %d, %s status = %d, want agreement",
				results[0].route, results[0].status, results[i].route, results[i].status)
		}
		if results[i].body != results[0].body {
			t.Errorf("%s body = %q, %s body = %q, want byte-identical",
				results[0].route, results[0].body, results[i].route, results[i].body)
		}
	}
}
