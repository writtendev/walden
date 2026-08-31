package store_test

import (
	"path/filepath"
	"testing"

	"github.com/writtendev/walden/internal/store"
)

func TestStoreRepoPath(t *testing.T) {
	s := store.New("/data")
	got := s.RepoPath("my-repo")
	expected := filepath.Join("/data", "my-repo.git")
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}
