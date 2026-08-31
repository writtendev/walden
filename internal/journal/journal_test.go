package journal_test

import (
	"testing"

	"github.com/writtendev/walden/internal/journal"
)

func TestMetaStreamID(t *testing.T) {
	if journal.MetaStreamID != "_meta" {
		t.Errorf("expected MetaStreamID to be '_meta', got %q", journal.MetaStreamID)
	}
}
