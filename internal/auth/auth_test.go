package auth_test

import (
	"testing"

	"github.com/writtendev/walden/internal/auth"
)

func TestActions(t *testing.T) {
	if auth.ActionRead != "r" {
		t.Errorf("expected ActionRead to be 'r', got %q", auth.ActionRead)
	}
	if auth.ActionWrite != "w" {
		t.Errorf("expected ActionWrite to be 'w', got %q", auth.ActionWrite)
	}
	if auth.ActionCreate != "c" {
		t.Errorf("expected ActionCreate to be 'c', got %q", auth.ActionCreate)
	}
}
