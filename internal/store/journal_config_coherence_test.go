package store_test

import (
	"testing"

	"github.com/writtendev/walden/internal/config"
	"github.com/writtendev/walden/internal/store"
)

// TestConfigAndStoreAgreeOnJournalRefusalWording is the regression for item 5
// of WALD-91: Config.Validate keeps its own shallow check of the journal URL
// (it runs first, on the boot path, before store's deep parse), but it must
// say exactly what store.ParseJournalURL would say for the same cause. Two
// vocabularies for the same knob is confusing on its own, and a second
// wording invites the two to drift apart the next time either is edited.
//
// This does not belong in internal/store's leak test: that file's guarantee
// is "never leaks a secret," which is a property of every refusal string.
// This is a narrower claim about two specific refusals matching each other
// byte for byte, and deserves its own test so a future edit to one wording
// without the other fails here, by name, rather than as a fresh finding in
// the next review.
func TestConfigAndStoreAgreeOnJournalRefusalWording(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"unparseable-url", "://invalid-url"},
		{"no-scheme", "no-scheme-bucket/path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, configErr := config.LoadWithEnv([]string{"--journal", tt.raw}, envLookup(nil))
			if configErr == nil {
				t.Fatalf("config.LoadWithEnv(%q) succeeded, want refusal", tt.raw)
			}

			_, storeErr := store.ParseJournalURL(tt.raw, envLookup(nil))
			if storeErr == nil {
				t.Fatalf("store.ParseJournalURL(%q) succeeded, want refusal", tt.raw)
			}

			if configErr.Error() != storeErr.Error() {
				t.Errorf("config and store disagree on the refusal for %q:\nconfig: %q\nstore:  %q", tt.raw, configErr.Error(), storeErr.Error())
			}
		})
	}
}
