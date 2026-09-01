package refusal

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestRefusalFormatting(t *testing.T) {
	tests := []struct {
		name     string
		refusal  *Refusal
		expected string
	}{
		{
			name:     "full-refusal",
			refusal:  New("command", "unknown subcommand 'bogus'", "run 'walden help' for usage"),
			expected: "command: unknown subcommand 'bogus' (run 'walden help' for usage)",
		},
		{
			name:     "empty-fix",
			refusal:  New("serve", "listen address :8470 already in use", ""),
			expected: "serve: listen address :8470 already in use",
		},
		{
			name:     "empty-what-and-why",
			refusal:  New("", "", ""),
			expected: "refused: unspecified reason",
		},
		{
			name:     "multiline-inputs-sanitized",
			refusal:  New("serve\ncommand", "data dir\r\nnot accessible\n(errno 13)", "check permissions\nand retry"),
			expected: "serve command: data dir not accessible (errno 13) (check permissions and retry)",
		},
		{
			name:     "consecutive-whitespace-collapsed",
			refusal:  New("  token    create  ", "  invalid   scope  string  ", "  use  'rw:repo'  "),
			expected: "token create: invalid scope string (use 'rw:repo')",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.refusal.Error()
			if got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
			if strings.Contains(got, "\n") || strings.Contains(got, "\r") {
				t.Errorf("Error() contains newline characters: %q", got)
			}
		})
	}
}

func TestFromError(t *testing.T) {
	t.Run("nil-error", func(t *testing.T) {
		ref := FromError("action", nil, "do something")
		got := ref.Error()
		want := "action: unspecified reason (do something)"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("wrapped-error-sanitized", func(t *testing.T) {
		inner := errors.New("underlying network failure\nconnection reset by peer")
		wrapped := fmt.Errorf("failed to reach object storage: %w", inner)

		ref := FromError("journal append", wrapped, "verify WALDEN_JOURNAL configuration")
		got := ref.Error()

		if strings.Contains(got, "\n") || strings.Contains(got, "\r") {
			t.Fatalf("refusal contains newline: %q", got)
		}

		expected := "journal append: failed to reach object storage: underlying network failure connection reset by peer (verify WALDEN_JOURNAL configuration)"
		if got != expected {
			t.Errorf("got %q, want %q", got, expected)
		}
	})

	t.Run("stack-trace-sanitized", func(t *testing.T) {
		rawErr := errors.New("unexpected crash\ngoroutine 1 [running]:\nmain.run(...)\n\t/walden/main.go:42")
		ref := FromError("server boot", rawErr, "restart walden")
		got := ref.Error()

		if strings.Contains(got, "goroutine") || strings.Contains(got, "\n") || strings.Contains(got, "\t") {
			t.Errorf("stack trace was not sanitized: %q", got)
		}

		expected := "server boot: unexpected crash (restart walden)"
		if got != expected {
			t.Errorf("got %q, want %q", got, expected)
		}
	})
}

func TestRefuseHelperAndTypeAssertion(t *testing.T) {
	err := Refuse("token", "missing subcommand", "expected create, list, or revoke")
	if err == nil {
		t.Fatal("Refuse returned nil")
	}

	var ref *Refusal
	if !errors.As(err, &ref) {
		t.Fatalf("expected error to be *Refusal, got %T", err)
	}

	if ref.What != "token" || ref.Why != "missing subcommand" || ref.Fix != "expected create, list, or revoke" {
		t.Errorf("unexpected refusal fields: %+v", ref)
	}

	if !errors.Is(err, &Refusal{}) {
		t.Errorf("errors.Is(err, &Refusal{}) returned false")
	}
}

func TestRefuseWithCauseAndUnwrap(t *testing.T) {
	sentinel := errors.New("underlying sentinel error")
	err := RefuseWithCause("operation", "failed condition", "retry later", sentinel)
	if err == nil {
		t.Fatal("RefuseWithCause returned nil")
	}

	if !errors.Is(err, sentinel) {
		t.Errorf("expected errors.Is(err, sentinel) to be true")
	}

	var ref *Refusal
	if !errors.As(err, &ref) {
		t.Fatalf("expected *Refusal, got %T", err)
	}

	if ref.Unwrap() != sentinel {
		t.Errorf("Unwrap() = %v, want %v", ref.Unwrap(), sentinel)
	}

	// FromError also wraps sentinel
	wrappedRef := FromError("operation", sentinel, "fix action")
	if !errors.Is(wrappedRef, sentinel) {
		t.Errorf("expected errors.Is(wrappedRef, sentinel) to be true")
	}

	// Nil target in Is
	if ref.Is(nil) {
		t.Errorf("expected ref.Is(nil) to be false")
	}
}
