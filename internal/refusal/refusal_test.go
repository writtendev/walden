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
}

func TestRefusalsWithDifferentCausesDoNotMatch(t *testing.T) {
	causeA := errors.New("cause a")
	causeB := errors.New("cause b")

	a := RefuseWithCause("operation a", "condition a", "retry a", causeA)
	b := RefuseWithCause("operation b", "condition b", "retry b", causeB)

	if errors.Is(a, b) {
		t.Errorf("errors.Is(a, b) returned true for refusals with distinct causes")
	}
	if errors.Is(b, a) {
		t.Errorf("errors.Is(b, a) returned true for refusals with distinct causes")
	}

	// Each refusal still matches its own cause, and only its own.
	if !errors.Is(a, causeA) {
		t.Errorf("expected errors.Is(a, causeA) to be true")
	}
	if errors.Is(a, causeB) {
		t.Errorf("expected errors.Is(a, causeB) to be false")
	}
	if !errors.Is(b, causeB) {
		t.Errorf("expected errors.Is(b, causeB) to be true")
	}
	if errors.Is(b, causeA) {
		t.Errorf("expected errors.Is(b, causeA) to be false")
	}

	// A cause reached through an intermediate wrap is still matchable, which is
	// what makes the old "errors.Is(r.Err, target)" branch redundant.
	wrapped := RefuseWithCause("operation c", "condition c", "retry c", fmt.Errorf("layer: %w", causeA))
	if !errors.Is(wrapped, causeA) {
		t.Errorf("expected errors.Is(wrapped, causeA) to be true")
	}

	// Each is still reachable as a refusal, and a causeless refusal is too.
	plain := Refuse("operation d", "condition d", "retry d")
	for name, err := range map[string]error{"a": a, "b": b, "wrapped": wrapped, "plain": plain} {
		var ref *Refusal
		if !errors.As(err, &ref) {
			t.Errorf("expected errors.As(%s, &ref) to be true", name)
		}
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
}
