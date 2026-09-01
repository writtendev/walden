// Package refusal implements walden's operator-facing refusal convention.
// Per PHILOSOPHY.md: "When walden refuses to do something, the reason should
// be printable in one line... The operator at 3am is the design persona."
package refusal

import (
	"fmt"
	"strings"
)

// Refusal represents an operator-facing refusal that guarantees a single-line
// message naming what was refused, why, and what to do about it.
type Refusal struct {
	What string
	Why  string
	Fix  string
	Err  error
}

// New creates a new Refusal with what was refused, why, and what to do about it.
// All fields are sanitized to guarantee the resulting message is strictly a single line
// with no embedded newlines, carriage returns, or stack trace artifacts.
func New(what, why, fix string) *Refusal {
	return &Refusal{
		What: sanitize(what),
		Why:  sanitize(why),
		Fix:  sanitize(fix),
	}
}

// FromError wraps an underlying error into an operator-facing Refusal.
// It extracts and sanitizes the error message so internal wrapped chains or multiline
// dumps do not leak to the operator.
func FromError(what string, err error, fix string) *Refusal {
	why := ""
	if err != nil {
		why = err.Error()
	}
	r := New(what, why, fix)
	r.Err = err
	return r
}

// Refuse is a convenience helper that returns a new Refusal as an error.
func Refuse(what, why, fix string) error {
	return New(what, why, fix)
}

// RefuseWithCause creates a new Refusal with an attached underlying cause error for errors.Is matching.
func RefuseWithCause(what, why, fix string, cause error) error {
	r := New(what, why, fix)
	r.Err = cause
	return r
}

// Error formats the refusal as a single-line string: "<what>: <why> (<fix>)".
// If Fix is empty, it formats as "<what>: <why>".
func (r *Refusal) Error() string {
	what := sanitize(r.What)
	why := sanitize(r.Why)
	fix := sanitize(r.Fix)

	if what == "" {
		what = "refused"
	}
	if why == "" {
		why = "unspecified reason"
	}

	if fix == "" {
		return fmt.Sprintf("%s: %s", what, why)
	}
	return fmt.Sprintf("%s: %s (%s)", what, why, fix)
}

// Unwrap returns the underlying causal error, if any. There is deliberately no
// Is method: errors.Is already walks Unwrap to reach the cause, and any Is that
// matched another *Refusal would make every refusal equal to every other one.
// Callers asking "is this a refusal at all" use errors.As.
func (r *Refusal) Unwrap() error {
	return r.Err
}

// sanitize strips newlines, carriage returns, tabs, and collapses whitespace,
// stripping out stack trace markers or multiline noise to guarantee single-line output.
func sanitize(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	// Truncate before stack trace headers or panic dumps if present
	if idx := strings.Index(s, "goroutine "); idx != -1 {
		s = strings.TrimSpace(s[:idx])
	}
	if idx := strings.Index(s, "panic: "); idx != -1 {
		s = strings.TrimSpace(s[:idx])
	}

	// Split by whitespace (including newlines, tabs, carriage returns) and re-join with single spaces
	fields := strings.Fields(s)
	return strings.Join(fields, " ")
}
