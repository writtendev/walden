package journal

import "time"

// The journal package's tests live in package journal_test, so that they read the package
// the way a caller does. The few unexported values they still have to reach are bridged
// here rather than exported for their sake: a constant with no caller outside this package
// does not belong in the package's surface.

// CodePreconditionFailed exposes codePreconditionFailed to the external tests, which pin
// it to a string literal and generate spec/journal/v1/fixtures/conditional_append.json
// from it.
const CodePreconditionFailed = codePreconditionFailed

// SetAbandonedCheckoutGraceForTest overrides abandonedCheckoutGrace so a test can drive a
// Lease past it in milliseconds instead of waiting out the production grace period. It
// returns a func that restores the production value, matching store.SetBackoffForTest's
// shape. The grace period is package state, so tests using this must not run in parallel
// with each other.
func SetAbandonedCheckoutGraceForTest(d time.Duration) (restore func()) {
	prev := abandonedCheckoutGrace
	abandonedCheckoutGrace = d
	return func() { abandonedCheckoutGrace = prev }
}
