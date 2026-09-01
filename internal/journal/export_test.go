package journal

// The journal package's tests live in package journal_test, so that they read the package
// the way a caller does. The few unexported values they still have to reach are bridged
// here rather than exported for their sake: a constant with no caller outside this package
// does not belong in the package's surface.

// CodePreconditionFailed exposes codePreconditionFailed to the external tests, which pin
// it to a string literal and generate spec/journal/v1/fixtures/conditional_append.json
// from it.
const CodePreconditionFailed = codePreconditionFailed
