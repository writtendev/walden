// WALD-23: (*store.Client).ProbeCAS driven against storetest.Fake, the same
// stateful in-memory S3 fake with fault injection storetest_client_test.go
// uses (WALD-24). A pass here means the probe's retry/classify behavior is
// right against something that actually enforces spec/journal/v1's
// compare-and-swap contract, and ties the boot refusal to the exact fixture
// text WALD-101 pinned - not a bespoke mock that only knows what a test
// author remembered to assert.
package store_test

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/store"
	"github.com/writtendev/walden/internal/store/storetest"
)

// probeKeyPattern is spec/journal/v1 section 11.6's probe key shape,
// journal-relative (i.e. with testPrefix already stripped).
var probeKeyPattern = regexp.MustCompile(`^v1/probe/[0-9a-f]{32}$`)

// newProbeClient starts a Fake and returns a store.Client pointed at it,
// with journal.Provider set to provider (empty for a self-hosted-style
// unrecognised endpoint, so ProbeCAS falls back to naming the endpoint's
// host[:port]). It shares newFakeClient's backoff shrinking and cleanup.
func newProbeClient(t *testing.T, provider string) (*store.Client, *storetest.Fake) {
	t.Helper()
	restore := store.SetBackoffForTest(time.Millisecond, 5*time.Millisecond)
	t.Cleanup(restore)

	fake := storetest.New(t)
	j := &store.Journal{
		Provider:    provider,
		Endpoint:    fake.URL(),
		Region:      "us-east-1",
		Bucket:      fake.Bucket(),
		Prefix:      testPrefix,
		PathStyle:   true,
		Credentials: store.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
	}
	return store.NewClient(j), fake
}

// putIfAbsentKeys returns, in arrival order, the journal-relative keys of
// every OpPutIfAbsent call the fake has logged.
func putIfAbsentKeys(fake *storetest.Fake) []string {
	var keys []string
	for _, c := range fake.Calls() {
		if c.Op == storetest.OpPutIfAbsent {
			keys = append(keys, strings.TrimPrefix(c.Key, testPrefix+"/"))
		}
	}
	return keys
}

func assertSingleLine(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("error is not a single line: %q", err.Error())
	}
}

// 1. A backend that honours If-None-Match: passes, both writes target the
// same key matching the probe's shape, and cleanup deletes it. A second,
// independent probe uses a different key.
func TestProbeCASHonouringBackendCleansUp(t *testing.T) {
	c, fake := newProbeClient(t, "")

	cleanup, err := c.ProbeCAS(context.Background())
	if err != nil {
		t.Fatalf("ProbeCAS: err = %v, want nil", err)
	}
	if cleanup != nil {
		t.Fatalf("ProbeCAS: cleanup = %v, want nil", cleanup)
	}

	keys := putIfAbsentKeys(fake)
	if len(keys) != 2 {
		t.Fatalf("fake saw %d PutIfAbsent calls, want 2", len(keys))
	}
	if keys[0] != keys[1] {
		t.Errorf("the two probe writes used different keys: %q, %q", keys[0], keys[1])
	}
	if !probeKeyPattern.MatchString(keys[0]) {
		t.Errorf("probe key %q does not match %s", keys[0], probeKeyPattern)
	}

	var deletes int
	for _, call := range fake.Calls() {
		if call.Op == storetest.OpDelete {
			deletes++
			if got := strings.TrimPrefix(call.Key, testPrefix+"/"); got != keys[0] {
				t.Errorf("DELETE key = %q, want %q", got, keys[0])
			}
		}
	}
	if deletes != 1 {
		t.Errorf("fake saw %d DELETE calls, want 1", deletes)
	}
	if _, ok := fake.Object(testPrefix + "/" + keys[0]); ok {
		t.Errorf("probe key %q still present after cleanup", keys[0])
	}

	// A second, independent probe must not reuse the first probe's key.
	_, err2 := c.ProbeCAS(context.Background())
	if err2 != nil {
		t.Fatalf("second ProbeCAS: err = %v, want nil", err2)
	}
	keys2 := putIfAbsentKeys(fake)
	if len(keys2) != 4 {
		t.Fatalf("fake saw %d PutIfAbsent calls after two probes, want 4", len(keys2))
	}
	if keys2[2] == keys[0] {
		t.Errorf("second probe reused the first probe's key %q", keys[0])
	}
}

// 2. A backend that ignores If-None-Match (ProbeCAS's Fault.IgnoreCondition,
// the non-CAS provider case): the probe refuses with RefuseProviderLacksCAS,
// naming the endpoint's host[:port] when the journal carries no provider
// name, and still cleans up the key it wrote.
func TestProbeCASIgnoringBackendRefuses(t *testing.T) {
	c, fake := newProbeClient(t, "")
	fake.Inject(storetest.Rule{
		Op: storetest.OpPutIfAbsent, Call: 1, Count: 2,
		Fault: storetest.Fault{IgnoreCondition: true},
	})

	cleanup, err := c.ProbeCAS(context.Background())
	if !errors.Is(err, store.ErrProviderUnsupported) {
		t.Fatalf("errors.Is(err, ErrProviderUnsupported) = false, err = %v", err)
	}
	assertSingleLine(t, err)
	if cleanup != nil {
		t.Errorf("cleanup = %v, want nil (the fake honours DELETE)", cleanup)
	}

	host := strings.TrimPrefix(fake.URL(), "http://")
	want := journal.RefuseProviderLacksCAS(host).Error()
	if err.Error() != want {
		t.Errorf("ProbeCAS error:\n got: %s\nwant: %s", err.Error(), want)
	}

	deletes := 0
	for _, call := range fake.Calls() {
		if call.Op == storetest.OpDelete {
			deletes++
		}
	}
	if deletes != 1 {
		t.Errorf("fake saw %d DELETE calls, want 1 (cleanup still runs on a refusal)", deletes)
	}
}

// 2a. The same ignoring backend, but with a recognised Provider set on the
// Journal (as ParseJournalURL would for a known hostname): the refusal
// names the provider, not the endpoint host.
func TestProbeCASIgnoringBackendNamesRecognizedProvider(t *testing.T) {
	c, fake := newProbeClient(t, "AWS S3")
	fake.Inject(storetest.Rule{
		Op: storetest.OpPutIfAbsent, Call: 1, Count: 2,
		Fault: storetest.Fault{IgnoreCondition: true},
	})

	_, err := c.ProbeCAS(context.Background())
	want := journal.RefuseProviderLacksCAS("AWS S3").Error()
	if err.Error() != want {
		t.Errorf("ProbeCAS error:\n got: %s\nwant: %s", err.Error(), want)
	}
	if strings.Contains(err.Error(), fake.URL()) {
		t.Errorf("ProbeCAS error names the endpoint instead of the recognised provider: %q", err.Error())
	}
}

// 3. 403 AccessDenied on the first write: a plain "invalid journal:
// compare-and-swap probe: ..." refusal naming the status and code, never
// ErrProviderUnsupported, and no DELETE - nothing was written.
func TestProbeCASFirstWriteForbidden(t *testing.T) {
	c, fake := newProbeClient(t, "")
	fake.Inject(storetest.Rule{
		Op: storetest.OpPutIfAbsent, Call: 1,
		Fault: storetest.Fault{Status: http.StatusForbidden, Code: "AccessDenied"},
	})

	cleanup, err := c.ProbeCAS(context.Background())
	if cleanup != nil {
		t.Errorf("cleanup = %v, want nil (nothing was written)", cleanup)
	}
	if err == nil {
		t.Fatal("ProbeCAS succeeded, want a refusal")
	}
	if !strings.HasPrefix(err.Error(), "invalid journal: compare-and-swap probe:") {
		t.Errorf("error = %q, want prefix %q", err.Error(), "invalid journal: compare-and-swap probe:")
	}
	if !strings.Contains(err.Error(), "403 AccessDenied") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "403 AccessDenied")
	}
	if errors.Is(err, store.ErrProviderUnsupported) {
		t.Errorf("a 403 on the first write must not match ErrProviderUnsupported: %v", err)
	}
	assertSingleLine(t, err)

	for _, call := range fake.Calls() {
		if call.Op == storetest.OpDelete {
			t.Errorf("unexpected DELETE call: %+v", call)
		}
	}
}

// 4. 500 on the second write: the outcome is ambiguous (WALD-22's
// r.conditional rule - once the request has reached storage, no failure
// past that point is retried), so ProbeCAS must not resend it: exactly two
// PutIfAbsent calls, ErrOutcomeUnknown, never ErrProviderUnsupported.
func TestProbeCASSecondWriteAmbiguous(t *testing.T) {
	c, fake := newProbeClient(t, "")
	fake.Inject(storetest.Rule{
		Op: storetest.OpPutIfAbsent, Call: 2,
		Fault: storetest.Fault{Status: http.StatusInternalServerError, Code: "InternalError"},
	})

	_, err := c.ProbeCAS(context.Background())
	if !errors.Is(err, store.ErrOutcomeUnknown) {
		t.Fatalf("errors.Is(err, ErrOutcomeUnknown) = false, err = %v", err)
	}
	if errors.Is(err, store.ErrProviderUnsupported) {
		t.Errorf("an ambiguous second write must not match ErrProviderUnsupported: %v", err)
	}
	assertSingleLine(t, err)

	keys := putIfAbsentKeys(fake)
	if len(keys) != 2 {
		t.Fatalf("fake saw %d PutIfAbsent calls, want exactly 2 (no resend of an ambiguous write)", len(keys))
	}
}

// 5. A failed cleanup delete is a separate warning, never a refusal: the
// probe itself passed (err nil), and cleanup names the stranded key on one
// line.
func TestProbeCASDeleteFailureIsWarning(t *testing.T) {
	c, fake := newProbeClient(t, "")
	fake.Inject(storetest.Rule{
		Op: storetest.OpDelete, Call: 1,
		Fault: storetest.Fault{Status: http.StatusForbidden, Code: "AccessDenied"},
	})

	cleanup, err := c.ProbeCAS(context.Background())
	if err != nil {
		t.Fatalf("ProbeCAS: err = %v, want nil (the probe itself passed)", err)
	}
	if cleanup == nil {
		t.Fatal("cleanup = nil, want a warning naming the stranded key")
	}
	assertSingleLine(t, cleanup)

	keys := putIfAbsentKeys(fake)
	if len(keys) != 2 {
		t.Fatalf("fake saw %d PutIfAbsent calls, want 2", len(keys))
	}
	if !strings.Contains(cleanup.Error(), keys[0]) {
		t.Errorf("cleanup warning %q does not name the stranded key %q", cleanup.Error(), keys[0])
	}
}

// 6. ErrOutcomeUnknown on the FIRST write (a 500 that actually landed the
// object, per Fault.Land - the exact ambiguity classify's r.conditional
// rule describes): the probe cannot prove the write never landed, so it
// must still attempt cleanup rather than stranding v1/probe/<hex> forever
// (spec/journal/v1 section 11.6 item 6), and must not resend the write.
func TestProbeCASFirstWriteAmbiguousCleansUp(t *testing.T) {
	c, fake := newProbeClient(t, "")
	fake.Inject(storetest.Rule{
		Op: storetest.OpPutIfAbsent, Call: 1,
		Fault: storetest.Fault{Status: http.StatusInternalServerError, Code: "InternalError", Land: true},
	})

	cleanup, err := c.ProbeCAS(context.Background())
	if !errors.Is(err, store.ErrOutcomeUnknown) {
		t.Fatalf("errors.Is(err, ErrOutcomeUnknown) = false, err = %v", err)
	}
	if errors.Is(err, store.ErrProviderUnsupported) {
		t.Errorf("an ambiguous first write must not match ErrProviderUnsupported: %v", err)
	}
	assertSingleLine(t, err)

	keys := putIfAbsentKeys(fake)
	if len(keys) != 1 {
		t.Fatalf("fake saw %d PutIfAbsent calls, want exactly 1 (no resend of an ambiguous first write)", len(keys))
	}

	var deletes int
	for _, call := range fake.Calls() {
		if call.Op == storetest.OpDelete {
			deletes++
			if got := strings.TrimPrefix(call.Key, testPrefix+"/"); got != keys[0] {
				t.Errorf("DELETE key = %q, want %q", got, keys[0])
			}
		}
	}
	if deletes != 1 {
		t.Errorf("fake saw %d DELETE calls, want 1 (cleanup attempted despite the ambiguous first write)", deletes)
	}
	if cleanup != nil {
		t.Errorf("cleanup = %v, want nil (the fake honours DELETE)", cleanup)
	}
	if _, ok := fake.Object(testPrefix + "/" + keys[0]); ok {
		t.Errorf("probe key %q still present after cleanup", keys[0])
	}
}

// 7. Same ambiguous first write, but cleanup's own DELETE fails: a warning
// naming the stranded key, never a refusal - ProbeCAS's own err is still
// ErrOutcomeUnknown, unaffected by the cleanup failure.
func TestProbeCASFirstWriteAmbiguousCleanupFails(t *testing.T) {
	c, fake := newProbeClient(t, "")
	fake.Inject(storetest.Rule{
		Op: storetest.OpPutIfAbsent, Call: 1,
		Fault: storetest.Fault{Status: http.StatusInternalServerError, Code: "InternalError", Land: true},
	})
	fake.Inject(storetest.Rule{
		Op: storetest.OpDelete, Call: 1,
		Fault: storetest.Fault{Status: http.StatusForbidden, Code: "AccessDenied"},
	})

	cleanup, err := c.ProbeCAS(context.Background())
	if !errors.Is(err, store.ErrOutcomeUnknown) {
		t.Fatalf("errors.Is(err, ErrOutcomeUnknown) = false, err = %v", err)
	}
	if cleanup == nil {
		t.Fatal("cleanup = nil, want a warning naming the stranded key")
	}
	assertSingleLine(t, cleanup)

	keys := putIfAbsentKeys(fake)
	if len(keys) != 1 {
		t.Fatalf("fake saw %d PutIfAbsent calls, want exactly 1", len(keys))
	}
	if !strings.Contains(cleanup.Error(), keys[0]) {
		t.Errorf("cleanup warning %q does not name the stranded key %q", cleanup.Error(), keys[0])
	}
}
