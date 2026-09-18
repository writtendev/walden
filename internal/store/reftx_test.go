// Tests for (*Client).AppendRefTx (WALD-27), driven against storetest.Fake
// the same way storetest_client_test.go and genesis_test.go are: a pass
// here means the write path proves spec/journal/v1 section 11's actual
// "done when" end to end — a real 412 through PutIfAbsent becomes a fencing
// refusal, and a merely retryable failure never does, with the sequence
// left reusable — against something that actually enforces the
// compare-and-swap contract, not a mock that only knows what a test author
// remembered to assert.
package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/store"
	"github.com/writtendev/walden/internal/store/storetest"
)

// fixedReftxNow is the deterministic clock every AppendRefTx test uses, so
// a written record's timestamp never depends on wall-clock time.
func fixedReftxNow() time.Time {
	return time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
}

// reftxUpdates is a single, valid ref update triple shared by every test
// below that does not care about its specific contents, only that
// AppendRefTx has at least one to work with.
func reftxUpdates() []journal.RefUpdate {
	return []journal.RefUpdate{
		{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
	}
}

// assertReftxOneLine fails the test unless err is non-nil and its message
// has no embedded newline, per AGENTS.md's mechanical review rule that
// every operator-facing refusal is one line.
func assertReftxOneLine(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if strings.Count(err.Error(), "\n") != 0 {
		t.Errorf("refusal is not one line: %q", err.Error())
	}
}

// 1. Happy path: the written key is fullKey(journal.TxKey(stream, 0)), the
// bytes at it equal MarshalRefTx's own output, the returned seq is 0, and
// the record we wrote is one a replay can verify (journal.VerifyRefTx
// against the public half of the signing key). The lease then advances: a
// second AppendRefTx on the same lease writes seq 1.
func TestAppendRefTxHappyPathAndLeaseAdvance(t *testing.T) {
	c, fake := newFakeClient(t)
	ctx := context.Background()

	priv, pub, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	leases := journal.NewLeases(c)
	lease, err := leases.Open(ctx, "repo-alpha")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	segments := []string{"db89aeed94af475ae97ce5fe75618d404f017d23e0aa61ce1c7abd11707dbbab"}
	updates := reftxUpdates()

	seq, err := c.AppendRefTx(ctx, lease, priv, 0, segments, updates, fixedReftxNow)
	if err != nil {
		t.Fatalf("AppendRefTx: %v", err)
	}
	if seq != 0 {
		t.Fatalf("seq = %d, want 0", seq)
	}

	key := fullKey(journal.TxKey("repo-alpha", 0))
	data, ok := fake.Object(key)
	if !ok {
		t.Fatalf("Object(%q) not found", key)
	}

	var rec journal.RefTransactionRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("json.Unmarshal wrote bytes: %v", err)
	}
	if err := journal.VerifyRefTx(&rec, journal.FormatPublicKey(pub)); err != nil {
		t.Fatalf("VerifyRefTx on the written record: %v", err)
	}

	rebuilt := journal.NewRefTransactionRecord("repo-alpha", 0, 0, fixedReftxNow().UTC().Format(time.RFC3339), segments, updates)
	rebuilt.Signature = rec.Signature
	want, err := journal.MarshalRefTx(rebuilt)
	if err != nil {
		t.Fatalf("MarshalRefTx: %v", err)
	}
	if !bytes.Equal(data, want) {
		t.Errorf("written bytes do not equal MarshalRefTx's own output\ngot:\n%s\nwant:\n%s", data, want)
	}

	// The lease advances: a second AppendRefTx on the same lease writes seq 1.
	seq2, err := c.AppendRefTx(ctx, lease, priv, 0, segments, updates, fixedReftxNow)
	if err != nil {
		t.Fatalf("second AppendRefTx: %v", err)
	}
	if seq2 != 1 {
		t.Errorf("second seq = %d, want 1", seq2)
	}
	if _, ok := fake.Object(fullKey(journal.TxKey("repo-alpha", 1))); !ok {
		t.Errorf("expected an object at seq 1")
	}
}

// 2. A real 412 from a key the fake actually holds (Fault.Rival - never a
// fabricated status) fences the stream and returns spec section 11.5 item 1
// verbatim. A further AppendRefTx on the same lease makes zero additional
// requests and returns item 2 verbatim.
func TestAppendRefTxPreconditionFencesStreamAndStopsFurtherWrites(t *testing.T) {
	c, fake := newFakeClient(t)
	ctx := context.Background()

	priv, _, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	leases := journal.NewLeases(c)
	lease, err := leases.Open(ctx, "repo-alpha")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	fake.Inject(storetest.Rule{
		Op:    storetest.OpPutIfAbsent,
		Key:   fullKey(journal.TxKey("repo-alpha", 0)),
		Call:  1,
		Fault: storetest.Fault{Rival: []byte(`{"rival":true}`)},
	})

	_, err = c.AppendRefTx(ctx, lease, priv, 0, nil, reftxUpdates(), fixedReftxNow)
	want := journal.RefuseStreamFenced("repo-alpha", 0).Error()
	if err == nil || err.Error() != want {
		t.Fatalf("AppendRefTx error:\ngot:  %v\nwant: %q", err, want)
	}
	if !errors.Is(err, journal.ErrFenced) {
		t.Errorf("expected error to match journal.ErrFenced")
	}

	callsBefore := len(fake.Calls())

	_, err = c.AppendRefTx(ctx, lease, priv, 0, nil, reftxUpdates(), fixedReftxNow)
	wantPerm := journal.RefusePermanentlyFenced("repo-alpha").Error()
	if err == nil || err.Error() != wantPerm {
		t.Fatalf("AppendRefTx after fencing:\ngot:  %v\nwant: %q", err, wantPerm)
	}
	if got := len(fake.Calls()); got != callsBefore {
		t.Errorf("fake saw %d further requests after fencing, want 0", got-callsBefore)
	}
}

// 3. A landed-but-unacknowledged write (Land:true, a bare 500) fences the
// stream with spec section 11.5 item 7's unknown-outcome wording, never
// item 1's - the writer never resent and never re-read the key to find out
// (spec section 11.4 item 6).
func TestAppendRefTxLandedThenUnacknowledgedFencesWithUnknownOutcome(t *testing.T) {
	c, fake := newFakeClient(t)
	ctx := context.Background()

	priv, _, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	leases := journal.NewLeases(c)
	lease, err := leases.Open(ctx, "repo-gamma")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	fake.Inject(storetest.Rule{
		Op:    storetest.OpPutIfAbsent,
		Key:   fullKey(journal.TxKey("repo-gamma", 0)),
		Call:  1,
		Fault: storetest.Fault{Land: true, Status: http.StatusInternalServerError},
	})

	_, err = c.AppendRefTx(ctx, lease, priv, 0, nil, reftxUpdates(), fixedReftxNow)
	want := journal.RefuseAppendOutcomeUnknown("repo-gamma", 0).Error()
	if err == nil || err.Error() != want {
		t.Fatalf("AppendRefTx error:\ngot:  %v\nwant: %q", err, want)
	}
	if !errors.Is(err, journal.ErrFenced) {
		t.Errorf("expected error to match journal.ErrFenced")
	}
	if !lease.Fencer().IsFenced("repo-gamma") {
		t.Errorf("expected repo-gamma to be fenced")
	}
}

// 4. A burst of MaxAttemptsForTest 503s - never landed - exhausts retries
// with a plain retryable error (store.ErrStorageUnavailable): the stream is
// left unfenced and the sequence unconsumed, so the next AppendRefTx writes
// the same seq. This is the half of the ticket's "done when" that says a
// retryable failure must not become a fencing signal.
func TestAppendRefTxRetryableFailureLeavesSequenceReusable(t *testing.T) {
	c, fake := newFakeClient(t)
	ctx := context.Background()

	priv, _, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	leases := journal.NewLeases(c)
	lease, err := leases.Open(ctx, "repo-delta")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	key := journal.TxKey("repo-delta", 0)
	fake.Inject(storetest.Rule{
		Op:    storetest.OpPutIfAbsent,
		Key:   fullKey(key),
		Call:  1,
		Count: store.MaxAttemptsForTest,
		Fault: storetest.Fault{Status: http.StatusServiceUnavailable, Code: "SlowDown"},
	})

	_, err = c.AppendRefTx(ctx, lease, priv, 0, nil, reftxUpdates(), fixedReftxNow)
	if !errors.Is(err, store.ErrStorageUnavailable) {
		t.Fatalf("errors.Is(_, ErrStorageUnavailable) = false, err = %v", err)
	}
	if lease.Fencer().IsFenced("repo-delta") {
		t.Errorf("expected repo-delta to remain unfenced after a retryable failure")
	}
	if _, ok := fake.Object(fullKey(key)); ok {
		t.Errorf("expected no object written once retries were exhausted")
	}

	seq, err := c.AppendRefTx(ctx, lease, priv, 0, nil, reftxUpdates(), fixedReftxNow)
	if err != nil {
		t.Fatalf("second AppendRefTx (after the retryable failure): %v", err)
	}
	if seq != 0 {
		t.Errorf("seq = %d, want 0 (the sequence must be reusable after a retryable failure)", seq)
	}
}

// 5. Stream isolation (spec section 11.4 item 5): fencing repo-alpha
// through one lease leaves repo-beta writable through its own lease on the
// same registry.
func TestAppendRefTxStreamIsolation(t *testing.T) {
	c, fake := newFakeClient(t)
	ctx := context.Background()

	priv, _, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	leases := journal.NewLeases(c)
	alpha, err := leases.Open(ctx, "repo-alpha")
	if err != nil {
		t.Fatalf("Open(repo-alpha): %v", err)
	}
	beta, err := leases.Open(ctx, "repo-beta")
	if err != nil {
		t.Fatalf("Open(repo-beta): %v", err)
	}

	fake.Inject(storetest.Rule{
		Op:    storetest.OpPutIfAbsent,
		Key:   fullKey(journal.TxKey("repo-alpha", 0)),
		Call:  1,
		Fault: storetest.Fault{Rival: []byte(`{"rival":true}`)},
	})

	if _, err := c.AppendRefTx(ctx, alpha, priv, 0, nil, reftxUpdates(), fixedReftxNow); !errors.Is(err, journal.ErrFenced) {
		t.Fatalf("expected repo-alpha to fence, got %v", err)
	}

	seq, err := c.AppendRefTx(ctx, beta, priv, 0, nil, reftxUpdates(), fixedReftxNow)
	if err != nil {
		t.Fatalf("AppendRefTx(repo-beta) after repo-alpha fenced: %v", err)
	}
	if seq != 0 {
		t.Errorf("seq = %d, want 0", seq)
	}
	if _, ok := fake.Object(fullKey(journal.TxKey("repo-beta", 0))); !ok {
		t.Errorf("expected repo-beta's write to have landed")
	}
}

// 6. Each pre-check AppendRefTx makes before ever calling lease.Append
// refuses with zero entries added to fake.Calls() beyond whatever Open
// itself already made, leaves the stream unfenced, and is exactly one
// line - including the wrong-size private key, the test that proves a bad
// key refuses instead of fencing (ed25519.Sign would otherwise panic
// inside lease.Append's callback and fence a healthy stream through
// WALD-29's unknown-outcome path).
func TestAppendRefTxPreChecksRefuseWithZeroNetworkCallsAndNoFencing(t *testing.T) {
	priv, _, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	t.Run("wrong-size private key", func(t *testing.T) {
		c, fake := newFakeClient(t)
		ctx := context.Background()
		leases := journal.NewLeases(c)
		lease, err := leases.Open(ctx, "repo-alpha")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		callsBefore := len(fake.Calls())

		badPriv := priv[:len(priv)-1]
		_, err = c.AppendRefTx(ctx, lease, badPriv, 0, nil, reftxUpdates(), fixedReftxNow)
		assertReftxOneLine(t, err)
		if errors.Is(err, journal.ErrFenced) {
			t.Errorf("a malformed key must refuse, not fence: %v", err)
		}
		if lease.Fencer().IsFenced("repo-alpha") {
			t.Errorf("expected repo-alpha to remain unfenced")
		}
		if got := len(fake.Calls()); got != callsBefore {
			t.Errorf("fake saw %d further requests, want 0", got-callsBefore)
		}
	})

	t.Run("meta stream", func(t *testing.T) {
		c, fake := newFakeClient(t)
		ctx := context.Background()
		leases := journal.NewLeases(c)
		lease, err := leases.Open(ctx, journal.MetaStreamID)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		callsBefore := len(fake.Calls())

		_, err = c.AppendRefTx(ctx, lease, priv, 0, nil, reftxUpdates(), fixedReftxNow)
		assertReftxOneLine(t, err)
		if errors.Is(err, journal.ErrFenced) {
			t.Errorf("a ref transaction targeting _meta must refuse, not fence: %v", err)
		}
		if lease.Fencer().IsFenced(journal.MetaStreamID) {
			t.Errorf("expected _meta to remain unfenced")
		}
		if got := len(fake.Calls()); got != callsBefore {
			t.Errorf("fake saw %d further requests, want 0", got-callsBefore)
		}
	})

	t.Run("no updates", func(t *testing.T) {
		c, fake := newFakeClient(t)
		ctx := context.Background()
		leases := journal.NewLeases(c)
		lease, err := leases.Open(ctx, "repo-alpha")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		callsBefore := len(fake.Calls())

		_, err = c.AppendRefTx(ctx, lease, priv, 0, nil, nil, fixedReftxNow)
		assertReftxOneLine(t, err)
		if errors.Is(err, journal.ErrFenced) {
			t.Errorf("an empty updates array must refuse, not fence: %v", err)
		}
		if lease.Fencer().IsFenced("repo-alpha") {
			t.Errorf("expected repo-alpha to remain unfenced")
		}
		if got := len(fake.Calls()); got != callsBefore {
			t.Errorf("fake saw %d further requests, want 0", got-callsBefore)
		}
	})
}
