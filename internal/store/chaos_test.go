// WALD-35: the chaos test ARCHITECTURE.md's Fencing section promises ("it is
// specified by fixtures and exercised by a chaos test before it is trusted
// with anyone's bytes"). It drives the now-complete write path -
// (*Client).AppendSegment then (*Client).AppendRefTx through
// journal.Lease.Append - against storetest's fake bucket under a seeded
// catalogue of injected faults, plus a barrier-synchronized race between
// several independent journal.Leases registries standing in for separate
// walden instances.
//
// It pins the four things a survey of lease_test.go, fencing_test.go,
// reftx_test.go, segment_test.go, genesis_test.go and
// storetest_client_test.go found uncovered (WALD-35's Linear plan has the
// full survey):
//
//  1. No permanent sequence gap (spec/journal/v1 section 1, section 12 rule
//     3), across a fence-and-restart cycle.
//  2. Every acknowledged append is present in the journal, intact,
//     verifiable, and its segments exist.
//  3. Two independent instances never both land a record at one
//     (stream, seq).
//  4. A tx/ key is never written unconditionally.
//
// It deliberately does not restate what is already pinned elsewhere: the
// eight section 11.5 refusal strings (fencing_test.go,
// TestFixtureConditionalAppend against fixtures/conditional_append.json -
// this file compares against the journal.RefuseXxx(...) constructors, never
// a fresh literal), segment PUT idempotency under crash-and-retry
// (segment_test.go), per-stream fencing isolation as a headline property
// (already covered by TestStreamIsolationAcrossFencing and friends - this
// file keeps it only as a cheap background assertion since the chaos run
// touches several streams anyway), or that a 412 fences with zero further
// network calls (reftx_test.go).
//
// Two judgment calls a reviewer should look at directly:
//
//   - One fault shape is excluded on purpose: Land combined with 408, 429,
//     or 503. Spec section 11.4 item 6 lists those as statuses storage
//     returns only for a request it rejected before evaluation, so a landed
//     one of them is a shape the spec declares impossible - injecting it
//     would make the client's own safe resend take a 412 caused by its own
//     earlier write and fence a healthy stream, testing the fake's
//     imagination rather than walden.
//   - storetest.Fault.Rival writes are not logged as a Call (see
//     storetest.go's package doc), so the "no tx/ key lands twice" check
//     below measures only walden's own writes. It is paired with an
//     explicit "the rival's bytes still hold the key" assertion in the
//     proven-conflict case, so the pair together is still a real no-fork
//     check.
//
// Rotation (WALD-31, merged since this ticket's plan was written) is
// deliberately not exercised here: keyEpoch is held at 0 throughout, one
// signing key, no epoch-floor assertion, no replay. That is out of this
// ticket's approved scope (a follow-up covers rotation chaos), and it keeps
// this file clear of WALD-108's per-stream key-epoch floor question, which
// is a decision for that follow-up to make, not this one.
//
// Reproducibility is non-negotiable: the randomized half
// (TestChaosWritePathFaultsAndRestart) runs from a fixed default seed (the
// leakSeed = 18 idiom journal_leak_test.go already uses in this package),
// so a green run means the same thing on every machine, and
// WALDEN_CHAOS_SEED / WALDEN_CHAOS_ROUNDS scale it - test-only env vars read
// from this _test.go file alone, the same non-sixth-knob precedent
// WALDEN_LEAK_ITERATIONS and WALDEN_CONFORMANCE_JOURNAL already set. Every
// failure prints the seed, the round, the stream, the seq, the fault class,
// a dump of fake.Calls(), and the exact command to replay it. The
// concurrent half (TestChaosWritePathConcurrentInstances) needs no seed:
// every assertion it makes holds under every goroutine interleaving - a
// fixed barrier and an exactly-one-winner check, never anything whose truth
// depends on scheduling, because this is the repo's first randomized
// concurrent test and a flaky one would tax every future PR (see WALD-28's
// TestEnsureGenesisConcurrentRaceSingleWinner, which review caught asserting
// one of two legitimate outcomes - the shape this file avoids repeating).
//
// Like every other test in this package, this file adds no t.Parallel():
// store.SetBackoffForTest is package state (newChaosClient shrinks it, the
// same idiom newFakeClient in storetest_client_test.go already uses), so
// tests using it must not run concurrently with each other.
package store_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/store"
	"github.com/writtendev/walden/internal/store/storetest"
)

// chaosDefaultSeed is the fixed default for WALDEN_CHAOS_SEED: a green run
// at the default means the same thing on every machine, the same guarantee
// journal_leak_test.go's leakSeed gives its own generator.
const chaosDefaultSeed = 18

// chaosDefaultRounds and chaosDefaultConcurrentRounds are the default
// budgets for the two tests below, tuned so the pair together add roughly 3s
// to this package's `go test -race` run (see the PR description for the
// measured figure). WALDEN_CHAOS_ROUNDS overrides both at once: the nightly
// workflow (.github/workflows/chaos.yml) sets it much higher.
const (
	chaosDefaultRounds           = 150
	chaosDefaultConcurrentRounds = 40
	// chaosConcurrentInstances (K) is fixed, not scaled by the env var: it
	// is what determines contention per round (more instances racing one
	// stream), not how many rounds to run, and 5 is already enough to make
	// the race certain every time (storetest's fake enforces the
	// conditional PUT under one mutex - see its own package doc).
	chaosConcurrentInstances = 5
)

// chaosSigningKey is deterministic - not crypto/rand - so this file needs no
// second seed for reproducibility: the fault schedule is the only thing that
// varies run to run, and it is already pinned by chaosDefaultSeed /
// WALDEN_CHAOS_SEED.
var (
	chaosPriv   = ed25519.NewKeyFromSeed(chaosSigningSeedBytes())
	chaosPub    = chaosPriv.Public().(ed25519.PublicKey)
	chaosSigner = mustChaosSigner()
)

func chaosSigningSeedBytes() []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return seed
}

// mustChaosSigner builds the *journal.Signer every AppendRefTx call in this
// file signs with (WALD-30, merged after this ticket's plan was written:
// AppendRefTx now takes a *journal.Signer rather than a bare
// priv/keyEpoch pair). journal.NewSigner requires a *journal.SigningChain
// already initialized from a genesis record naming the signer's own public
// key, so this seeds one in memory with chaosPub - no bucket round trip,
// since this file's chain of trust is never replayed from storage. Holding
// only a genesis record (no rotation applied) is exactly "keyEpoch held at
// 0 throughout" per the ticket's scope: rotation chaos is a follow-up.
func mustChaosSigner() *journal.Signer {
	chain := journal.NewSigningChain()
	genesis := &journal.GenesisRecord{
		Version:   journal.VersionPrefix,
		Stream:    journal.MetaStreamID,
		Seq:       0,
		Type:      journal.RecordTypeGenesis,
		PublicKey: journal.FormatPublicKey(chaosPub),
		Timestamp: chaosNow().UTC().Format(time.RFC3339),
	}
	if err := chain.ApplyGenesis(genesis); err != nil {
		panic(fmt.Sprintf("chaos: ApplyGenesis: %v", err))
	}
	signer, err := journal.NewSigner(chain, chaosPriv)
	if err != nil {
		panic(fmt.Sprintf("chaos: NewSigner: %v", err))
	}
	return signer
}

// chaosNow is the fixed clock every record in this file is signed under.
func chaosNow() time.Time {
	return time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
}

// chaosUpdates is the single, valid ref update every round writes. Its
// content is never git-meaningful (this file drives the journal write path,
// not git semantics), so every round and every stream reuses the same
// triple; what makes each record unique is its (stream, seq) coordinate.
func chaosUpdates() []journal.RefUpdate {
	return []journal.RefUpdate{
		{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
	}
}

// chaosPack is a minimal, valid packfile (spec/journal/v1 section 6.3): the
// 12-byte header plus 20 bytes standing in for a SHA-1 checksum, exactly
// journal.PackfileMinSize long. Its content never varies, so AppendSegment
// derives the same digest every round - re-uploading it is a no-op success
// under section 6.4's idempotency rule, exactly like a real client retrying
// a push after a crash between the segment landing and the ref transaction
// being acknowledged.
var chaosPack = func() []byte {
	b := make([]byte, journal.PackfileMinSize)
	copy(b, journal.PackfileMagic)
	binary.BigEndian.PutUint32(b[4:8], 2)
	binary.BigEndian.PutUint32(b[8:12], 0)
	return b
}()

// chaosStreams are the two or three repo streams the fault-and-restart test
// rotates a random pick across each round.
var chaosStreams = []journal.StreamID{"chaos-alpha", "chaos-beta", "chaos-gamma"}

// chaosEnvInt reads name as a positive integer, refusing with t.Fatalf if it
// is set to anything else - the same discipline
// TestJournalRefusalsHideTheSecretRandomized already applies to
// WALDEN_LEAK_ITERATIONS. An unset or empty value returns def.
func chaosEnvInt(t *testing.T, name string, def int) int {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		t.Fatalf("%s = %q, want a positive integer", name, v)
	}
	return n
}

// newChaosClient starts a Fake and returns a store.Client pointed at it with
// no bucket-level key prefix - so journal.TxKey(stream, seq) is exactly the
// fake's own full key, the newLeaseClient idiom internal/journal/lease_test.go
// already uses - with the package's retry backoff shrunk for the test's
// lifetime, the same idiom newFakeClient (storetest_client_test.go) uses.
func newChaosClient(t *testing.T) (*store.Client, *storetest.Fake) {
	t.Helper()
	restore := store.SetBackoffForTest(time.Millisecond, 5*time.Millisecond)
	t.Cleanup(restore)

	fake := storetest.New(t)
	j := &store.Journal{
		Endpoint:    fake.URL(),
		Region:      "us-east-1",
		Bucket:      fake.Bucket(),
		PathStyle:   true,
		Credentials: store.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
	}
	return store.NewClient(j), fake
}

// nextSeqFromFake predicts the sequence AppendRefTx is about to hand out for
// stream, the same way (*journal.Leases).Open discovers a head: the highest
// existing tx/ key under the stream's prefix, plus one, or 0 if none exist.
// It lets a round inject a fault against the exact key about to be written,
// before making the call - "just-in-time", per the ticket's plan - without
// reaching into journal.Lease's unexported state.
func nextSeqFromFake(fake *storetest.Fake, stream journal.StreamID) journal.Seq {
	prefix := journal.TxPrefix(stream)
	var (
		head  journal.Seq
		found bool
	)
	for _, k := range fake.Keys() {
		base, ok := strings.CutPrefix(k, prefix)
		if !ok {
			continue
		}
		base, ok = strings.CutSuffix(base, ".json")
		if !ok || strings.Contains(base, "/") {
			continue
		}
		seq, err := journal.ParseSeq(base)
		if err != nil {
			continue
		}
		if !found || seq > head {
			head, found = seq, true
		}
	}
	if !found {
		return 0
	}
	return head + 1
}

// parseTxKey splits a full ("v1/streams/<stream>/tx/<seq>.json") key back
// into its stream and sequence, or ok=false for anything else (a segment
// key, a malformed key). Used only by chaosTxSeqsByStream below, to check
// invariant 4 (no permanent gap) against raw key presence - which must
// include a key storetest.Fault.Rival wrote directly into the fake's object
// map without going through the client, since a real restarted instance's
// head-discovery LIST would see that key too.
func parseTxKey(key string) (stream journal.StreamID, seq journal.Seq, ok bool) {
	const streamsPrefix = "v1/streams/"
	const txMid = "/tx/"
	rest, ok := strings.CutPrefix(key, streamsPrefix)
	if !ok {
		return "", 0, false
	}
	i := strings.Index(rest, txMid)
	if i < 0 {
		return "", 0, false
	}
	s := rest[:i]
	tail, ok := strings.CutSuffix(rest[i+len(txMid):], ".json")
	if !ok || strings.Contains(tail, "/") {
		return "", 0, false
	}
	n, err := journal.ParseSeq(tail)
	if err != nil {
		return "", 0, false
	}
	return journal.StreamID(s), n, true
}

// chaosTxSeqsByStream groups every tx/ key currently in fake by stream,
// for invariant 4's contiguity check.
func chaosTxSeqsByStream(fake *storetest.Fake) map[journal.StreamID][]journal.Seq {
	out := make(map[journal.StreamID][]journal.Seq)
	for _, k := range fake.Keys() {
		stream, seq, ok := parseTxKey(k)
		if !ok {
			continue
		}
		out[stream] = append(out[stream], seq)
	}
	return out
}

// dumpCalls renders fake's call log for a failure message, per this file's
// reproducibility requirement.
func dumpCalls(fake *storetest.Fake) string {
	var b strings.Builder
	for _, c := range fake.Calls() {
		fmt.Fprintf(&b, "  #%d %s %s faulted=%v landed=%v status=%d\n", c.N, c.Op, c.Key, c.Faulted, c.Landed, c.Status)
	}
	return b.String()
}

// chaosAck records one AppendRefTx call this file acknowledged (returned a
// nil error for), the population invariant 3 below checks. A landed-but-
// unacknowledged write (an unknown-outcome fault with Land set) is
// deliberately not added here: it was never acknowledged to the caller, so
// invariant 1 ("no acknowledged push is ever absent") says nothing about
// it - only the per-round assertion for that fault class checks it directly.
type chaosAck struct {
	stream journal.StreamID
	seq    journal.Seq
}

// checkChaosInvariants runs the ticket's four invariants (see this file's
// header comment) against fake's current state. verify names the
// acknowledged appends invariant 3 (present, intact, verifiable, segments
// exist) checks by this call - the round loop below passes only the
// entries newly acknowledged this round, an O(1)-amortized signature
// re-verification per round rather than re-verifying the whole run's
// history every round (which is what "after every round" cost before this
// comment was added: O(rounds^2) ed25519 verifications, the dominant share
// of this test's added runtime). The other three invariants are cheap (no
// cryptography) and always scan fake's full current state regardless of
// what verify contains. Called after every round with that round's new
// acks, and once more after the loop with the complete acked slice, so
// every acknowledged append is still verified at least once each - "once
// at the end" per the ticket's plan, satisfied literally as well as
// incrementally.
func checkChaosInvariants(t *testing.T, label string, fake *storetest.Fake, verify []chaosAck) {
	t.Helper()

	// Invariant: no tx/ key ever lands twice. storetest.Fault.Rival is not
	// logged as a Call (see this file's header comment), so this measures
	// only walden's own writes through the client - which is exactly what
	// "the sequence never forks" needs measured, paired with the explicit
	// rival-bytes-survived check the proven-conflict case makes inline.
	landed := make(map[string]int)
	for _, call := range fake.Calls() {
		if call.Op == storetest.OpPutIfAbsent && strings.Contains(call.Key, "/tx/") && call.Landed {
			landed[call.Key]++
		}
	}
	for k, n := range landed {
		if n > 1 {
			t.Fatalf("%s: tx key %s landed %d times (sequence forked)\ncalls:\n%s", label, k, n, dumpCalls(fake))
		}
	}

	// Invariant: a tx/ key is never written unconditionally.
	for _, call := range fake.Calls() {
		if call.Op == storetest.OpPut && strings.Contains(call.Key, "/tx/") {
			t.Fatalf("%s: unconditional PUT to tx key %s\ncalls:\n%s", label, call.Key, dumpCalls(fake))
		}
	}

	// Invariant: every acknowledged append is present, intact, and
	// verifiable, and every segment digest it references exists.
	for _, a := range verify {
		key := journal.TxKey(a.stream, a.seq)
		data, ok := fake.Object(key)
		if !ok {
			t.Fatalf("%s: acknowledged (%s, %d) missing from the bucket at %s", label, a.stream, a.seq, key)
		}
		var rec journal.RefTransactionRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			t.Fatalf("%s: acknowledged (%s, %d) at %s does not unmarshal: %v", label, a.stream, a.seq, key, err)
		}
		if err := rec.Validate(); err != nil {
			t.Fatalf("%s: acknowledged (%s, %d) at %s fails Validate: %v", label, a.stream, a.seq, key, err)
		}
		if err := journal.VerifyRefTx(&rec, journal.FormatPublicKey(chaosPub)); err != nil {
			t.Fatalf("%s: acknowledged (%s, %d) at %s fails VerifyRefTx: %v", label, a.stream, a.seq, key, err)
		}
		if rec.Stream != a.stream || rec.Seq != a.seq {
			t.Fatalf("%s: acknowledged (%s, %d) at %s names (%s, %d) instead", label, a.stream, a.seq, key, rec.Stream, rec.Seq)
		}
		for _, seg := range rec.Segments {
			if _, ok := fake.Object(journal.SegmentKey(rec.Stream, seg)); !ok {
				t.Fatalf("%s: acknowledged (%s, %d) at %s references missing segment %s", label, a.stream, a.seq, key, seg)
			}
		}
	}

	// Invariant: no permanent sequence gap. Checked against raw key
	// presence (see parseTxKey's doc comment), not the acked list, since a
	// key a rival wrote directly still occupies its seq from a fresh
	// registry's head-discovery point of view.
	for stream, seqs := range chaosTxSeqsByStream(fake) {
		sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
		for i, s := range seqs {
			if uint64(s) != uint64(i) {
				t.Fatalf("%s: stream %s has a sequence gap: seqs=%v", label, stream, seqs)
			}
		}
	}
}

// assertFencedThenInert checks the two properties the ticket's plan asks
// this file to keep as cheap background assertions once a round has just
// fenced stream on lease's registry, rather than as this ticket's own
// headline coverage (both are already pinned elsewhere - see this file's
// header comment):
//
//   - a further Append on the same lease refuses RefusePermanentlyFenced
//     having made zero further requests;
//   - every other configured stream that was not already fenced on this
//     same registry stays unfenced (stream isolation). alreadyFenced names
//     the streams this registry legitimately fenced in an earlier round
//     (before this one restarted anything), so a stream fenced by its own,
//     independent, earlier conflict is not mistaken for isolation being
//     violated by this round's conflict.
func assertFencedThenInert(t *testing.T, label string, c *store.Client, ctx context.Context, lease *journal.Lease, fake *storetest.Fake, stream journal.StreamID, streams []journal.StreamID, alreadyFenced map[journal.StreamID]bool) {
	t.Helper()

	if !lease.Fencer().IsFenced(stream) {
		t.Fatalf("%s: expected stream %s to be fenced", label, stream)
	}
	for _, other := range streams {
		if other == stream || alreadyFenced[other] {
			continue
		}
		if lease.Fencer().IsFenced(other) {
			t.Fatalf("%s: stream isolation violated: %s fenced by %s's conflict", label, other, stream)
		}
	}

	callsBefore := len(fake.Calls())
	_, err := c.AppendRefTx(ctx, lease, chaosSigner, nil, chaosUpdates(), chaosNow)
	want := journal.RefusePermanentlyFenced(stream).Error()
	if err == nil || err.Error() != want {
		t.Fatalf("%s: Append on fenced stream %s = %v, want %q", label, stream, err, want)
	}
	if got := len(fake.Calls()); got != callsBefore {
		t.Fatalf("%s: fake saw %d further requests after stream %s fenced, want 0\n%s", label, got-callsBefore, stream, dumpCalls(fake))
	}
}

// faultClass partitions the catalogue by what spec/journal/v1 says each
// class proves - the partition is the assertion, not the individual fault
// shapes within it.
type faultClass int

const (
	// classClean injects nothing: the append lands normally.
	classClean faultClass = iota
	// classProvablyUnapplied covers statuses and shapes storage returns
	// only for a request it rejected before evaluation (spec section 11.4
	// item 6): the writer may safely resend. It either succeeds once the
	// injected burst ends, or exhausts store.MaxAttemptsForTest and
	// returns a plain retryable error with the stream left unfenced and
	// the sequence still on offer.
	classProvablyUnapplied
	// classUnknownOutcome covers a dropped connection or a 500/502/504:
	// the writer cannot prove whether the write landed, so it fences with
	// RefuseAppendOutcomeUnknown - the sequence is consumed only if the
	// fault also actually applied the write (Fault.Land).
	classUnknownOutcome
	// classProvenConflict is a real 412 from a key storetest.Fault.Rival
	// actually holds: the writer fences with RefuseStreamFenced, and the
	// rival's bytes must still be there afterward.
	classProvenConflict
)

func (c faultClass) String() string {
	switch c {
	case classClean:
		return "clean"
	case classProvablyUnapplied:
		return "provably-unapplied"
	case classUnknownOutcome:
		return "unknown-outcome"
	case classProvenConflict:
		return "proven-conflict"
	default:
		return fmt.Sprintf("faultClass(%d)", int(c))
	}
}

// pickFaultClass draws uniformly across the four classes.
func pickFaultClass(r *rand.Rand) faultClass {
	return faultClass(r.Intn(4))
}

// provablyUnappliedFault draws one of the shapes spec section 11.4 item 6
// names as provably not landed: 408, 429, 503, 400 RequestTimeout, or 409
// ConditionalRequestConflict.
//
// Deliberately excluded, per the ticket's plan: Land combined with any of
// these statuses. Spec section 11.4 item 6 declares that shape impossible
// (storage only returns these statuses for a request it rejected before
// evaluating a write), so injecting it would make the client's own safe
// resend take a 412 caused by its own earlier write and fence a healthy
// stream - testing the fake's imagination, not walden.
//
// TruncateBody is deliberately not one of these shapes, unlike the plan's
// own fault table: see unknownOutcomeFault's doc comment for why a chaos
// run against this file's small ref-transaction bodies puts it in the
// other bucket instead.
func provablyUnappliedFault(r *rand.Rand) storetest.Fault {
	switch r.Intn(5) {
	case 0:
		return storetest.Fault{Status: http.StatusRequestTimeout, Code: "RequestTimeout"}
	case 1:
		return storetest.Fault{Status: http.StatusTooManyRequests, Code: "TooManyRequests"}
	case 2:
		return storetest.Fault{Status: http.StatusServiceUnavailable, Code: "ServiceUnavailable"}
	case 3:
		return storetest.Fault{Status: http.StatusBadRequest, Code: "RequestTimeout"}
	default:
		return storetest.Fault{Status: http.StatusConflict, Code: "ConditionalRequestConflict"}
	}
}

// unknownOutcomeFault draws one of the shapes spec section 11.4 item 6 names
// as leaving the outcome unprovable: a dropped connection (with or without
// the write actually landing first), a 500/502/504 (ditto), or a body cut
// before it fully reaches the fake.
//
// TruncateBody sits here, not in provablyUnappliedFault, which is a
// deliberate departure from the fault table in the ticket's plan (recorded
// in the PR description): (*Client).send's wrote signal is
// wroteOK.Load() || delivered, and delivered tracks bytes read off the
// local io.Reader into the aws-chunked encoder, not bytes actually
// acknowledged by the peer. A ref-transaction record is far smaller than
// the 64 KiB chunk size, so the encoder drains it into a single chunk in
// one local read before net/http ever tries to write it to the wire -
// delivered goes true, and classify (client.go) treats the conditional
// request as having reached storage, exactly as it must for a genuinely
// larger body truncated mid-chunk. The fake proves nothing was stored
// (TruncateBody's branch in handlePut runs and returns before the PUT
// condition is even evaluated), but the client has no way to know that -
// it only knows its own local write finished - so it correctly does what
// section 11.4 item 6 requires of an unprovable outcome: fence rather than
// guess. That is conservative, not incorrect: an unnecessary fencing costs
// availability, never the two invariants this file exists to pin. Land is
// irrelevant to this shape (the fake's TruncateBody branch returns before
// Land is ever consulted), so it is deliberately left unset here - the
// per-round assertion for this fault class already handles Land == false
// by checking the key stays absent, which holds for this shape too.
func unknownOutcomeFault(r *rand.Rand) storetest.Fault {
	statuses := []struct {
		status int
		code   string
	}{
		{http.StatusInternalServerError, "InternalError"},
		{http.StatusBadGateway, "BadGateway"},
		{http.StatusGatewayTimeout, "GatewayTimeout"},
	}
	switch r.Intn(6) {
	case 0:
		return storetest.Fault{Drop: true}
	case 1:
		return storetest.Fault{Drop: true, Land: true}
	case 2:
		s := statuses[r.Intn(len(statuses))]
		return storetest.Fault{Status: s.status, Code: s.code}
	case 3:
		s := statuses[r.Intn(len(statuses))]
		return storetest.Fault{Land: true, Status: s.status, Code: s.code}
	default:
		return storetest.Fault{TruncateBody: 1}
	}
}

// buildFault returns the Fault (if any) and the Rule.Count for class, given
// round (used only to make a proven-conflict's rival bytes distinguishable
// in a failure dump). count is 0 for classClean, meaning "inject nothing".
func buildFault(r *rand.Rand, class faultClass, round int) (fault storetest.Fault, count int) {
	switch class {
	case classClean:
		return storetest.Fault{}, 0
	case classProvablyUnapplied:
		// 1..MaxAttemptsForTest: sometimes the burst ends before the
		// client gives up (succeeds on internal retry), sometimes it
		// exhausts every attempt (a plain retryable error).
		return provablyUnappliedFault(r), 1 + r.Intn(store.MaxAttemptsForTest)
	case classUnknownOutcome:
		// A conditional PutIfAbsent never retries past an unprovable
		// failure (classify returns retry=false), so one occurrence is
		// always enough.
		return unknownOutcomeFault(r), 1
	case classProvenConflict:
		return storetest.Fault{Rival: []byte(fmt.Sprintf(`{"rival":true,"round":%d}`, round))}, 1
	default:
		panic(fmt.Sprintf("chaos: unhandled fault class %v", class))
	}
}

// TestChaosWritePathFaultsAndRestart drives one simulated walden instance at
// a time against a seeded catalogue of injected faults (buildFault above),
// restarting (discarding the *journal.Leases registry for a fresh one, the
// same recovery a real process performs) whenever the stream it was about
// to use turns out fenced on the current registry, and re-checking every
// invariant in checkChaosInvariants after every round. See this file's
// header comment for what it pins and what it deliberately leaves to other
// tests.
func TestChaosWritePathFaultsAndRestart(t *testing.T) {
	seed := chaosEnvInt(t, "WALDEN_CHAOS_SEED", chaosDefaultSeed)
	rounds := chaosEnvInt(t, "WALDEN_CHAOS_ROUNDS", chaosDefaultRounds)

	c, fake := newChaosClient(t)
	ctx := context.Background()

	r := rand.New(rand.NewSource(int64(seed)))
	var leases *journal.Leases
	// fencedOnRegistry tracks which streams the *current* registry has
	// legitimately fenced so far, reset on every restart (a fresh registry
	// starts with a fresh Fencer, per real restart semantics - see the
	// Open-error branch below). assertFencedThenInert uses it to tell "this
	// round's own conflict fenced a healthy stream" (a real isolation
	// violation) from "this stream was already fenced by its own, earlier,
	// independent conflict" (expected, not a violation).
	fencedOnRegistry := map[journal.StreamID]bool{}
	newRegistry := func() {
		leases = journal.NewLeases(c)
		fencedOnRegistry = map[journal.StreamID]bool{}
	}
	newRegistry()

	var acked []chaosAck
	lastChecked := 0 // index into acked already covered by an earlier checkChaosInvariants call

	fail := func(round int, stream journal.StreamID, seq journal.Seq, class faultClass, format string, args ...any) {
		t.Helper()
		t.Fatalf(
			"chaos seed=%d rounds=%d round=%d stream=%s seq=%d class=%s: %s\nreproduce with:\n  WALDEN_CHAOS_SEED=%d WALDEN_CHAOS_ROUNDS=%d go test -race -count=1 -run '^TestChaosWritePathFaultsAndRestart$' ./internal/store/\ncalls:\n%s",
			seed, rounds, round, stream, seq, class, fmt.Sprintf(format, args...), seed, rounds, dumpCalls(fake),
		)
	}

	for round := 1; round <= rounds; round++ {
		stream := chaosStreams[r.Intn(len(chaosStreams))]

		lease, err := leases.Open(ctx, stream)
		if err != nil {
			if !errors.Is(err, journal.ErrFenced) {
				fail(round, stream, 0, classClean, "Open: %v", err)
			}
			// The current registry has this stream fenced: simulate a
			// restart. A real operator's remedy for a fenced stream is
			// exactly this - restart the process to re-materialize from
			// the journal - which resets every stream's in-memory
			// fencing state, not just the one that fenced.
			newRegistry()
			lease, err = leases.Open(ctx, stream)
			if err != nil {
				fail(round, stream, 0, classClean, "Open after restart: %v", err)
			}
		}

		seq := nextSeqFromFake(fake, stream)
		key := journal.TxKey(stream, seq)

		class := pickFaultClass(r)
		fault, count := buildFault(r, class, round)
		if count > 0 {
			fake.Inject(storetest.Rule{Op: storetest.OpPutIfAbsent, Key: key, Call: 1, Count: count, Fault: fault})
		}

		seg, err := c.AppendSegment(ctx, stream, bytes.NewReader(chaosPack), int64(len(chaosPack)))
		if err != nil {
			fail(round, stream, seq, class, "AppendSegment: %v", err)
		}

		gotSeq, appendErr := c.AppendRefTx(ctx, lease, chaosSigner, []string{seg}, chaosUpdates(), chaosNow)

		switch class {
		case classClean:
			if appendErr != nil {
				fail(round, stream, seq, class, "expected success, got %v", appendErr)
			}
			if gotSeq != seq {
				fail(round, stream, seq, class, "AppendRefTx returned seq %d, want %d", gotSeq, seq)
			}
			acked = append(acked, chaosAck{stream, gotSeq})

		case classProvablyUnapplied:
			if appendErr == nil {
				if gotSeq != seq {
					fail(round, stream, seq, class, "AppendRefTx returned seq %d, want %d", gotSeq, seq)
				}
				acked = append(acked, chaosAck{stream, gotSeq})
			} else {
				if errors.Is(appendErr, journal.ErrFenced) {
					fail(round, stream, seq, class, "a provably-unapplied fault must never fence, got %v", appendErr)
				}
				if !errors.Is(appendErr, store.ErrStorageUnavailable) {
					fail(round, stream, seq, class, "expected store.ErrStorageUnavailable, got %v", appendErr)
				}
				if lease.Fencer().IsFenced(stream) {
					fail(round, stream, seq, class, "stream fenced after a provably-unapplied fault")
				}
				if _, ok := fake.Object(key); ok {
					fail(round, stream, seq, class, "object written at %s despite exhausted provably-unapplied retries", key)
				}
			}

		case classUnknownOutcome:
			if appendErr == nil {
				fail(round, stream, seq, class, "expected an unknown-outcome fencing refusal, got success at seq %d", gotSeq)
			}
			if !errors.Is(appendErr, journal.ErrFenced) {
				fail(round, stream, seq, class, "expected journal.ErrFenced, got %v", appendErr)
			}
			want := journal.RefuseAppendOutcomeUnknown(stream, seq).Error()
			if appendErr.Error() != want {
				fail(round, stream, seq, class, "refusal mismatch:\ngot:  %s\nwant: %s", appendErr.Error(), want)
			}
			if fault.Land {
				data, ok := fake.Object(key)
				if !ok {
					fail(round, stream, seq, class, "Land fault set but nothing landed at %s", key)
				}
				var rec journal.RefTransactionRecord
				if err := json.Unmarshal(data, &rec); err != nil {
					fail(round, stream, seq, class, "landed-but-unacknowledged object at %s does not unmarshal: %v", key, err)
				}
				if err := journal.VerifyRefTx(&rec, journal.FormatPublicKey(chaosPub)); err != nil {
					fail(round, stream, seq, class, "landed-but-unacknowledged object at %s does not verify: %v", key, err)
				}
			} else if _, ok := fake.Object(key); ok {
				fail(round, stream, seq, class, "object present at %s despite Land unset", key)
			}
			assertFencedThenInert(t, fmt.Sprintf("seed=%d round=%d", seed, round), c, ctx, lease, fake, stream, chaosStreams, fencedOnRegistry)
			fencedOnRegistry[stream] = true

		case classProvenConflict:
			if appendErr == nil {
				fail(round, stream, seq, class, "expected a fencing refusal from a rival, got success at seq %d", gotSeq)
			}
			if !errors.Is(appendErr, journal.ErrFenced) {
				fail(round, stream, seq, class, "expected journal.ErrFenced, got %v", appendErr)
			}
			want := journal.RefuseStreamFenced(stream, seq).Error()
			if appendErr.Error() != want {
				fail(round, stream, seq, class, "refusal mismatch:\ngot:  %s\nwant: %s", appendErr.Error(), want)
			}
			data, ok := fake.Object(key)
			if !ok || !bytes.Equal(data, fault.Rival) {
				fail(round, stream, seq, class, "rival bytes did not survive at %s: got %q, want %q", key, data, fault.Rival)
			}
			assertFencedThenInert(t, fmt.Sprintf("seed=%d round=%d", seed, round), c, ctx, lease, fake, stream, chaosStreams, fencedOnRegistry)
			fencedOnRegistry[stream] = true
		}

		checkChaosInvariants(t, fmt.Sprintf("seed=%d round=%d", seed, round), fake, acked[lastChecked:])
		lastChecked = len(acked)
	}

	// Once at the end, per the ticket's plan: a full pass re-verifying
	// every acknowledged append from scratch, not just the ones each round
	// added.
	checkChaosInvariants(t, fmt.Sprintf("seed=%d final", seed), fake, acked)
}

// dumpWinnerLoserTable renders one iteration's K outcomes for a failure
// message, per the ticket's plan for the concurrent half.
func dumpWinnerLoserTable(results []error, seqs []journal.Seq) string {
	var b strings.Builder
	for k, err := range results {
		fmt.Fprintf(&b, "  instance %d: seq=%d err=%v\n", k, seqs[k], err)
	}
	return b.String()
}

// TestChaosWritePathConcurrentInstances races chaosConcurrentInstances
// independent journal.NewLeases registries - standing in for separate
// walden processes - against one shared stream over one shared fake,
// repeated across chaosDefaultConcurrentRounds (WALDEN_CHAOS_ROUNDS) fresh
// streams. Every registry opens the stream before any of them appends, so
// the race is certain; a channel close releases them together as a fixed
// barrier. Every assertion below holds under every possible interleaving -
// exactly one winner, K-1 refusals carrying journal.ErrFenced and the
// section 11.5 item-1 wording, and exactly one object at the head sequence
// holding the winner's own record - so this test needs no seed to be
// reproducible (see this file's header comment for why that matters here).
func TestChaosWritePathConcurrentInstances(t *testing.T) {
	rounds := chaosEnvInt(t, "WALDEN_CHAOS_ROUNDS", chaosDefaultConcurrentRounds)
	const k = chaosConcurrentInstances

	c, fake := newChaosClient(t)
	ctx := context.Background()

	for i := 1; i <= rounds; i++ {
		stream := journal.StreamID(fmt.Sprintf("chaos-concurrent-%d", i))

		registries := make([]*journal.Leases, k)
		leases := make([]*journal.Lease, k)
		for j := 0; j < k; j++ {
			registries[j] = journal.NewLeases(c)
			lease, err := registries[j].Open(ctx, stream)
			if err != nil {
				t.Fatalf("iteration %d: instance %d: Open(%s): %v", i, j, stream, err)
			}
			leases[j] = lease
		}

		start := make(chan struct{})
		results := make([]error, k)
		seqs := make([]journal.Seq, k)
		var wg sync.WaitGroup
		for j := 0; j < k; j++ {
			wg.Add(1)
			go func(j int) {
				defer wg.Done()
				<-start
				seq, err := c.AppendRefTx(ctx, leases[j], chaosSigner, nil, chaosUpdates(), chaosNow)
				results[j] = err
				seqs[j] = seq
			}(j)
		}
		close(start) // the fixed barrier: every instance races from the same starting line
		wg.Wait()

		winners, winnerIdx := 0, -1
		for j := 0; j < k; j++ {
			if results[j] == nil {
				winners++
				winnerIdx = j
			}
		}
		if winners != 1 {
			t.Fatalf("iteration %d: stream %s: got %d winners among %d instances, want exactly 1\n%s\ncalls:\n%s",
				i, stream, winners, k, dumpWinnerLoserTable(results, seqs), dumpCalls(fake))
		}
		if seqs[winnerIdx] != 0 {
			t.Fatalf("iteration %d: stream %s: winner (instance %d) landed at seq %d, want 0\n%s",
				i, stream, winnerIdx, seqs[winnerIdx], dumpWinnerLoserTable(results, seqs))
		}

		want := journal.RefuseStreamFenced(stream, 0).Error()
		for j := 0; j < k; j++ {
			if j == winnerIdx {
				continue
			}
			if !errors.Is(results[j], journal.ErrFenced) {
				t.Fatalf("iteration %d: stream %s: loser (instance %d) = %v, want journal.ErrFenced\n%s",
					i, stream, j, results[j], dumpWinnerLoserTable(results, seqs))
			}
			if results[j].Error() != want {
				t.Fatalf("iteration %d: stream %s: loser (instance %d) refusal:\ngot:  %s\nwant: %s\n%s",
					i, stream, j, results[j].Error(), want, dumpWinnerLoserTable(results, seqs))
			}
		}

		key := journal.TxKey(stream, 0)
		data, ok := fake.Object(key)
		if !ok {
			t.Fatalf("iteration %d: stream %s: no object at %s after the race\n%s", i, stream, key, dumpWinnerLoserTable(results, seqs))
		}
		var rec journal.RefTransactionRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			t.Fatalf("iteration %d: stream %s: object at %s does not unmarshal: %v", i, stream, key, err)
		}
		if err := journal.VerifyRefTx(&rec, journal.FormatPublicKey(chaosPub)); err != nil {
			t.Fatalf("iteration %d: stream %s: object at %s does not verify: %v", i, stream, key, err)
		}
		if rec.Stream != stream || rec.Seq != 0 {
			t.Fatalf("iteration %d: stream %s: object at %s names (%s, %d) instead", i, stream, key, rec.Stream, rec.Seq)
		}
	}
}
