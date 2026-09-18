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
	"net"
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

	// chaosConcurrentRoundsCap bounds how many rounds
	// TestChaosWritePathConcurrentInstances ever runs, even when
	// WALDEN_CHAOS_ROUNDS asks for more - deliberately decoupling the
	// concurrent half's budget from the sequential half's. WALD-35 PR #65's
	// round-2 review found the nightly workflow driving both halves off one
	// WALDEN_CHAOS_ROUNDS=5000 exhausting the runner's ephemeral port range
	// (see .github/workflows/chaos.yml and newChaosConcurrentClient's doc
	// comment for the mechanism and the fix on the connection-reuse side).
	// The other half of that fix is here: unlike
	// TestChaosWritePathFaultsAndRestart, whose seeded fault catalogue keeps
	// exploring new ground every additional round, this test has no
	// catalogue and no seed - every round is the same fixed barrier over
	// the same K=5 instances.
	//
	// Round-3 review corrected the reasoning that used to stand here.
	// "Every assertion already holds under every interleaving by
	// construction" is true, and it is why a failure in this test is never
	// a flake (see this test's own doc comment) - but that is a claim
	// about the assertions, not about what repeating the race explores.
	// What varies round to round is the schedule, not the property:
	// which of the K instances reaches the fake's CAS mutex first, and
	// where the Go runtime preempts each goroutine. Sampling schedules is
	// the only reason to run a race test more than once at all, so rounds
	// past a few hundred still buy real, if steeply diminishing,
	// interleaving coverage - not merely "confirmation of a property that
	// does not vary round to round," which would equally have justified
	// capping this at 5.
	//
	// The cap holds anyway, for the reason that actually binds: port
	// budget, not a coverage ceiling. At K=5 shared-client connections per
	// round, even newChaosConcurrentClient's wider pool leaves this half's
	// port usage scaling with round count (see its own doc comment), and
	// 500 is sized to keep that unremarkable rather than to stop sampling
	// new schedules - see .github/workflows/chaos.yml for the measured
	// figures. 500 is 12.5x chaosDefaultConcurrentRounds (the same order
	// of magnitude the nightly scales the sequential half's default by),
	// and every mutation this half alone catches, it catches by iteration
	// 1 (see the PR's round-2 and round-3 review for the re-run mutation
	// table) - so nothing this file currently relies on this half to
	// detect is lost at 500. Raising the cap trades port budget for more
	// interleaving sampling; it is not fixing an assertion that is
	// unsound below it.
	chaosConcurrentRoundsCap = 500
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

// chaosConcurrentClientMaxIdleConnsPerHost is the concurrent test's own
// *http.Transport idle-connection-pool ceiling per host, comfortably above
// chaosConcurrentInstances (K): TestChaosWritePathConcurrentInstances
// routes every one of K goroutines' requests, on every round, through one
// shared *store.Client, so that Client's Transport idle pool is shared
// across a burst of K simultaneous requests. net/http's default
// MaxIdleConnsPerHost (2) is far below K=5, so on every round the K-2
// requests that exceed the idle pool close their TCP connection instead of
// returning it to the pool when the request finishes, and each such close
// leaves an ephemeral port in TIME_WAIT for the OS's usual linger period.
// WALD-35 PR #65's round-2 review measured this exhausting the runner's
// ephemeral port range at the nightly workflow's WALDEN_CHAOS_ROUNDS=5000
// (see .github/workflows/chaos.yml, and chaosConcurrentRoundsCap's doc
// comment for the other half of the fix). Raising the ceiling well above K
// lets every instance's connection be reused round after round instead of
// closed and redialed, which removes the growth rather than merely
// slowing it.
const chaosConcurrentClientMaxIdleConnsPerHost = 64

// newChaosConcurrentClient is newChaosClient's counterpart for
// TestChaosWritePathConcurrentInstances, the one test in this file that
// ever has more than one request in flight on the same *store.Client at
// once. It is built through store.NewClientForTest - exposed by
// export_test.go for exactly this kind of test-side *http.Client injection
// - with a wider connection pool per host
// (chaosConcurrentClientMaxIdleConnsPerHost) than store.NewClient (used by
// newChaosClient) sets by default, rather than through store.NewClient
// itself: this is the concurrent test's own transport to configure, not
// production's - client.go's NewClient, and its own default pool size, are
// untouched. Every other Transport setting mirrors client.go's own
// production values, duplicated here by literal value since client.go's
// are unexported and this file's two-file scope (chaos_test.go and
// .github/workflows/chaos.yml only) keeps this file from exporting them: a
// staleness risk if client.go's own numbers ever change, not a correctness
// one, since none of this test's fault injection reads these exact
// durations (unlike TestChaosWritePathFaultsAndRestart, this test injects
// no faults at all).
func newChaosConcurrentClient(t *testing.T) (*store.Client, *storetest.Fake) {
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
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext, // mirrors client.go's dialTimeout
			TLSHandshakeTimeout:   10 * time.Second,                                     // mirrors client.go's tlsHandshakeTimeout
			ResponseHeaderTimeout: 30 * time.Second,                                     // mirrors client.go's responseHeaderTimeout
			IdleConnTimeout:       30 * time.Second,                                     // mirrors client.go's idleConnTimeout
			MaxIdleConnsPerHost:   chaosConcurrentClientMaxIdleConnsPerHost,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // mirrors client.go's own CheckRedirect
		},
	}
	return store.NewClientForTest(j, httpClient, chaosNow), fake
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

// chaosInvariantState carries the running state checkChaosInvariantsRound
// needs to check this file's per-round invariants incrementally - in
// O(new work this round) rather than by rescanning fake's entire history
// every round. Before this type existed, checkChaosInvariants rescanned
// fake.Calls() (for the no-double-land and no-unconditional-PUT checks)
// and fake.Keys() (for the no-gap check) from scratch on every call, so a
// chaos run's cost was quadratic in its round count - invisible at this
// file's small default budget, but it meant the nightly workflow's much
// larger WALDEN_CHAOS_ROUNDS never finished inside any reasonable timeout
// (WALD-35 PR #65 review; see .github/workflows/chaos.yml). callsChecked
// is how many of fake.Calls() the call-based checks below have already
// scanned; landed and poisoned are the running per-key state those checks
// need (see checkTxCallInvariants); frontier is the next sequence each
// stream is expected to occupy, for the no-gap check (see
// checkNoGapAtKey). checkChaosInvariantsFinal still does one full,
// from-scratch sweep at the end with fresh state, as a check against a bug
// in this incremental bookkeeping itself and not only against the
// production code under test - "once at the end" per the ticket's plan,
// the same idiom this file already used for the signature-verification
// invariant before this split.
//
// callsChecked alone is not enough to make the call-based checks cheap,
// though: storetest.Fake.Calls() (test-support code this file's approved
// scope does not touch) copies its entire, ever-growing call log on every
// invocation, so even a windowed scan over calls[callsChecked:] still pays
// O(total calls so far) just to obtain that slice - the residual quadratic
// cost that made a WALDEN_CHAOS_ROUNDS=20000 nightly run measure 629s
// without even the first test completing. checkChaosInvariantsRound below
// works around this by calling fake.Calls() only at a bounded number of
// checkpoints per run (chaosCallsCheckpoints), rather than every round: see
// its own doc comment.
type chaosInvariantState struct {
	callsChecked int
	landed       map[string]int
	poisoned     map[string]bool
	frontier     map[journal.StreamID]journal.Seq
}

func newChaosInvariantState() *chaosInvariantState {
	return &chaosInvariantState{
		landed:   make(map[string]int),
		poisoned: make(map[string]bool),
		frontier: make(map[journal.StreamID]journal.Seq),
	}
}

// predictedSeq returns the sequence a round about to touch stream should
// expect - the same value (*journal.Leases).Open will discover as that
// stream's head plus one, or 0 if the stream has no key yet, so a round can
// inject a fault against the exact key about to be written before making
// the call ("just-in-time", per the ticket's plan) without reaching into
// journal.Lease's unexported state.
//
// This file used to compute that by scanning fake.Keys() fresh every round
// (nextSeqFromFake, since removed) - a full copy-and-sort of every key in
// the bucket, and, on top of the calls-based checks' own cost, a third
// per-round O(n log n) scan WALD-35 PR #65's review named as a source of
// the nightly's quadratic runtime (chaosCallsCheckpoints' doc comment
// covers the other two). frontier already tracks the same value
// incrementally, in O(1), as a side effect of checkNoGapAtKey verifying
// every round's own write lands where expected: the two stay in lockstep
// by construction, since every tx/ key this file's round loop ever writes
// is written at exactly the key predictedSeq names (see buildFault, and
// checkNoGapAtKey's own doc comment for why no round ever touches a
// different key). checkChaosInvariantsFinal's full, from-scratch
// checkNoGapFull sweep at the end of every run is the safety net that
// would still catch any drift between this shortcut and the bucket's real
// state, the same role it plays for the other invariants this file checks
// incrementally.
func (s *chaosInvariantState) predictedSeq(stream journal.StreamID) journal.Seq {
	return s.frontier[stream]
}

// chaosCallsCheckpoints bounds how many times TestChaosWritePathFaultsAndRestart
// calls fake.Calls() over one run, regardless of how many rounds that run
// has. Fixing the number of checkpoints, rather than fixing the interval
// between them, keeps the total cost of every fake.Calls() copy across a
// run O(chaosCallsCheckpoints * finalCallCount) - linear in the run's own
// size no matter how large WALDEN_CHAOS_ROUNDS scales it, unlike a fixed
// interval (which still degrades to a call-log copy every round as rounds
// grows) or no bound at all (the O(rounds^2) cost this const exists to
// cap). checkNoGapAtKey and verifyAcks stay genuinely per-round regardless
// of this constant: they read fake.Object, not fake.Calls(), so checking
// them every round costs nothing extra. 100 checkpoints keeps a call-based
// invariant violation attributable to a window of about rounds/100 rounds
// even at the nightly budget - see checkChaosInvariantsRound.
const chaosCallsCheckpoints = 100

// checkTxCallInvariants scans calls - a slice of fake.Calls() in arrival
// order - for three of this file's invariants against every tx/ key they
// touch:
//
//   - a tx/ key is never written unconditionally (OpPut);
//   - a tx/ key never lands (Landed == true) more than once - two
//     independent instances never both land a record at one (stream, seq);
//   - a tx/ key never sees a PUT(If-None-Match: *) after it has already
//     seen a genuine 412 for that same key.
//
// The third check is the fix for what WALD-35 PR #65's review found: this
// file's fault catalogue never deletes a tx/ key or sets IgnoreCondition,
// so a second conditional PUT against an already-occupied key always lands
// false, and the "landed more than once" check alone could never fire -
// it would pass even if AppendRefTx resent PutIfAbsent after a proven 412
// (spec/journal/v1 section 11.4 items 3 and 6, and the exact mutation the
// ticket's own "how to know it worked" names as its demonstration).
// Counting the request itself, not just a successful landing, is what
// makes it falsifiable: a resend is illegal the moment it is sent, whether
// or not it happens to land. A legitimate retry never trips this: every
// fault class in this file that can retry the same key
// (classProvablyUnapplied's burst of
// 408/429/503/400-RequestTimeout/409-ConditionalRequestConflict) never
// includes a 412, and the one fault class in this test's sequential half
// that does produce a real 412 (classProvenConflict) fires at most once
// per key: assertFencedThenInert (called immediately after, in the round
// loop) proves the writer fences and makes zero further requests, and
// frontier (chaosInvariantState) only ever advances predictedSeq past a
// key once something has landed there, so no later round in the
// sequential half ever asks buildFault to target an already-occupied key
// again - see classify in client.go, which never retries past a 412 at
// all.
//
// This checker is not valid for TestChaosWritePathConcurrentInstances'
// race, and must not be wired into it without reworking it first: there, K
// independent instances all send PutIfAbsent against the very same key at
// once, and a genuine, entirely correct race produces up to K-1 real 412s
// on that one key (one winner, K-1 losers) - "fires at most once per key"
// above holds only because the sequential half never retries a key past a
// proven 412, not because a 412 is inherently rare there. The concurrent
// test happens to never call checkTxCallInvariants today, which is the
// only reason this file's current behavior is correct; wiring it in as
// written would fail on entirely correct concurrent code.
//
// landed and poisoned are mutated in place, so a caller can run this
// call-window by call-window across many invocations (see
// checkChaosInvariantsRound) and get the same result as one call over the
// whole log (see checkChaosInvariantsFinal) - the same incremental-vs-full
// equivalence the signature check below already relies on.
//
// fail reports a violation found among calls; it does not call t.Fatalf
// itself, because what a caller can honestly say about "where" a violation
// happened differs by who is calling: checkChaosInvariantsRound only owns
// a checkpoint's own round range (see chaosCallFailf), and
// checkChaosInvariantsFinal owns the whole run. Both build fail with
// chaosCallFailf so every call-based failure - checkpoint or final - still
// carries the seed, round count, and replay command every other failure in
// this file does.
func checkTxCallInvariants(t *testing.T, fail func(format string, args ...any), fake *storetest.Fake, calls []storetest.Call, landed map[string]int, poisoned map[string]bool) {
	t.Helper()
	for _, call := range calls {
		if call.Op != storetest.OpPut && call.Op != storetest.OpPutIfAbsent {
			continue
		}
		if !strings.Contains(call.Key, "/tx/") {
			continue
		}
		if call.Op == storetest.OpPut {
			fail("unconditional PUT to tx key %s\ncalls:\n%s", call.Key, dumpCalls(fake))
		}
		if poisoned[call.Key] {
			fail("PUT(If-None-Match: *) to tx key %s (call #%d) after that key already saw a proven 412 - a proven 412 must never be resent\ncalls:\n%s", call.Key, call.N, dumpCalls(fake))
		}
		if call.Landed {
			landed[call.Key]++
			if landed[call.Key] > 1 {
				fail("tx key %s landed %d times (sequence forked)\ncalls:\n%s", call.Key, landed[call.Key], dumpCalls(fake))
			}
		}
		if call.Status == http.StatusPreconditionFailed {
			poisoned[call.Key] = true
		}
	}
}

// chaosCallFailf builds the failure formatter checkTxCallInvariants reports
// every call-based invariant violation through. Unlike checkNoGapAtKey and
// verifyAcks, which run every round and can honestly name the exact round a
// violation happened on, checkTxCallInvariants only inspects fake.Calls()
// at a bounded number of checkpoints (chaosCallsCheckpoints) - so all a
// mid-run match actually establishes is that some call within window (a
// round range, described by the caller) is the culprit, never that the
// checkpoint's own round is where it happened. WALD-35 PR #65's round-2
// review found the previous version of this file printing the checkpoint
// round as if it were the violating round, with no round count and no
// replay command - unlike fail() in the round loop below. window names
// what this call actually knows (a round range for a mid-run checkpoint,
// or that it swept the complete history for the final, once-at-the-end
// check - see checkChaosInvariantsFinal), and this always prints the same
// seed, rounds, and replay command fail() does, so a call-based failure
// stays exactly as reproducible from its own output as every other
// failure in this file.
func chaosCallFailf(t *testing.T, seed, rounds int, window string) func(format string, args ...any) {
	return func(format string, args ...any) {
		t.Helper()
		t.Fatalf(
			"chaos seed=%d rounds=%d %s: %s\nreproduce with:\n  WALDEN_CHAOS_SEED=%d WALDEN_CHAOS_ROUNDS=%d go test -race -count=1 -run '^TestChaosWritePathFaultsAndRestart$' ./internal/store/",
			seed, rounds, window, fmt.Sprintf(format, args...), seed, rounds,
		)
	}
}

// checkNoGapAtKey is the incremental form of the no-permanent-gap
// invariant: rather than rescanning every key in the bucket every round
// (chaosTxSeqsByStream below, over fake.Keys() - O(n log n) in the
// bucket's current size, and the dominant cost of the quadratic runtime
// the WALD-35 PR #65 review measured), it checks only the exact key this
// round itself could have written, (stream, seq) - the one key any round
// ever touches, whether via the client's own write or
// storetest.Fault.Rival (which lands directly at the same predicted key -
// see buildFault). If something landed there, it must be exactly the next
// sequence this stream was expecting; if nothing did (an exhausted
// provably-unapplied retry, or an unknown-outcome fault with Land unset),
// the stream's frontier is unchanged, and the next round touching this
// stream will predict the same key again via predictedSeq, which is
// correct.
func checkNoGapAtKey(t *testing.T, label string, fake *storetest.Fake, frontier map[journal.StreamID]journal.Seq, stream journal.StreamID, seq journal.Seq) {
	t.Helper()
	if _, ok := fake.Object(journal.TxKey(stream, seq)); !ok {
		return
	}
	if want := frontier[stream]; seq != want {
		t.Fatalf("%s: stream %s has a sequence gap: a key landed at seq %d, want %d next", label, stream, seq, want)
	}
	frontier[stream] = seq + 1
}

// checkNoGapFull is the full, from-scratch form of the no-gap invariant,
// checked against raw key presence (see parseTxKey's doc comment) rather
// than the acked list, since a key a rival wrote directly still occupies
// its seq from a fresh registry's head-discovery point of view. Used only
// by checkChaosInvariantsFinal, once, at the end of a run.
func checkNoGapFull(t *testing.T, label string, fake *storetest.Fake) {
	t.Helper()
	for stream, seqs := range chaosTxSeqsByStream(fake) {
		sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
		for i, s := range seqs {
			if uint64(s) != uint64(i) {
				t.Fatalf("%s: stream %s has a sequence gap: seqs=%v", label, stream, seqs)
			}
		}
	}
}

// verifyAcks checks invariant 3 (present, intact, verifiable, segments
// exist) for every entry in verify - the round loop below passes only the
// entries newly acknowledged this round, an O(1)-amortized signature
// re-verification per round rather than re-verifying the whole run's
// history every round (which is what "after every round" cost before this
// split existed: O(rounds^2) ed25519 verifications, the dominant share of
// this test's added runtime). checkChaosInvariantsFinal calls this once
// more with the complete acked slice, so every acknowledged append is
// still verified at least once each - "once at the end" per the ticket's
// plan, satisfied literally as well as incrementally.
func verifyAcks(t *testing.T, label string, fake *storetest.Fake, verify []chaosAck) {
	t.Helper()
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
}

// checkChaosInvariantsRound runs the cheap, incremental form of every
// invariant in this file's header comment after one round of
// TestChaosWritePathFaultsAndRestart: seed and rounds are the run's own
// parameters (for chaosCallFailf's replay command below), round is this
// round's number, stream and seq are that round's own predicted (stream,
// seq) coordinate (see chaosInvariantState.predictedSeq), and newAcks is
// only the entries newly acknowledged this round. checkCalls, computed by
// the caller from chaosCallsCheckpoints, tells this round whether it is
// one of the bounded number of checkpoints that pays for a fake.Calls()
// copy; checkNoGapAtKey and verifyAcks run every round regardless, since
// neither needs the call log. See chaosInvariantState's doc comment for
// why this must stay incremental, and chaosCallsCheckpoints' for why
// "incremental" alone was not enough to stop rescanning fake's whole
// history every round. checkpointStart is the last round an earlier
// checkpoint already covered (0 if this is the first), so a call-based
// violation here is reported honestly as somewhere within
// (checkpointStart, round], not as round itself - see chaosCallFailf.
func checkChaosInvariantsRound(t *testing.T, seed, rounds, round, checkpointStart int, fake *storetest.Fake, state *chaosInvariantState, newAcks []chaosAck, stream journal.StreamID, seq journal.Seq, checkCalls bool) {
	t.Helper()
	label := fmt.Sprintf("seed=%d round=%d", seed, round)
	if checkCalls {
		calls := fake.Calls()
		window := fmt.Sprintf("checkpoint round=%d (a call-based check runs only at checkpoints, chaosCallsCheckpoints of them per run - this failure was found somewhere within rounds %d-%d, not necessarily at round %d itself)", round, checkpointStart+1, round, round)
		checkTxCallInvariants(t, chaosCallFailf(t, seed, rounds, window), fake, calls[state.callsChecked:], state.landed, state.poisoned)
		state.callsChecked = len(calls)
	}
	checkNoGapAtKey(t, label, fake, state.frontier, stream, seq)
	verifyAcks(t, label, fake, newAcks)
}

// checkChaosInvariantsFinal runs every invariant in this file's header
// comment once more, from scratch, against fake's complete final state -
// the "once at the end" full sweep chaosInvariantState's doc comment
// promises, and a check against a bug in the incremental bookkeeping
// itself, not only against the production code under test. seed and
// rounds feed chaosCallFailf's replay command, the same as
// checkChaosInvariantsRound; label is used only for the two checks that
// already honestly name "final" (checkNoGapFull, verifyAcks).
func checkChaosInvariantsFinal(t *testing.T, seed, rounds int, label string, fake *storetest.Fake, acked []chaosAck) {
	t.Helper()
	checkTxCallInvariants(t, chaosCallFailf(t, seed, rounds, "final sweep (complete call history, every round)"), fake, fake.Calls(), make(map[string]int), make(map[string]bool))
	checkNoGapFull(t, label, fake)
	verifyAcks(t, label, fake, acked)
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
// wroteOK.Load() || delivered. Measured (instrumenting send during this
// ticket's review, WALD-35 PR #65): for a body this small - a
// ref-transaction record, far under the 64 KiB chunk size - wroteOK alone
// already reads true, independent of delivered, because net/http's
// WroteRequest trace hook fires with a nil error as soon as the small
// request's local write completes into the connection's socket buffer,
// which happens before the fake ever reads past its TruncateBody cutoff.
// (delivered also happens to go true here, since the aws-chunked encoder
// drains a body this size into a single chunk in one local read - but that
// is not what decides the classification, and a future reader should not
// "fix" delivered expecting this case to reclassify as provably-unapplied:
// wroteOK would still make wrote true on its own.) The same measurement
// shows where the boundary actually is: a 200000-byte body cut well before
// the local write completes gives wroteOK=false and delivered=false, and
// classify's wrote==false path is what makes that shape safely resendable.
// So for this file's small bodies, wrote is true, and classify (client.go)
// treats the conditional request as having reached storage, exactly as it
// must for a genuinely larger body truncated mid-chunk. The fake proves
// nothing was stored (TruncateBody's branch in handlePut runs and returns
// before the PUT condition is even evaluated), but the client has no way
// to know that - it only knows its own local write finished - so it
// correctly does what section 11.4 item 6 requires of an unprovable
// outcome: fence rather than guess. That is conservative, not incorrect:
// an unnecessary fencing costs availability, never the two invariants this
// file exists to pin. Land is irrelevant to this shape (the fake's
// TruncateBody branch returns before Land is ever consulted), so it is
// deliberately left unset here - the per-round assertion for this fault
// class already handles Land == false by checking the key stays absent,
// which holds for this shape too.
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
	lastChecked := 0              // index into acked already covered by an earlier checkChaosInvariantsRound call
	lastCallsCheckpointRound := 0 // most recent round whose checkpoint already scanned fake.Calls(); see checkChaosInvariantsRound's checkpointStart
	invState := newChaosInvariantState()

	// callsCheckInterval spaces the run's fake.Calls() checkpoints (see
	// chaosCallsCheckpoints) evenly across every round, rounding down to at
	// least 1 so a small run (the default budget) still checks calls every
	// round exactly as before this file added the checkpoint bound.
	callsCheckInterval := rounds / chaosCallsCheckpoints
	if callsCheckInterval < 1 {
		callsCheckInterval = 1
	}

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

		seq := invState.predictedSeq(stream)
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

		checkCalls := round%callsCheckInterval == 0 || round == rounds
		checkChaosInvariantsRound(t, seed, rounds, round, lastCallsCheckpointRound, fake, invState, acked[lastChecked:], stream, seq, checkCalls)
		lastChecked = len(acked)
		if checkCalls {
			lastCallsCheckpointRound = round
		}
	}

	// Once at the end, per the ticket's plan: a full pass re-checking every
	// invariant from scratch against fake's complete final state, not just
	// the incremental work each round added.
	checkChaosInvariantsFinal(t, seed, rounds, fmt.Sprintf("seed=%d final", seed), fake, acked)
}

// chaosInstanceUpdates returns a ref update unique to instance j among the
// k racing instances in TestChaosWritePathConcurrentInstances, so the
// "exactly one object landed, and it is the provable winner's own record"
// check at the end of that test is actually falsifiable. WALD-35 PR #65's
// review found that with every instance marshaling a byte-identical record
// (same signer, same fixed clock, the same single chaosUpdates() value,
// nil segments), that check degenerated to "some valid record is present
// at the head sequence" - true regardless of which instance actually won.
// A distinct ref name and OID per instance makes the landed record's
// identity a genuine claim about who won. The value differs only by j, an
// input fixed before the race starts, never by anything that depends on
// scheduling, so this keeps the concurrent half interleaving-independent -
// the property that keeps it non-flaky (see this file's header comment).
func chaosInstanceUpdates(j int) []journal.RefUpdate {
	return []journal.RefUpdate{
		{Ref: fmt.Sprintf("refs/heads/instance-%d", j), OldOID: journal.ZeroOID40, NewOID: fmt.Sprintf("%040x", j+1)},
	}
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
// repeated across chaosDefaultConcurrentRounds (WALDEN_CHAOS_ROUNDS, capped
// at chaosConcurrentRoundsCap - see its own doc comment for why this half
// keeps its own, smaller budget rather than scaling 1:1 with
// WALDEN_CHAOS_ROUNDS the way it used to) fresh streams. Every registry
// opens the stream before any of them appends, so the race is certain; a
// channel close releases them together as a fixed barrier. Every assertion
// below holds under every possible interleaving - exactly one winner, K-1
// refusals carrying journal.ErrFenced and the section 11.5 item-1 wording,
// and exactly one object at the head sequence holding the winner's own
// record - so this test needs no seed to be reproducible (see this file's
// header comment for why that matters here).
func TestChaosWritePathConcurrentInstances(t *testing.T) {
	rounds := chaosEnvInt(t, "WALDEN_CHAOS_ROUNDS", chaosDefaultConcurrentRounds)
	if rounds > chaosConcurrentRoundsCap {
		rounds = chaosConcurrentRoundsCap
	}
	const k = chaosConcurrentInstances

	c, fake := newChaosConcurrentClient(t)
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
				seq, err := c.AppendRefTx(ctx, leases[j], chaosSigner, nil, chaosInstanceUpdates(j), chaosNow)
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
		// The record at the head sequence must be the winner's own -
		// chaosInstanceUpdates(winnerIdx), not merely some instance's -
		// which is what makes this check mean something instead of
		// degenerating to "some valid record is present" (see
		// chaosInstanceUpdates' doc comment).
		wantUpdates := chaosInstanceUpdates(winnerIdx)
		if len(rec.Updates) != len(wantUpdates) || rec.Updates[0] != wantUpdates[0] {
			t.Fatalf("iteration %d: stream %s: object at %s carries updates %+v, want the winner's (instance %d) own: %+v",
				i, stream, key, rec.Updates, winnerIdx, wantUpdates)
		}
	}
}
