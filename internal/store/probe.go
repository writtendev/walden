// This file implements the boot-time compare-and-swap probe (WALD-23,
// spec/journal/v1 section 11.6). WALD-79 deleted the per-provider cas bit
// from journal.go's provider table: a hostname cannot see a proxy in front
// of a bucket or a build too old to honour a precondition, so this probe -
// two real conditional writes against the real bucket - is the sole gate on
// whether object storage may hold a journal. It doubles as the credentials
// and reachability check: a wrong access key, an unreachable endpoint, or
// missing write permission on the prefix all surface here, at boot, with
// one line, rather than on the first push.
package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
)

// probeBody is written to the probe key on both conditional writes. Its
// bytes carry no meaning walden ever reads back - the probe only cares
// whether the two writes it makes behave the way spec section 11.6
// requires - so it is a short fixed constant rather than anything random.
const probeBody = "walden compare-and-swap probe\n"

// ProbeCAS proves, once at boot, that c's bucket honors If-None-Match: *. A
// first PutIfAbsent to a fresh, random v1/probe/<32-hex> key (outside
// v1/streams/, spec section 9.2, so neither materialization nor a stream
// LIST ever sees it) must succeed; a second PutIfAbsent at the same key
// must come back 412. A 200 on the second write means the bucket silently
// overwrote instead of rejecting the precondition, and ProbeCAS returns
// journal.RefuseProviderLacksCAS - spec section 11.5 item 6. Any other
// failure on either write (403, an unreachable endpoint, retries
// exhausted, or ErrOutcomeUnknown) is wrapped once as a plain "invalid
// journal" refusal instead: this is the same probe that would have caught
// a bad access key or a typo'd bucket on the first push, so surfacing
// those as a compare-and-swap capability problem would be wrong, and
// never matches ErrProviderUnsupported.
//
// ProbeCAS always attempts to delete the probe key once its first write is
// not provably unapplied - a success, or ErrOutcomeUnknown, per classify's
// r.conditional rule in client.go: once a conditional request has reached
// storage, no failure past that point proves the write was rejected, so
// the key may exist even though this write returned an error - whether the
// probe otherwise passed or refused. cleanup is a separate, non-nil error -
// never a refusal to boot - when that delete fails; the caller
// (cmd/walden/main.go) prints it as a warning and boots past it. cleanup
// is nil when the delete is skipped because the first write is proven
// never to have landed, since there is then nothing to clean up. A
// stranded probe key is litter, not a durability problem, and nothing
// under v1/streams/ is ever deleted by this or any other operation.
func (c *Client) ProbeCAS(ctx context.Context) (cleanup, err error) {
	key, err := probeKey()
	if err != nil {
		return nil, wrapProbeFailure(err)
	}

	body := []byte(probeBody)
	if err := c.PutIfAbsent(ctx, key, bytes.NewReader(body), int64(len(body))); err != nil {
		if !errors.Is(err, ErrOutcomeUnknown) {
			// The first write is proven never to have landed - see
			// classify's r.conditional rule in client.go - so there is
			// nothing to clean up.
			return nil, wrapProbeFailure(err)
		}
		// The first write's outcome is unknown: it may have landed even
		// though this attempt came back an error, so attempt cleanup
		// rather than stranding v1/probe/<hex> forever (spec section
		// 11.6 item 6).
		return c.cleanupProbeKey(ctx, key), wrapProbeFailure(err)
	}

	err = c.PutIfAbsent(ctx, key, bytes.NewReader(body), int64(len(body)))
	switch {
	case errors.Is(err, ErrPrecondition):
		// The bucket rejected the second write, exactly as spec section
		// 11.6 requires: the probe passes.
		err = nil
	case err == nil:
		// The bucket accepted a second write against a key that already
		// existed: it does not honor If-None-Match, so it cannot host a
		// journal.
		err = journal.RefuseProviderLacksCAS(c.providerName())
	default:
		err = wrapProbeFailure(err)
	}

	return c.cleanupProbeKey(ctx, key), err
}

// providerName names the bucket in ProbeCAS's refusal, and in the wrapped
// refusal any other probe failure produces: c.journal.Provider when walden
// recognises the endpoint host, or the endpoint's host[:port] otherwise -
// MinIO, Ceph RGW, and Garage have no provider name to give.
func (c *Client) providerName() string {
	if c.journal.Provider != "" {
		return c.journal.Provider
	}
	if u, err := url.Parse(c.journal.Endpoint); err == nil && u.Host != "" {
		return u.Host
	}
	return c.journal.Endpoint
}

// probeUnavailableFix is probeFailureFix's clause for the transient class -
// ErrStorageUnavailable: retries exhausted, or a send that never reached
// storage at all (a dial failure, a closed port, a name that does not
// resolve). It is deliberately boot-appropriate rather than borrowed from
// the wrapped cause: ProbeCAS runs before cmd/walden/main.go calls
// net.Listen, so a failure here means walden has exited and bound
// nothing, not that it is up and degrading - fixFor's "pushes succeed
// when storage returns" (client.go) describes the latter, and would tell
// an operator reading this refusal that requests are already being
// served when none are.
const probeUnavailableFix = "restart walden once storage is reachable, or check the journal knob"

// probeOutcomeUnknownFix is probeFailureFix's clause for ErrOutcomeUnknown:
// the probe cannot prove whether its write landed, but it cannot tell the
// operator to wait for storage to "become reachable" either - the request
// may already have been answered, just not legibly. What is true
// regardless is that every boot draws a fresh probeKey (crypto/rand, 16
// bytes), so a stray write from this attempt can never collide with the
// next one: restarting is always safe, unlike probeUnavailableFix's
// framing (which implies storage is currently down) or the permanent
// classes below (where restarting would just repeat the same refusal).
const probeOutcomeUnknownFix = "restart walden - the probe key is fresh each boot, so this attempt's write, landed or not, cannot affect the next one"

// wrapProbeFailure wraps any ProbeCAS failure that is not itself the
// compare-and-swap capability problem - a 403, an unreachable endpoint,
// retries exhausted, or an ambiguous outcome - as a single "invalid
// journal" refusal, with probeFailureFix(cause) as its fix clause. The
// detail comes from probeFailureWhy rather than cause.Error(): a
// *refusal.Refusal from PutIfAbsent formats its own Fix (fixFor, tuned for
// a running server mid-push) into that string, and appending another fix
// clause alongside it would stack two into a single line.
func wrapProbeFailure(cause error) error {
	return refusal.RefuseWithCause("invalid journal", "compare-and-swap probe: "+probeFailureWhy(cause), probeFailureFix(cause), cause)
}

// probeFailureFix picks wrapProbeFailure's fix clause by cause's failure
// class - never one uniform string, because "restart" is only true advice
// for some of them:
//
//   - ErrStorageUnavailable (retries exhausted, a dial failure, an
//     unreachable endpoint): probeUnavailableFix. Storage was not there to
//     answer, so restarting once it is back is the actual remedy.
//   - ErrOutcomeUnknown (an ambiguous write, on either the first or the
//     second PutIfAbsent): probeOutcomeUnknownFix. Neither
//     probeUnavailableFix's "once storage is reachable" (it may already be)
//     nor the permanent classes' credentials clause (nothing said the
//     credentials were wrong) fits, and fixFor itself returns "" here since
//     it assumes the journal layer supplies the fix for a running server.
//   - everything else - ErrStorageRefused (403, 404 NoSuchBucket, 501, and
//     any other permanent status) and any cause classify cannot name -
//     fixFor(cause), which for these lands on its own default: "check
//     bucket, region and credentials". Storage was reachable and refused,
//     so restarting changes nothing; the credentials-and-bucket clause is
//     the one that actually points at what this probe exists to catch.
func probeFailureFix(cause error) string {
	switch {
	case errors.Is(cause, ErrStorageUnavailable):
		return probeUnavailableFix
	case errors.Is(cause, ErrOutcomeUnknown):
		return probeOutcomeUnknownFix
	default:
		return fixFor(cause)
	}
}

// probeFailureWhy returns cause's detail without any fix clause of its
// own: the bare "<what>: <why>" of a *refusal.Refusal from PutIfAbsent, or
// cause.Error() for a plain error (probeKey's crypto/rand failure never
// carries one). Skipping the *Refusal's own Fix field here is what keeps
// wrapProbeFailure's probeFailureFix the only fix clause in the result.
func probeFailureWhy(cause error) string {
	var r *refusal.Refusal
	if errors.As(cause, &r) {
		return r.What + ": " + r.Why
	}
	return cause.Error()
}

// cleanupProbeKey deletes key and returns a one-line warning - never a
// refusal - when the delete fails. It is always safe to call once the
// probe's first write has landed, whether the probe otherwise passed or
// refused.
//
// The warning's text comes from probeFailureWhy(err), not err.Error(): the
// delete's own *refusal.Refusal carries an append-time fix clause of its
// own (fixFor's "pushes succeed when storage returns" for a retry-exhausted
// delete, or "check bucket, region and credentials" for a 403) that is
// wrong here on both counts - net.Listen has not run yet, so nothing is
// pushing, and per spec/journal/v1 section 11.6 a failed cleanup delete is
// litter to note and move past, not a problem for the operator to act on.
// probeFailureWhy strips that clause, leaving no Fix at all - an empty Fix
// formats with no trailing parentheses, which is the correct shape for a
// warning with nothing to tell the operator to do.
func (c *Client) cleanupProbeKey(ctx context.Context, key string) error {
	if err := c.delete(ctx, key); err != nil {
		return refusal.RefuseWithCause("journal probe cleanup", "left "+key+" behind: "+probeFailureWhy(err), "", err)
	}
	return nil
}

// probeKey returns a fresh v1/probe/<32-hex> key, journal-relative: 16
// random bytes from crypto/rand, hex-encoded. A random suffix per boot
// means two waldens starting against the same journal prefix never race
// the same probe key.
func probeKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "v1/probe/" + hex.EncodeToString(b[:]), nil
}
