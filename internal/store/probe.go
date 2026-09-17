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
// never a refusal to boot - when that delete fails, or is skipped because
// the first write is proven never to have landed; the caller
// (cmd/walden/main.go) prints it as a warning and boots past it. A
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

// wrapProbeFailure wraps any ProbeCAS failure that is not itself the
// compare-and-swap capability problem - a 403, an unreachable endpoint,
// retries exhausted, or an ambiguous outcome - as a single "invalid
// journal" refusal. The fix is left empty: the wrapped cause (a
// *refusal.Refusal from PutIfAbsent, or a plain error generating the probe
// key) already carries what an operator needs, and a second "(...)" would
// stack two fixes into one line.
func wrapProbeFailure(cause error) error {
	return refusal.RefuseWithCause("invalid journal", "compare-and-swap probe: "+cause.Error(), "", cause)
}

// cleanupProbeKey deletes key and returns a one-line warning - never a
// refusal - when the delete fails. It is always safe to call once the
// probe's first write has landed, whether the probe otherwise passed or
// refused.
func (c *Client) cleanupProbeKey(ctx context.Context, key string) error {
	if err := c.delete(ctx, key); err != nil {
		return refusal.RefuseWithCause("journal probe cleanup", "left "+key+" behind: "+err.Error(), "", err)
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
