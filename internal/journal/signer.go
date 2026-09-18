// This file adds walden's signing identity as a value (WALD-30): a
// Signer bundles the private key a process appends with, together with
// the epoch and formatted public key a verified *SigningChain reports for
// it, so a ref transaction cannot be signed with a key the journal does
// not name — that disagreement becomes unrepresentable rather than merely
// discouraged.
//
// Signer holds no cryptographic mechanism of its own: the actual signing
// still happens in the package-level SignRefTx (reftx.go); this file only
// decides, once, which key and epoch a process signs with, and then
// stamps that pair onto every record it signs.
package journal

import (
	"crypto/ed25519"
	"fmt"
)

// Signer is an immutable signing identity, good for the life of the
// process that built it: an Ed25519 private key, the epoch a verified
// signing chain reported as active for it at the moment NewSigner ran, and
// that key's own public half, formatted.
//
// A Signer does not hold the *SigningChain it was built from. A
// SigningChain carries the mutable state of one replay and is explicitly
// not safe for concurrent use (see its own doc comment); Signer's three
// fields are set once, by NewSigner, and never written again, which is
// what makes a Signer itself safe for concurrent use.
//
// NewSigner is the only place that checks a key against a chain, but it
// is not the only way a *Signer value can come to exist: Signer's fields
// are unexported, not unconstructable — &Signer{} and new(Signer) compile
// from any package and produce a non-nil *Signer whose private key is
// nil (the wrong size for ed25519.Sign, which panics rather than errors
// on that). Valid and SignRefTx below both guard against that specific
// shape at the point that would otherwise panic. Neither this comment nor
// theirs claims a *Signer is guaranteed to have gone through NewSigner,
// or that it still matches whatever chain it was checked against — only
// that SignRefTx returns an error instead of panicking when its key is
// the wrong size.
//
// A Signer must be short-lived and re-derived per process — loaded fresh
// by whatever process is about to append, never cached across a key
// rotation. One held past a rotation would go on stamping the epoch it
// was built with even though the chain has since moved on, producing
// records at a retired epoch that a per-stream key-epoch floor (spec
// section 8.1 rule 15) cannot catch on a stream a replay has not yet seen
// carry a higher epoch — an open gap (WALD-108) this type does not
// attempt to close, and must not be made easier to hit by holding a
// Signer longer than one process invocation needs it.
//
// A Signer proves only that a record was written by whoever holds the key
// the journal names at the epoch its verified chain reports for it — spec
// section 2.2: journal signing is tamper-evidence of history, not
// protection from a malicious server. A server that holds the signing key
// and wishes to lie can sign its lies; nothing here, or built on top of
// this type, may imply a stronger claim.
type Signer struct {
	priv  ed25519.PrivateKey
	epoch Epoch
	pub   string
}

// NewSigner builds the signing identity a writer uses for one process
// invocation: priv, together with the epoch and public key chain — a
// *SigningChain already verified from genesis, e.g. by
// (*store.Client).ReplayMeta — reports as currently active. It is the only
// place that decides which key signs and at what epoch.
//
// It refuses, each in one line, when:
//   - chain is nil or has not been initialized with a genesis record
//     (ErrGenesisMissing): there is no active key for priv to be checked
//     against yet.
//   - priv is not a valid Ed25519 private key size (ErrInvalidKey):
//     ed25519.Sign panics on a wrong-size key, so this check is
//     load-bearing, not defensive, the same way AppendRefTx's own
//     wrong-size-key pre-check was before this type existed to absorb it.
//   - priv's public half is not the chain's active key (ErrInvalidKey),
//     compared as decoded key bytes rather than formatted strings — the
//     same comparison (*store.Client).adoptGenesis already makes, and for
//     the same reason: ParsePublicKey accepts uppercase hex, so a chain
//     whose active key is spec-non-conformant but parseable must not read
//     as a mismatch against a local key that is byte-for-byte correct.
//
// On success, NewSigner fixes chain.CurrentEpoch() and
// FormatPublicKey(pub) into the returned Signer once, here. Nothing about
// the Signer changes afterward even if the *SigningChain it was built from
// is mutated later by further replay — which is exactly why a Signer must
// not be kept around past the process invocation that built it (see the
// type's own doc comment).
func NewSigner(chain *SigningChain, priv ed25519.PrivateKey) (*Signer, error) {
	if chain == nil || !chain.IsInitialized() {
		return nil, fmt.Errorf("%w: cannot build a signer before genesis", ErrGenesisMissing)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: ed25519 private key must be %d bytes, got %d", ErrInvalidKey, ed25519.PrivateKeySize, len(priv))
	}
	activePub, err := ParsePublicKey(chain.ActiveKey())
	if err != nil {
		return nil, fmt.Errorf("%w: chain's active key %q: %w", ErrInvalidKey, chain.ActiveKey(), err)
	}
	localPub := priv.Public().(ed25519.PublicKey)
	if !localPub.Equal(activePub) {
		return nil, fmt.Errorf("%w: private key's public half does not match the chain's active key %s", ErrInvalidKey, chain.ActiveKey())
	}
	return &Signer{
		priv:  priv,
		epoch: chain.CurrentEpoch(),
		pub:   FormatPublicKey(localPub),
	}, nil
}

// Epoch returns the key epoch this signer stamps on every record it
// signs: the position, in the chain it was built from, that key held at
// the moment NewSigner ran.
func (s *Signer) Epoch() Epoch {
	return s.epoch
}

// PublicKey returns this signer's public key, formatted as
// "ed25519:<64-hex>".
func (s *Signer) PublicKey() string {
	return s.pub
}

// Valid reports whether s has a private key ed25519.Sign can use without
// panicking: non-nil and exactly ed25519.PrivateKeySize bytes. It exists
// because a *Signer can reach this package's callers without having gone
// through NewSigner (see Signer's own doc comment) — Valid is the check a
// caller can run before handing s to SignRefTx, so a misused Signer
// refuses instead of only failing once something tries to sign with it.
//
// Valid does not check s against any *SigningChain — only NewSigner has a
// chain to check against — so it cannot tell a Signer that never matched
// one from a Signer that once did and has since gone stale across a
// rotation. It reports exactly one thing: whether s.priv is a usable
// Ed25519 key.
func (s *Signer) Valid() error {
	if s == nil {
		return fmt.Errorf("%w: signer is nil", ErrInvalidKey)
	}
	if len(s.priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: ed25519 private key must be %d bytes, got %d", ErrInvalidKey, ed25519.PrivateKeySize, len(s.priv))
	}
	return nil
}

// SignRefTx sets r.KeyEpoch to s.Epoch() and signs r with s's private key
// via the package-level SignRefTx. The epoch is set here, immediately
// before signing, and nowhere else: one source of the epoch means a
// record can never carry a key_epoch that disagrees with the key that
// signed it.
//
// SignRefTx calls s.Valid() before touching s.priv. This check is
// load-bearing, not defensive: ed25519.Sign panics, rather than
// returning an error, on a wrong-size key, and a *Signer built without
// going through NewSigner — &Signer{} or new(Signer), constructible from
// any package despite Signer's fields being unexported — reaches this
// method with a nil, wrong-size priv. The guard has to live here, at the
// point that would otherwise panic, because a guard placed only at
// construction does not run for a value that was never constructed
// through it.
func (s *Signer) SignRefTx(r *RefTransactionRecord) error {
	if r == nil {
		return fmt.Errorf("%w: record cannot be nil", ErrInvalidRefTx)
	}
	if err := s.Valid(); err != nil {
		return err
	}
	r.KeyEpoch = s.epoch
	return SignRefTx(s.priv, r)
}
