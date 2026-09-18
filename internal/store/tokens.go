// This file adds walden's write path for token_create and token_revoke
// records (WALD-33, spec/journal/v1 section 4.3): the _meta writer that
// makes ARCHITECTURE.md's "journaled to the meta stream, so restore
// restores your tokens too" true, plus ReplayMetaTable, the thin exported
// accessor for the token table (*journal.TokenTable) meta.go's replayMeta
// now rebuilds as part of every _meta walk.
//
// AppendTokenCreate and AppendTokenRevoke are callers of
// (*journal.Lease).Append (lease.go, WALD-29), not a second
// implementation of it — the same relationship (*Client).AppendRefTx
// (reftx.go, WALD-27) has to that method, and the shape both of these
// functions are modelled on. (*Client).RotateKey (rotation.go, WALD-31)
// is the other model, for the sequence-drift check both functions here
// share with it: a _meta writer built on a *journal.SigningChain replayed
// earlier, appending through a *journal.Lease opened independently, has
// to prove those two views of _meta still agree before it trusts either
// one to sign at the sequence the lease offers.
package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
)

// ReplayMetaTable replays _meta exactly as ReplayMeta (meta.go) does, and
// also returns the token table (*journal.TokenTable) the same walk
// rebuilds — the table ReplayMeta's own thinner signature discards.
// Callers that need both the signing chain and the token table (the
// token CLI's create/revoke path, cmd/walden/token.go) use this instead
// of ReplayMeta; RotateKey and EnsureGenesis, which need only the chain,
// keep using ReplayMeta unchanged.
func (c *Client) ReplayMetaTable(ctx context.Context) (*journal.SigningChain, *journal.TokenTable, error) {
	return c.replayMeta(ctx)
}

// AppendTokenCreate builds a TokenCreateRecord at the sequence lease
// hands out, signs it with priv, marshals it, and conditionally writes it
// to "v1/streams/_meta/tx/<seq>.json", returning the sequence it landed
// at.
//
// chain is the *journal.SigningChain a caller's own ReplayMetaTable (or
// ReplayMeta) call already produced — this function does not replay
// _meta itself, the same division AppendRefTx draws between building a
// record and discovering a stream's head. chain is used for two things:
// chain.ActiveKey(), to confirm priv is actually the key allowed to sign
// at _meta's current position (see the signing-key check below), and
// chain.LastMetaSeq(), to confirm the sequence lease.Append hands the
// closure below is the very next one after the sequence chain was
// verified through (see the sequence-drift check below, RotateKey's own
// refuseMetaSequenceDrift reasoning applied to a token record).
//
// Checks run before lease.Append is ever called, each a one-line refusal
// with zero network calls, in the order a caller's mistake is cheapest to
// catch — mirroring AppendRefTx's own five, extended for chain and
// scopes:
//
//  1. A nil lease. Checked first because every other pre-check below
//     names it as "token create" or "token revoke" without needing
//     lease.Stream() — but the stream check itself (4) does, so a nil
//     lease has to be ruled out before that call could panic.
//  2. A nil ctx. Load-bearing, not defensive, exactly as it is in
//     AppendRefTx: ctx is handed to PutIfAbsent inside the closure, and
//     store.(*Client).do's first statement calls ctx.Err() — a method
//     call on a nil interface value panics exactly where this guards
//     against it — and ctx cannot be hoisted out of the closure, because
//     PutIfAbsent needs it at the point of the write.
//  3. A private key of the wrong size. Load-bearing: ed25519.Sign panics
//     on a wrong-size key, inside SignTokenCreate, inside the closure.
//  4. A nil now.
//  5. A nil or uninitialized chain. Load-bearing: the closure below calls
//     chain.LastMetaSeq(), and (*journal.SigningChain).LastMetaSeq is a
//     method on a pointer receiver — a nil chain panics there, inside the
//     closure, exactly the class of bug this file exists to keep out of
//     lease.Append's callback.
//  6. lease.Stream() naming anything but the meta stream. Token records
//     only ever go on _meta (spec section 9.1) — the inverse of
//     AppendRefTx's own check, which refuses _meta for a ref
//     transaction.
//  7. journal.ValidateTokenID(tokenID).
//  8. journal.ValidateTokenHash(tokenHash).
//  9. The full scopes check: non-empty, no empty entry, no duplicate,
//     journal.ValidateTokenScope on each, utf8.ValidString on each — the
//     same rules TokenCreateRecord.Validate itself enforces (spec section
//     4.3), checked here so that SignTokenCreate's own Validate call
//     inside the closure can only ever fail on the one field it cannot
//     check ahead of time: seq, which the closure only learns from
//     lease.Append.
//
// The signing key must be the chain's active key. A token record carries
// no key_epoch of its own (unlike a ref transaction or a marker) and is
// verified against the key active at its own meta sequence (spec section
// 4.3's payload note, section 8.1 rule 19) — so signing with any key but
// chain.ActiveKey() would land a record no future replay could ever
// accept, which is unrecoverable once it is in the bucket. Compared as
// decoded bytes (ed25519.PublicKey.Equal), not formatted strings: the
// same round-2 finding RotateKey (rotation.go) already encodes and
// adoptGenesis (genesis.go) is pinned on, so a chain whose active key is
// spec-non-conformant but parseable hex (uppercase, which ParsePublicKey
// accepts) is still compared correctly rather than reformatted to
// lowercase and silently passed.
//
// now().UTC().Format(time.RFC3339) is computed once, above lease.Append,
// exactly as AppendRefTx and RotateKey compute their own timestamp: a
// caller-supplied clock that panics when invoked now panics here, in this
// function's own frame, before lease.Append — and therefore its panic
// recovery and permanent fencing — ever runs. scopes is cloned above the
// closure for the same reason: a caller mutating its own slice between
// this call and the closure's eventual Sign/Marshal must not be able to
// produce a record whose signature covers different bytes than its JSON.
//
// Inside the closure: the sequence-drift check, then build, sign,
// marshal, and one conditional PUT. Beyond that this function classifies
// nothing — a Sign, Marshal, or PutIfAbsent failure is passed back to
// lease.Append unchanged, exactly as AppendRefTx's own closure does.
// lease.Append is the only place a proven 412 is sorted from an
// unprovable outcome from every other failure (spec section 11.4); this
// file does not touch a Fencer, does not GET or LIST, and does not call
// PutIfAbsent twice.
//
// This is narrower than "no panic path left" inside the closure, not that
// claim restated a third time: it is what an audit of this closure's own
// call chain supports today, the same qualification AppendRefTx's doc
// comment gives its own closure.
func (c *Client) AppendTokenCreate(
	ctx context.Context,
	lease *journal.Lease,
	priv ed25519.PrivateKey,
	chain *journal.SigningChain,
	tokenID, tokenHash string,
	scopes []string,
	now func() time.Time,
) (journal.Seq, error) {
	if lease == nil {
		return 0, refuseAppendToken("token create", fmt.Errorf("lease must not be nil"))
	}
	if ctx == nil {
		return 0, refuseAppendToken("token create", fmt.Errorf("ctx must not be nil"))
	}
	if len(priv) != ed25519.PrivateKeySize {
		return 0, refuseAppendToken("token create", fmt.Errorf("ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv)))
	}
	if now == nil {
		return 0, refuseAppendToken("token create", fmt.Errorf("now must not be nil"))
	}
	if chain == nil || !chain.IsInitialized() {
		return 0, refuseAppendToken("token create", fmt.Errorf("chain must be a replayed, initialized signing chain"))
	}
	if lease.Stream() != journal.MetaStreamID {
		return 0, refuseAppendToken("token create", fmt.Errorf("token records can only be appended to meta stream %q, got %q", journal.MetaStreamID, lease.Stream()))
	}
	if err := journal.ValidateTokenID(tokenID); err != nil {
		return 0, refuseAppendToken("token create", err)
	}
	if err := journal.ValidateTokenHash(tokenHash); err != nil {
		return 0, refuseAppendToken("token create", err)
	}
	if err := validateTokenCreateScopes(scopes); err != nil {
		return 0, refuseAppendToken("token create", err)
	}
	if err := requireActiveSigningKey("token create", priv, chain); err != nil {
		return 0, err
	}

	// See the doc comment above: hoisted so a panicking clock panics here,
	// to this call's own caller, rather than through lease.Append's panic
	// recovery and permanent fencing. scopesCopy is likewise hoisted so
	// nothing the closure signs and marshals can be mutated out from under
	// it between the two.
	ts := now().UTC().Format(time.RFC3339)
	scopesCopy := append([]string(nil), scopes...)

	var seq journal.Seq
	err := lease.Append(func(s journal.Seq) error {
		if want := chain.LastMetaSeq() + 1; s != want {
			return refuseTokenSequenceDrift("token create", chain.LastMetaSeq(), s)
		}
		seq = s
		rec := journal.NewTokenCreateRecord(s, tokenID, tokenHash, scopesCopy, ts)
		if err := journal.SignTokenCreate(priv, rec); err != nil {
			return err
		}
		data, err := journal.MarshalTokenCreate(rec)
		if err != nil {
			return err
		}
		return c.PutIfAbsent(ctx, journal.TxKey(journal.MetaStreamID, s), bytes.NewReader(data), int64(len(data)))
	})
	if err != nil {
		return 0, err
	}
	return seq, nil
}

// AppendTokenRevoke builds a TokenRevokeRecord at the sequence lease
// hands out, signs it with priv, marshals it, and conditionally writes it
// to _meta, returning the sequence it landed at. See AppendTokenCreate's
// doc comment for the full reasoning behind every check and the hoisting
// below — this function shares all of it except the scopes check, which
// a revocation has nothing to carry (spec section 4.4: "a revocation
// withdraws a grant, it does not describe one").
func (c *Client) AppendTokenRevoke(
	ctx context.Context,
	lease *journal.Lease,
	priv ed25519.PrivateKey,
	chain *journal.SigningChain,
	tokenID, tokenHash string,
	now func() time.Time,
) (journal.Seq, error) {
	if lease == nil {
		return 0, refuseAppendToken("token revoke", fmt.Errorf("lease must not be nil"))
	}
	if ctx == nil {
		return 0, refuseAppendToken("token revoke", fmt.Errorf("ctx must not be nil"))
	}
	if len(priv) != ed25519.PrivateKeySize {
		return 0, refuseAppendToken("token revoke", fmt.Errorf("ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv)))
	}
	if now == nil {
		return 0, refuseAppendToken("token revoke", fmt.Errorf("now must not be nil"))
	}
	if chain == nil || !chain.IsInitialized() {
		return 0, refuseAppendToken("token revoke", fmt.Errorf("chain must be a replayed, initialized signing chain"))
	}
	if lease.Stream() != journal.MetaStreamID {
		return 0, refuseAppendToken("token revoke", fmt.Errorf("token records can only be appended to meta stream %q, got %q", journal.MetaStreamID, lease.Stream()))
	}
	if err := journal.ValidateTokenID(tokenID); err != nil {
		return 0, refuseAppendToken("token revoke", err)
	}
	if err := journal.ValidateTokenHash(tokenHash); err != nil {
		return 0, refuseAppendToken("token revoke", err)
	}
	if err := requireActiveSigningKey("token revoke", priv, chain); err != nil {
		return 0, err
	}

	ts := now().UTC().Format(time.RFC3339)

	var seq journal.Seq
	err := lease.Append(func(s journal.Seq) error {
		if want := chain.LastMetaSeq() + 1; s != want {
			return refuseTokenSequenceDrift("token revoke", chain.LastMetaSeq(), s)
		}
		seq = s
		rec := journal.NewTokenRevokeRecord(s, tokenID, tokenHash, ts)
		if err := journal.SignTokenRevoke(priv, rec); err != nil {
			return err
		}
		data, err := journal.MarshalTokenRevoke(rec)
		if err != nil {
			return err
		}
		return c.PutIfAbsent(ctx, journal.TxKey(journal.MetaStreamID, s), bytes.NewReader(data), int64(len(data)))
	})
	if err != nil {
		return 0, err
	}
	return seq, nil
}

// validateTokenCreateScopes runs the same field rules
// TokenCreateRecord.Validate enforces on scopes (spec section 4.3): at
// least one entry, no entry empty, none repeated, none carrying a
// control character or invalid UTF-8. Checked here, ahead of
// lease.Append, so that SignTokenCreate's own Validate call inside the
// closure can only ever fail on seq — the one field this function cannot
// check before lease.Append hands it out.
//
// The UTF-8 half of this duplicates MarshalTokenCreate's own guard
// (journal/token.go). That is deliberate, not a copy that drifted: this
// function runs before the record even exists, entirely to keep
// SignTokenCreate's Validate call inside the closure free of anything but
// the seq-dependent header, while MarshalTokenCreate's guard runs after,
// against whatever scopes the record actually ended up carrying — a
// defense a caller who reaches Marshal some other way still gets.
func validateTokenCreateScopes(scopes []string) error {
	if len(scopes) == 0 {
		return fmt.Errorf("%w: scopes must carry at least one scope", journal.ErrInvalidTokenRecord)
	}
	seen := make(map[string]bool, len(scopes))
	for i, scope := range scopes {
		if scope == "" {
			return fmt.Errorf("%w: scopes[%d] cannot be empty", journal.ErrInvalidTokenRecord, i)
		}
		if err := journal.ValidateTokenScope(scope); err != nil {
			return fmt.Errorf("%w: scopes[%d]: %w", journal.ErrInvalidTokenRecord, i, err)
		}
		if !utf8.ValidString(scope) {
			return fmt.Errorf("%w: scopes[%d] is not valid UTF-8: %q", journal.ErrInvalidTokenRecord, i, scope)
		}
		if seen[scope] {
			return fmt.Errorf("%w: duplicate scope %q", journal.ErrInvalidTokenRecord, scope)
		}
		seen[scope] = true
	}
	return nil
}

// requireActiveSigningKey refuses unless priv's public half is exactly
// chain's currently active signing key, compared as decoded key bytes
// (ed25519.PublicKey.Equal) rather than formatted strings — see
// AppendTokenCreate's doc comment for why. op names the caller
// ("token create" or "token revoke") for the refusal's "what".
func requireActiveSigningKey(op string, priv ed25519.PrivateKey, chain *journal.SigningChain) error {
	localPub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return refuseAppendToken(op, fmt.Errorf("signing key's public half is not an ed25519 public key"))
	}
	activeKey := chain.ActiveKey()
	parsedActive, err := journal.ParsePublicKey(activeKey)
	if err != nil {
		return refuseAppendToken(op, fmt.Errorf("chain's active key %q does not parse: %w", activeKey, err))
	}
	if !localPub.Equal(parsedActive) {
		return refusal.Refuse(
			op+" refused",
			fmt.Sprintf("the signing key provided is %s, but the journal's active signing key is %s", journal.FormatPublicKey(localPub), activeKey),
			"sign with the journal's active signing key, or replay _meta again if a rotation has landed since this key was loaded",
		)
	}
	return nil
}

// refuseAppendToken wraps cause — an input validation failure caught
// before any network call — in walden's one-line operator-facing refusal
// shape, styled on internal/store/reftx.go's refuseAppendRefTx for the
// same kind of pre-check. op names the operation ("token create" or
// "token revoke") the way refuseMetaSequenceDrift (rotation.go) names
// "rotate-key".
func refuseAppendToken(op string, cause error) error {
	return refusal.RefuseWithCause(op+" refused", cause.Error(), "", cause)
}

// refuseTokenSequenceDrift returns a one-line refusal when the sequence
// (*journal.Lease).Append hands this file's closure does not immediately
// follow the sequence chain (the caller's own ReplayMetaTable/ReplayMeta
// result) was verified through: a concurrent _meta writer landed a record
// after that replay, or the two diverge for some other reason. This is
// RotateKey's own refuseMetaSequenceDrift (rotation.go) reasoning applied
// to a token record: chain was verified as of chain.LastMetaSeq(), seq
// comes from the lease's independent LIST-derived head, and signing at a
// sequence chain was not verified against risks a record verified against
// the wrong active key. A plain error, deliberately: Lease.Append's own
// contract (lease.go) is that any error but ErrPreconditionFailed or
// ErrOutcomeUnknown leaves the stream unfenced and the sequence
// unconsumed, and that is the right outcome here — the caller's cached
// chain is stale, not _meta itself, and replaying again gets a fresh,
// consistent chain to append from. Retrying inside the closure by
// re-reading the head is not an option spec section 11.4 item 4 allows.
func refuseTokenSequenceDrift(op string, chainLastSeq, leaseSeq journal.Seq) error {
	return refusal.Refuse(
		op+" refused",
		fmt.Sprintf("this %s's replay verified _meta through seq %d, but the append sequence offered is %d", op, chainLastSeq, leaseSeq),
		fmt.Sprintf("retry the %s: _meta changed since this replay, so a fresh run will append from the current state", op),
	)
}
