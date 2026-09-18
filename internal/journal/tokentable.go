// This file implements the token table spec/journal/v1 section 4.5
// describes: the rebuild a replay of _meta folds every token_create and
// token_revoke record into, so that a restore holding nothing but the
// journal ends up with exactly the table a server serving requests from
// disk would have. It is the production type TestFixtureTokenTableReplay
// (fixtures_test.go) exercised only as an inline map and five inline
// t.Errorf strings before this ticket (WALD-33) — that test now drives
// this type instead.
//
// Neither ApplyTokenCreate nor ApplyTokenRevoke verifies a record's
// signature: verification is the walk's job, already performed through
// (*SigningChain).VerifyTokenCreate/VerifyTokenRevoke (section 8.1 rule
// 19, section 4.5 rule 2) before a caller ever reaches this file. A caller
// that applies a record to this table without having verified it first is
// the bug — not something this type can catch, since by the time a record
// reaches here it is indistinguishable from one that was properly
// checked.
package journal

import (
	"fmt"

	"github.com/writtendev/walden/internal/refusal"
)

// TokenRow is one row of the token table: the hash a bearer token is
// looked up by, what it may touch, and whether it still may. Scopes is
// carried verbatim from the token_create record that minted it — section
// 4.3's "scope strings are opaque to the journal" — so this package
// assigns it no meaning and does not parse it; that conversion belongs to
// whoever answers requests with the table (internal/auth), which this
// package must not import.
type TokenRow struct {
	TokenID   string
	TokenHash string
	Scopes    []string
	Revoked   bool
}

// TokenTable is the token table a replay of _meta rebuilds: start empty
// (rule 1), a token_create inserts a live row (rule 4), a token_revoke
// marks the named row revoked (rule 5), and a row is never removed once
// inserted (rule 6) — a revoked row is kept, revoked.
//
// Like *SigningChain, a *TokenTable is one replay's state and is not safe
// for concurrent use. It carries no mutex, on purpose: the walk that
// builds it is serial by construction, the same reason SigningChain's own
// doc comment gives.
type TokenTable struct {
	rows  map[string]*TokenRow
	order []string
}

// NewTokenTable returns an empty token table.
func NewTokenTable() *TokenTable {
	return &TokenTable{rows: make(map[string]*TokenRow)}
}

// ApplyTokenCreate applies an already-verified token_create record to the
// table (section 4.5 rule 4). A record naming a token_id the table
// already holds is a reused identifier, which the format forbids: this
// refuses with RefuseReusedTokenID (section 8.1 rule 10) rather than
// overwrite the existing row.
//
// rec.Scopes is cloned into the new row, not aliased: a caller that
// mutates its own copy of rec.Scopes after this call must not be able to
// reach back into the table through it.
func (t *TokenTable) ApplyTokenCreate(rec *TokenCreateRecord) error {
	if _, exists := t.rows[rec.TokenID]; exists {
		return RefuseReusedTokenID(rec.Seq, rec.TokenID)
	}
	row := &TokenRow{
		TokenID:   rec.TokenID,
		TokenHash: rec.TokenHash,
		Scopes:    append([]string(nil), rec.Scopes...),
	}
	t.rows[rec.TokenID] = row
	t.order = append(t.order, rec.TokenID)
	return nil
}

// ApplyTokenRevoke applies an already-verified token_revoke record to the
// table (section 4.5 rule 5). A record naming a token_id the table does
// not hold does not chain to a creation and is refused with
// RefuseUnknownTokenRevoked (rule 11); one whose token_hash disagrees
// with the hash the create recorded is refused with
// RefuseTokenHashDisagreement (rule 12) rather than applied — a
// revocation that has drifted from the record it revokes must be visible,
// not silently accepted.
//
// A row already revoked, revoked again, is applied idempotently: neither
// section 4.5 rule 5 nor section 8.1 rules 10-12 give a line for that
// case, and inventing a refusal here would refuse a journal the spec
// accepts. The write side (internal/store/tokens.go) is where a caller
// asking to revoke an already-revoked token is refused instead, the same
// place auth.ErrTokenAlreadyRevoked already lives.
func (t *TokenTable) ApplyTokenRevoke(rec *TokenRevokeRecord) error {
	row, exists := t.rows[rec.TokenID]
	if !exists {
		return RefuseUnknownTokenRevoked(rec.Seq, rec.TokenID)
	}
	if row.TokenHash != rec.TokenHash {
		return RefuseTokenHashDisagreement(rec.Seq, rec.TokenID)
	}
	row.Revoked = true
	return nil
}

// Row returns a copy of the row named tokenID, and whether it exists.
func (t *TokenTable) Row(tokenID string) (*TokenRow, bool) {
	row, ok := t.rows[tokenID]
	if !ok {
		return nil, false
	}
	cp := *row
	cp.Scopes = append([]string(nil), row.Scopes...)
	return &cp, true
}

// Rows returns every row in the table, in the order their token_create
// records were applied.
func (t *TokenTable) Rows() []*TokenRow {
	out := make([]*TokenRow, 0, len(t.order))
	for _, id := range t.order {
		row := t.rows[id]
		cp := *row
		cp.Scopes = append([]string(nil), row.Scopes...)
		out = append(out, &cp)
	}
	return out
}

// RefuseReusedTokenID returns the one-line refusal spec section 8.1 rule
// 10 prescribes: a token_create at seq names a token_id the rebuilt table
// already holds.
func RefuseReusedTokenID(seq Seq, tokenID string) error {
	return refusal.Refuse(
		"refusal: replay failed",
		fmt.Sprintf("token create at seq %d reuses token id %s", seq, tokenID),
		"",
	)
}

// RefuseUnknownTokenRevoked returns the one-line refusal spec section 8.1
// rule 11 prescribes: a token_revoke at seq names a token_id the rebuilt
// table does not hold, so the revocation does not chain to a creation.
func RefuseUnknownTokenRevoked(seq Seq, tokenID string) error {
	return refusal.Refuse(
		"refusal: replay failed",
		fmt.Sprintf("token revoke at seq %d names unknown token %s", seq, tokenID),
		"",
	)
}

// RefuseTokenHashDisagreement returns the one-line refusal spec section
// 8.1 rule 12 prescribes: a token_revoke at seq carries a token_hash that
// is not the one recorded for that token_id.
func RefuseTokenHashDisagreement(seq Seq, tokenID string) error {
	return refusal.Refuse(
		"refusal: replay failed",
		fmt.Sprintf("token revoke at seq %d disagrees with the hash recorded for token %s", seq, tokenID),
		"",
	)
}

// RefuseInvalidTokenRecord returns the one-line refusal spec section 8.1
// rule 13 prescribes: a token_create or token_revoke at seq violates a
// field rule of section 4.3 or 4.4 and is refused before it is applied to
// the token table (section 4.5 rule 3). reason names the field rule that
// failed.
func RefuseInvalidTokenRecord(seq Seq, reason string) error {
	return refusal.Refuse(
		"refusal: replay failed",
		fmt.Sprintf("invalid token record at seq %d (%s)", seq, reason),
		"",
	)
}
