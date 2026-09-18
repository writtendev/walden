package journal_test

import (
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/journal"
)

// TestTokenTableStartsEmpty covers spec section 4.5 rule 1: a table with nothing applied to
// it holds no rows.
func TestTokenTableStartsEmpty(t *testing.T) {
	table := journal.NewTokenTable()
	if got := table.Rows(); len(got) != 0 {
		t.Errorf("NewTokenTable().Rows() = %v, want empty", got)
	}
	if _, ok := table.Row("tok_admin_01"); ok {
		t.Error("Row found a row in a freshly constructed table")
	}
}

// TestTokenTableApplyCreate covers rule 4: a token_create inserts a live row.
func TestTokenTableApplyCreate(t *testing.T) {
	table := journal.NewTokenTable()
	rec := validTokenCreate()
	rec.Scopes = []string{"rw:blog-*", "r:docs"}
	if err := table.ApplyTokenCreate(rec); err != nil {
		t.Fatalf("ApplyTokenCreate failed: %v", err)
	}

	row, ok := table.Row(rec.TokenID)
	if !ok {
		t.Fatal("Row did not find the token just created")
	}
	if row.TokenID != rec.TokenID {
		t.Errorf("TokenID = %q, want %q", row.TokenID, rec.TokenID)
	}
	if row.TokenHash != rec.TokenHash {
		t.Errorf("TokenHash = %q, want %q", row.TokenHash, rec.TokenHash)
	}
	if row.Revoked {
		t.Error("a freshly created row came back revoked")
	}
	if got, want := strings.Join(row.Scopes, ","), strings.Join(rec.Scopes, ","); got != want {
		t.Errorf("Scopes = %q, want %q", got, want)
	}

	// The row Row returns is a copy: mutating it must not reach the table.
	row.Scopes[0] = "rwc:*"
	row2, _ := table.Row(rec.TokenID)
	if row2.Scopes[0] == "rwc:*" {
		t.Error("Row returned a row aliasing the table's own scopes slice")
	}
}

// TestTokenTableApplyCreateClonesScopes covers the same aliasing hazard on the write side:
// mutating the caller's slice after ApplyTokenCreate must not reach the table.
func TestTokenTableApplyCreateClonesScopes(t *testing.T) {
	table := journal.NewTokenTable()
	rec := validTokenCreate()
	scopes := []string{"rwc:*"}
	rec.Scopes = scopes
	if err := table.ApplyTokenCreate(rec); err != nil {
		t.Fatalf("ApplyTokenCreate failed: %v", err)
	}
	scopes[0] = "r:docs"

	row, _ := table.Row(rec.TokenID)
	if row.Scopes[0] != "rwc:*" {
		t.Errorf("ApplyTokenCreate aliased the caller's scopes slice: row.Scopes[0] = %q, want %q", row.Scopes[0], "rwc:*")
	}
}

// TestTokenTableReusedTokenIDRefused covers spec section 8.1 rule 10, byte for byte: a
// token_create naming a token_id the table already holds is refused rather than
// overwriting the row.
func TestTokenTableReusedTokenIDRefused(t *testing.T) {
	table := journal.NewTokenTable()
	first := validTokenCreate()
	if err := table.ApplyTokenCreate(first); err != nil {
		t.Fatalf("first ApplyTokenCreate failed: %v", err)
	}

	second := validTokenCreate()
	second.Seq = 7
	second.TokenHash = "sha256:5453e0186b8b6f1d4852424e8ae33ecf685ce338a44862fc8db2acddc7b40d2a"
	err := table.ApplyTokenCreate(second)
	if err == nil {
		t.Fatal("ApplyTokenCreate accepted a reused token id")
	}
	wantLine := "refusal: replay failed: token create at seq 7 reuses token id " + second.TokenID
	if err.Error() != wantLine {
		t.Errorf("error = %q, want %q", err.Error(), wantLine)
	}
	assertOneLine(t, err)

	// The original row must be untouched: the refused create did not overwrite it.
	row, ok := table.Row(first.TokenID)
	if !ok {
		t.Fatal("the original row is gone after the refused create")
	}
	if row.TokenHash != first.TokenHash {
		t.Errorf("TokenHash = %q, want the original %q (the refused create must not overwrite it)", row.TokenHash, first.TokenHash)
	}
}

// TestTokenTableUnknownTokenRevokedRefused covers rule 11: a token_revoke naming a
// token_id the table does not hold does not chain to a creation.
func TestTokenTableUnknownTokenRevokedRefused(t *testing.T) {
	table := journal.NewTokenTable()
	rec := validTokenRevoke()
	err := table.ApplyTokenRevoke(rec)
	if err == nil {
		t.Fatal("ApplyTokenRevoke accepted a revocation naming an unknown token")
	}
	wantLine := "refusal: replay failed: token revoke at seq 3 names unknown token " + rec.TokenID
	if err.Error() != wantLine {
		t.Errorf("error = %q, want %q", err.Error(), wantLine)
	}
	assertOneLine(t, err)
}

// TestTokenTableHashDisagreementRefused covers rule 12: a token_revoke whose token_hash
// disagrees with the one the create recorded is refused rather than applied.
func TestTokenTableHashDisagreementRefused(t *testing.T) {
	table := journal.NewTokenTable()
	create := validTokenCreate()
	if err := table.ApplyTokenCreate(create); err != nil {
		t.Fatalf("ApplyTokenCreate failed: %v", err)
	}

	revoke := validTokenRevoke()
	revoke.TokenHash = "sha256:5453e0186b8b6f1d4852424e8ae33ecf685ce338a44862fc8db2acddc7b40d2a"
	err := table.ApplyTokenRevoke(revoke)
	if err == nil {
		t.Fatal("ApplyTokenRevoke accepted a token_hash that disagrees with the recorded row")
	}
	wantLine := "refusal: replay failed: token revoke at seq 3 disagrees with the hash recorded for token " + revoke.TokenID
	if err.Error() != wantLine {
		t.Errorf("error = %q, want %q", err.Error(), wantLine)
	}
	assertOneLine(t, err)

	// The row must still be live: the refused revoke did not apply.
	row, _ := table.Row(create.TokenID)
	if row.Revoked {
		t.Error("a refused revoke still marked the row revoked")
	}
}

// TestTokenTableRefuseInvalidTokenRecord covers rule 13's exact published line. This
// refusal is emitted by the store-side walk (internal/store/meta.go) on a parse failure,
// not by TokenTable.Apply* itself — RefuseInvalidTokenRecord is pinned here directly since
// this is the file that owns it (WALD-33).
func TestTokenTableRefuseInvalidTokenRecord(t *testing.T) {
	err := journal.RefuseInvalidTokenRecord(5, "missing required field \"signature\"")
	wantLine := `refusal: replay failed: invalid token record at seq 5 (missing required field "signature")`
	if err.Error() != wantLine {
		t.Errorf("error = %q, want %q", err.Error(), wantLine)
	}
	assertOneLine(t, err)
}

// TestTokenTableRevokedRowIsKept covers rule 6: a revoked row is kept, not removed, and
// TestTokenTableDoubleRevokeIsIdempotent covers the case section 4.5 rule 5 and section 8.1
// rules 10-12 give no line for: a row already revoked, revoked again, applies without
// refusing.
func TestTokenTableRevokedRowIsKept(t *testing.T) {
	table := journal.NewTokenTable()
	create := validTokenCreate()
	if err := table.ApplyTokenCreate(create); err != nil {
		t.Fatalf("ApplyTokenCreate failed: %v", err)
	}
	revoke := validTokenRevoke()
	if err := table.ApplyTokenRevoke(revoke); err != nil {
		t.Fatalf("ApplyTokenRevoke failed: %v", err)
	}

	row, ok := table.Row(create.TokenID)
	if !ok {
		t.Fatal("the row is gone after being revoked; rule 6 requires it be kept")
	}
	if !row.Revoked {
		t.Error("the row is not marked revoked")
	}
	if row.TokenHash != create.TokenHash {
		t.Errorf("TokenHash after revoke = %q, want the original %q", row.TokenHash, create.TokenHash)
	}

	if got := table.Rows(); len(got) != 1 {
		t.Errorf("Rows() = %d entries, want 1 (the row is kept, not removed)", len(got))
	}
}

func TestTokenTableDoubleRevokeIsIdempotent(t *testing.T) {
	table := journal.NewTokenTable()
	create := validTokenCreate()
	if err := table.ApplyTokenCreate(create); err != nil {
		t.Fatalf("ApplyTokenCreate failed: %v", err)
	}
	revoke := validTokenRevoke()
	if err := table.ApplyTokenRevoke(revoke); err != nil {
		t.Fatalf("first ApplyTokenRevoke failed: %v", err)
	}

	second := validTokenRevoke()
	second.Seq = 9
	if err := table.ApplyTokenRevoke(second); err != nil {
		t.Errorf("second ApplyTokenRevoke on an already-revoked row refused: %v, want nil (idempotent)", err)
	}

	row, _ := table.Row(create.TokenID)
	if !row.Revoked {
		t.Error("row is not revoked after two revokes")
	}
}

// TestTokenTableRowsOrder covers Rows()'s ordering promise: token_create application order,
// not map iteration order.
func TestTokenTableRowsOrder(t *testing.T) {
	table := journal.NewTokenTable()
	first := validTokenCreate()
	first.TokenID = "tok_a"
	second := validTokenCreate()
	second.TokenID = "tok_b"
	second.Seq = 5
	third := validTokenCreate()
	third.TokenID = "tok_c"
	third.Seq = 6

	for _, rec := range []*journal.TokenCreateRecord{first, second, third} {
		if err := table.ApplyTokenCreate(rec); err != nil {
			t.Fatalf("ApplyTokenCreate(%s) failed: %v", rec.TokenID, err)
		}
	}

	rows := table.Rows()
	if len(rows) != 3 {
		t.Fatalf("Rows() = %d entries, want 3", len(rows))
	}
	wantOrder := []string{"tok_a", "tok_b", "tok_c"}
	for i, want := range wantOrder {
		if rows[i].TokenID != want {
			t.Errorf("Rows()[%d].TokenID = %q, want %q", i, rows[i].TokenID, want)
		}
	}
}

// assertOneLine fails t if err's message contains a newline — every refusal in this
// package promises PHILOSOPHY.md's "printable in one line".
func assertOneLine(t *testing.T, err error) {
	t.Helper()
	if strings.Count(err.Error(), "\n") != 0 {
		t.Errorf("refusal is not one line: %q", err.Error())
	}
}
