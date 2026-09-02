package auth_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/journal"
)

func fixturesPath(filename string) string {
	return filepath.Join("..", "..", "spec", "auth", "v1", "fixtures", filename)
}

func TestIdentifiersFixture(t *testing.T) {
	data, err := os.ReadFile(fixturesPath("identifiers.json"))
	if err != nil {
		t.Fatalf("failed to read identifiers.json: %v", err)
	}

	var fixture struct {
		Version string `json:"version"`
		Cases   []struct {
			Identifier  string `json:"identifier"`
			Valid       bool   `json:"valid"`
			Violation   string `json:"violation"`
			Description string `json:"description"`
		} `json:"cases"`
	}

	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("failed to unmarshal identifiers fixture: %v", err)
	}

	for _, tc := range fixture.Cases {
		err := auth.ValidateRepo(tc.Identifier)
		if tc.Valid {
			if err != nil {
				t.Errorf("fixture %q (%s): expected valid, got error: %v", tc.Identifier, tc.Description, err)
			}
		} else {
			if err == nil {
				t.Errorf("fixture %q (%s): expected invalid (%s), got nil error", tc.Identifier, tc.Description, tc.Violation)
			} else {
				if !errors.Is(err, auth.ErrInvalidRepo) {
					t.Errorf("fixture %q: expected ErrInvalidRepo, got %v", tc.Identifier, err)
				}
				if strings.Contains(err.Error(), "\n") {
					t.Errorf("fixture %q: refusal contains newline: %q", tc.Identifier, err.Error())
				}
			}
		}
	}
}

func TestScopesFixture(t *testing.T) {
	data, err := os.ReadFile(fixturesPath("scopes.json"))
	if err != nil {
		t.Fatalf("failed to read scopes.json: %v", err)
	}

	var fixture struct {
		Version      string `json:"version"`
		ScopeParsing []struct {
			Scope            string   `json:"scope"`
			Valid            bool     `json:"valid"`
			Actions          []string `json:"actions"`
			CanonicalActions string   `json:"canonical_actions"`
			Pattern          string   `json:"pattern"`
			Description      string   `json:"description"`
		} `json:"scope_parsing"`
		Evaluations []struct {
			Scopes      []string `json:"scopes"`
			Repo        string   `json:"repo"`
			Action      string   `json:"action"`
			Allowed     bool     `json:"allowed"`
			Description string   `json:"description"`
		} `json:"evaluations"`
	}

	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("failed to unmarshal scopes fixture: %v", err)
	}

	for _, tc := range fixture.ScopeParsing {
		parsed, err := auth.ParseScope(tc.Scope)
		if tc.Valid {
			if err != nil {
				t.Errorf("scope parsing %q (%s): expected valid, got: %v", tc.Scope, tc.Description, err)
				continue
			}
			if parsed.Pattern != tc.Pattern {
				t.Errorf("scope %q pattern = %q, want %q", tc.Scope, parsed.Pattern, tc.Pattern)
			}
			if parsed.Actions.String() != tc.CanonicalActions {
				t.Errorf("scope %q canonical actions = %q, want %q", tc.Scope, parsed.Actions.String(), tc.CanonicalActions)
			}
		} else {
			if err == nil {
				t.Errorf("scope parsing %q (%s): expected error, got nil", tc.Scope, tc.Description)
			}
		}
	}

	for _, tc := range fixture.Evaluations {
		scopes, err := auth.ParseScopes(tc.Scopes)
		if err != nil {
			t.Fatalf("failed to parse evaluation scopes %v: %v", tc.Scopes, err)
		}
		got := auth.Allows(scopes, auth.Action(tc.Action), tc.Repo)
		if got != tc.Allowed {
			t.Errorf("evaluation %v on repo %q action %q (%s): got %v, want %v", tc.Scopes, tc.Repo, tc.Action, tc.Description, got, tc.Allowed)
		}
	}
}

func TestBuiltinTokensFixture(t *testing.T) {
	data, err := os.ReadFile(fixturesPath("builtin_tokens.json"))
	if err != nil {
		t.Fatalf("failed to read builtin_tokens.json: %v", err)
	}

	var fixture struct {
		Version string `json:"version"`
		Tokens  []struct {
			TokenID   string   `json:"token_id"`
			RawToken  string   `json:"raw_token"`
			TokenHash string   `json:"token_hash"`
			Scopes    []string `json:"scopes"`
			Revoked   bool     `json:"revoked"`
		} `json:"tokens"`
	}

	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("failed to unmarshal builtin tokens fixture: %v", err)
	}

	ctx := context.Background()
	store := auth.NewMemoryTokenStore()
	authorizer := auth.NewBuiltinAuthorizer(store)

	for _, tok := range fixture.Tokens {
		computedHash := auth.HashToken(tok.RawToken)
		if computedHash != tok.TokenHash {
			t.Errorf("token %s hash mismatch: computed %q, want %q", tok.TokenID, computedHash, tok.TokenHash)
		}

		scopes, err := auth.ParseScopes(tok.Scopes)
		if err != nil {
			t.Fatalf("failed to parse scopes for token %s: %v", tok.TokenID, err)
		}

		store.SaveToken(ctx, &auth.TokenRecord{
			TokenID:   tok.TokenID,
			TokenHash: tok.TokenHash,
			Scopes:    scopes,
			Revoked:   tok.Revoked,
		})
	}

	// Test admin token permissions
	ok, err := authorizer.Authorize(ctx, "walden_sec_admin_0123456789abcdef", auth.ActionRead, "my-repo")
	if !ok || err != nil {
		t.Errorf("expected admin token read allowed, got ok=%v, err=%v", ok, err)
	}

	// Test revoked token refusal
	ok, err = authorizer.Authorize(ctx, "walden_sec_revoked_0123456789abcdef", auth.ActionRead, "my-repo")
	if ok || !errors.Is(err, auth.ErrUnauthorized) {
		t.Errorf("expected unauthorized for revoked token, got ok=%v, err=%v", ok, err)
	}
}

// TestBuiltinTokensJournalRoundTrip holds the journal's token records to the tokens this
// specification publishes: every token in builtin_tokens.json is minted into a
// journal.TokenCreateRecord, put through the encoding it is published in, and read back into
// the store the server actually serves from. It is the same trip a restore makes — mint,
// journal, replay — and it is asked of the published tokens rather than of one convenient
// example, so a record shape that cannot carry tok_writer_02's two scopes fails here.
func TestBuiltinTokensJournalRoundTrip(t *testing.T) {
	data, err := os.ReadFile(fixturesPath("builtin_tokens.json"))
	if err != nil {
		t.Fatalf("failed to read builtin_tokens.json: %v", err)
	}
	var fixture struct {
		Tokens []struct {
			TokenID   string   `json:"token_id"`
			RawToken  string   `json:"raw_token"`
			TokenHash string   `json:"token_hash"`
			Scopes    []string `json:"scopes"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("failed to unmarshal builtin tokens fixture: %v", err)
	}
	if len(fixture.Tokens) == 0 {
		t.Fatal("builtin_tokens.json publishes no tokens, so this proves nothing")
	}

	ctx := context.Background()
	store := auth.NewMemoryTokenStore()
	multiScope := 0

	for seq, tok := range fixture.Tokens {
		rec := &journal.TokenCreateRecord{
			Version:   journal.VersionPrefix,
			Stream:    journal.MetaStreamID,
			Seq:       journal.Seq(seq + 1),
			Type:      journal.RecordTypeTokenCreate,
			TokenID:   tok.TokenID,
			TokenHash: auth.HashToken(tok.RawToken),
			Scopes:    tok.Scopes,
			Timestamp: "2026-08-31T00:01:00Z",
		}
		if err := rec.Validate(); err != nil {
			t.Fatalf("token %s does not make a valid journal record: %v", tok.TokenID, err)
		}

		encoded, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("failed to encode the journal record for token %s: %v", tok.TokenID, err)
		}
		var replayed journal.TokenCreateRecord
		if err := json.Unmarshal(encoded, &replayed); err != nil {
			t.Fatalf("failed to decode the journal record for token %s: %v", tok.TokenID, err)
		}

		// What a replay holds after reading the record has to be enough to serve from: the
		// hash the request is looked up by, and scopes the authorizer can answer with.
		if replayed.TokenHash != tok.TokenHash {
			t.Errorf("token %s replayed hash %q, want the published %q", tok.TokenID, replayed.TokenHash, tok.TokenHash)
		}
		scopes, err := auth.ParseScopes(replayed.Scopes)
		if err != nil {
			t.Fatalf("scopes replayed for token %s do not parse: %v", tok.TokenID, err)
		}
		if len(scopes) != len(tok.Scopes) {
			t.Errorf("token %s replayed %d scopes, want %d", tok.TokenID, len(scopes), len(tok.Scopes))
		}
		if len(tok.Scopes) > 1 {
			multiScope++
		}
		if err := store.SaveToken(ctx, &auth.TokenRecord{
			TokenID:   replayed.TokenID,
			TokenHash: replayed.TokenHash,
			Scopes:    scopes,
		}); err != nil {
			t.Fatalf("failed to save the replayed token %s: %v", tok.TokenID, err)
		}
	}

	if multiScope == 0 {
		t.Fatal("no published token carries more than one scope, so nothing here exercises the array")
	}

	// tok_writer_02 is the token a single scope field cannot hold. Both of its scopes have to
	// survive the trip, and they are only proven to have survived by being enforced: the
	// second scope grants read on docs, and nothing else the token carries does.
	authorizer := auth.NewBuiltinAuthorizer(store)
	ok, err := authorizer.Authorize(ctx, "walden_sec_writer_0123456789abcdef", auth.ActionRead, "docs")
	if !ok || err != nil {
		t.Errorf("the second scope of tok_writer_02 did not survive the journal: ok=%v, err=%v", ok, err)
	}
	ok, err = authorizer.Authorize(ctx, "walden_sec_writer_0123456789abcdef", auth.ActionWrite, "blog-notes")
	if !ok || err != nil {
		t.Errorf("the first scope of tok_writer_02 did not survive the journal: ok=%v, err=%v", ok, err)
	}
	if ok, _ := authorizer.Authorize(ctx, "walden_sec_writer_0123456789abcdef", auth.ActionWrite, "docs"); ok {
		t.Error("tok_writer_02 came back with write on docs, which neither of its scopes grants")
	}
}

func TestCapabilityTokensFixture(t *testing.T) {
	data, err := os.ReadFile(fixturesPath("capability_tokens.json"))
	if err != nil {
		t.Fatalf("failed to read capability_tokens.json: %v", err)
	}

	var fixture struct {
		Version          string `json:"version"`
		TrustedPublicKey string `json:"trusted_public_key"`
		EvaluationTime   string `json:"evaluation_time"`
		ValidCapability  struct {
			Payload            auth.CapabilityPayload `json:"payload"`
			CanonicalPayload   string                 `json:"canonical_payload"`
			Signature          string                 `json:"signature"`
			SignatureBase64URL string                 `json:"signature_base64url"`
			CompactToken       string                 `json:"compact_token"`
		} `json:"valid_capability"`
		AdminCapability struct {
			Payload            auth.CapabilityPayload `json:"payload"`
			CanonicalPayload   string                 `json:"canonical_payload"`
			Signature          string                 `json:"signature"`
			SignatureBase64URL string                 `json:"signature_base64url"`
			CompactToken       string                 `json:"compact_token"`
		} `json:"admin_capability"`
		ExpiredCapability struct {
			Payload         auth.CapabilityPayload `json:"payload"`
			CompactToken    string                 `json:"compact_token"`
			ExpectedRefusal string                 `json:"expected_refusal"`
		} `json:"expired_capability"`
		FutureCapability struct {
			Payload         auth.CapabilityPayload `json:"payload"`
			CompactToken    string                 `json:"compact_token"`
			ExpectedRefusal string                 `json:"expected_refusal"`
		} `json:"future_capability"`
		TamperedCapability struct {
			CompactToken    string `json:"compact_token"`
			ExpectedRefusal string `json:"expected_refusal"`
		} `json:"tampered_capability"`
		WrongKeyCapability struct {
			CompactToken    string `json:"compact_token"`
			ExpectedRefusal string `json:"expected_refusal"`
		} `json:"wrong_key_capability"`
	}

	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("failed to unmarshal capability tokens fixture: %v", err)
	}

	pubKey, err := journal.ParsePublicKey(fixture.TrustedPublicKey)
	if err != nil {
		t.Fatalf("failed to parse trusted public key: %v", err)
	}

	evalTime, err := time.Parse(time.RFC3339, fixture.EvaluationTime)
	if err != nil {
		t.Fatalf("failed to parse evaluation time: %v", err)
	}

	// 1. Check Canonical payload generation
	canonical := string(auth.CanonicalCapabilityPayload(&fixture.ValidCapability.Payload))
	if canonical != fixture.ValidCapability.CanonicalPayload {
		t.Errorf("canonical payload mismatch:\ngot:\n%s\nwant:\n%s", canonical, fixture.ValidCapability.CanonicalPayload)
	}

	// 2. Check Ed25519 signature verification on valid capability
	sigBytes, err := hex.DecodeString(strings.TrimPrefix(fixture.ValidCapability.Signature, "ed25519:"))
	if err != nil {
		t.Fatalf("failed to hex decode signature: %v", err)
	}
	if !ed25519.Verify(pubKey, []byte(canonical), sigBytes) {
		t.Errorf("direct ed25519 signature verification failed on valid capability")
	}

	// 3. Verify valid capability compact token
	parsed, scopes, err := auth.ParseAndVerifyCapability(fixture.ValidCapability.CompactToken, pubKey, evalTime)
	if err != nil {
		t.Errorf("ParseAndVerifyCapability failed for valid capability: %v", err)
	} else {
		if parsed.ID != fixture.ValidCapability.Payload.ID {
			t.Errorf("parsed ID = %q, want %q", parsed.ID, fixture.ValidCapability.Payload.ID)
		}
		if len(scopes) != len(fixture.ValidCapability.Payload.Scopes) {
			t.Errorf("parsed scopes count = %d, want %d", len(scopes), len(fixture.ValidCapability.Payload.Scopes))
		}
	}

	// 4. Verify admin capability
	_, _, err = auth.ParseAndVerifyCapability(fixture.AdminCapability.CompactToken, pubKey, evalTime)
	if err != nil {
		t.Errorf("ParseAndVerifyCapability failed for admin capability: %v", err)
	}

	// 5. Verify expired capability fails
	_, _, err = auth.ParseAndVerifyCapability(fixture.ExpiredCapability.CompactToken, pubKey, evalTime)
	if err == nil {
		t.Errorf("expected expired capability to fail")
	} else if !errors.Is(err, auth.ErrExpired) {
		t.Errorf("expected ErrExpired, got %v", err)
	}

	// 6. Verify future capability fails
	_, _, err = auth.ParseAndVerifyCapability(fixture.FutureCapability.CompactToken, pubKey, evalTime)
	if err == nil {
		t.Errorf("expected future capability to fail")
	} else if !errors.Is(err, auth.ErrNotYetValid) {
		t.Errorf("expected ErrNotYetValid, got %v", err)
	}

	// 7. Verify tampered capability fails
	_, _, err = auth.ParseAndVerifyCapability(fixture.TamperedCapability.CompactToken, pubKey, evalTime)
	if err == nil {
		t.Errorf("expected tampered capability to fail")
	} else if !errors.Is(err, auth.ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}

	// 8. Verify wrong key capability fails
	_, _, err = auth.ParseAndVerifyCapability(fixture.WrongKeyCapability.CompactToken, pubKey, evalTime)
	if err == nil {
		t.Errorf("expected wrong key capability to fail")
	} else if !errors.Is(err, auth.ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}
