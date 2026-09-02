package auth_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/spectest"
)

// The published auth fixtures are hand-authored case tables rather than generator output, so
// the gate spec/journal/v1 gets — regenerate the tree, compare it to the committed one — has
// nothing to regenerate here. The same property is assembled out of five pieces instead:
//
//	TestFixtureTree                the fixtures directory holds exactly these files, and the
//	                               fixtures README names every one of them
//	the case counts below          how many cases each file carries, pinned to a literal
//	the executed counters          every case runs, and the number that ran is compared
//	                               against that literal, rather than a loop being trusted to
//	                               have had anything to iterate over
//	readFixture                    every field of every fixture is read by the test that runs
//	                               it; a field nothing reads is refused
//	TestSpecExamplesMatchFixtures  the specification's own JSON examples are the fixture
//	                               records they quote, byte for byte
//
// Between them: a fixture file cannot be added, deleted or emptied, a case cannot be dropped
// or skipped past, and a field no test reads cannot be introduced, without a test failing.
// That is what fixtures/README.md promises anyone reimplementing this format — "MUST pass all
// test cases defined in these fixture files without modification" — and until this gate it
// was promised by prose alone: emptying a file's cases to [] left the package green.
const (
	identifierCases      = 20
	scopeParsingCases    = 15
	scopeEvaluationCases = 19
	builtinTokenCases    = 4
	capabilityCases      = 6
)

// fixtureVersion is the format version every fixture in this directory declares. The auth
// format is versioned by its directory, spec/auth/v1, so a fixture carrying anything else is
// in the wrong tree.
const fixtureVersion = "v1"

// fixtureFiles is the exact contents of spec/auth/v1/fixtures. A file added here has to be
// read by a test in this package, and a file dropped from it has to be dropped from the
// directory: TestFixtureTree fails either way round.
var fixtureFiles = []string{
	"README.md",
	"builtin_tokens.json",
	"capability_tokens.json",
	"identifiers.json",
	"scopes.json",
}

// authSpecDir returns the published auth specification, spec/auth/v1.
func authSpecDir() string {
	return filepath.Join("..", "..", "spec", "auth", "v1")
}

func fixturesPath(filename string) string {
	return filepath.Join(authSpecDir(), "fixtures", filename)
}

// readFixture decodes a fixture file into v, refusing any field v does not carry.
//
// A fixture is a conformance claim, and a field no test reads is a claim nothing checks. The
// strictness is the point: a case table that grows a column fails here until a test reads it,
// rather than sitting in a published file looking load-bearing.
func readFixture(t *testing.T, filename string, v any) {
	t.Helper()
	data, err := os.ReadFile(fixturesPath(filename))
	if err != nil {
		t.Fatalf("failed to read %s: %v", filename, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("failed to unmarshal %s: %v", filename, err)
	}
}

// checkVersion asserts that a fixture declares the version of the tree it sits in.
func checkVersion(t *testing.T, filename, version string) {
	t.Helper()
	if version != fixtureVersion {
		t.Errorf("%s: version = %q, want %q", filename, version, fixtureVersion)
	}
}

// checkDescription asserts that a fixture's prose is present and is one line. Descriptions
// are the one part of these files nothing else pins, so this is all that holds them: a case
// that says nothing about itself is a case a reimplementation cannot act on.
func checkDescription(t *testing.T, what, description string) {
	t.Helper()
	if strings.TrimSpace(description) == "" {
		t.Errorf("%s carries no description", what)
	}
	if strings.ContainsAny(description, "\n\r") {
		t.Errorf("%s description is not a single line: %q", what, description)
	}
}

// TestFixtureTree asserts that spec/auth/v1/fixtures holds exactly the files this package
// reads, and that its README names each of them.
//
// Without this, a fixture file could be deleted, or one nothing reads added, and the package
// would stay green — which is the failure that matters on a published interface: a conformance
// suite that has quietly stopped being one still passes.
func TestFixtureTree(t *testing.T) {
	root := filepath.Join(authSpecDir(), "fixtures")
	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		found = append(found, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk %s: %v", root, err)
	}
	sort.Strings(found)

	if strings.Join(found, "\n") != strings.Join(fixtureFiles, "\n") {
		t.Errorf("the fixture tree holds:\n%s\nthe tests read:\n%s", strings.Join(found, "\n"), strings.Join(fixtureFiles, "\n"))
	}

	data, err := os.ReadFile(fixturesPath("README.md"))
	if err != nil {
		t.Fatalf("failed to read the fixtures README: %v", err)
	}
	readme := string(data)
	for _, name := range fixtureFiles {
		if name == "README.md" {
			continue
		}
		if !strings.Contains(readme, name) {
			t.Errorf("the fixtures README does not describe %s", name)
		}
	}
	if !strings.Contains(readme, "MUST pass all test cases") {
		t.Error("the fixtures README no longer states the conformance requirement these tests enforce")
	}
}

// identifierViolations are the violation classes identifiers.json distinguishes. Every one of
// them must be exercised by at least one case: pinning the count alone would let a whole class
// of refusal leave the table as long as something else was added in its place.
var identifierViolations = []string{
	"backslash",
	"empty",
	"invalid_char",
	"leading_dash",
	"leading_dot",
	"path_traversal",
	"reserved",
	"slash",
	"too_long",
	"trailing_dash",
	"trailing_dot",
	"whitespace",
}

func TestIdentifiersFixture(t *testing.T) {
	var fixture struct {
		Version     string `json:"version"`
		Description string `json:"description"`
		Cases       []struct {
			Identifier  string `json:"identifier"`
			Valid       bool   `json:"valid"`
			Violation   string `json:"violation"`
			Description string `json:"description"`
		} `json:"cases"`
	}
	readFixture(t, "identifiers.json", &fixture)
	checkVersion(t, "identifiers.json", fixture.Version)
	checkDescription(t, "identifiers.json", fixture.Description)

	if len(fixture.Cases) != identifierCases {
		t.Fatalf("identifiers.json carries %d cases, want %d", len(fixture.Cases), identifierCases)
	}

	known := make(map[string]bool, len(identifierViolations))
	for _, name := range identifierViolations {
		known[name] = false
	}

	ran := 0
	for _, tc := range fixture.Cases {
		checkDescription(t, "identifier case "+tc.Identifier, tc.Description)
		err := auth.ValidateRepo(tc.Identifier)
		if tc.Valid {
			if tc.Violation != "" {
				t.Errorf("fixture %q is valid but names violation %q", tc.Identifier, tc.Violation)
			}
			if err != nil {
				t.Errorf("fixture %q (%s): expected valid, got error: %v", tc.Identifier, tc.Description, err)
			}
		} else {
			if _, ok := known[tc.Violation]; !ok {
				t.Errorf("fixture %q names violation %q, which this test does not know", tc.Identifier, tc.Violation)
			}
			known[tc.Violation] = true
			if err == nil {
				t.Errorf("fixture %q (%s): expected invalid (%s), got nil error", tc.Identifier, tc.Description, tc.Violation)
			} else {
				if !errors.Is(err, auth.ErrInvalidRepo) {
					t.Errorf("fixture %q: expected ErrInvalidRepo, got %v", tc.Identifier, err)
				}
				if strings.ContainsAny(err.Error(), "\n\r") {
					t.Errorf("fixture %q: refusal is not a single line: %q", tc.Identifier, err.Error())
				}
			}
		}
		ran++
	}
	if ran != identifierCases {
		t.Errorf("%d identifier cases ran, want %d", ran, identifierCases)
	}
	for _, name := range identifierViolations {
		if !known[name] {
			t.Errorf("no identifier case exercises the %q violation", name)
		}
	}
}

func TestScopesFixture(t *testing.T) {
	var fixture struct {
		Version      string `json:"version"`
		Description  string `json:"description"`
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
	readFixture(t, "scopes.json", &fixture)
	checkVersion(t, "scopes.json", fixture.Version)
	checkDescription(t, "scopes.json", fixture.Description)

	if len(fixture.ScopeParsing) != scopeParsingCases {
		t.Fatalf("scopes.json carries %d parsing cases, want %d", len(fixture.ScopeParsing), scopeParsingCases)
	}
	if len(fixture.Evaluations) != scopeEvaluationCases {
		t.Fatalf("scopes.json carries %d evaluation cases, want %d", len(fixture.Evaluations), scopeEvaluationCases)
	}

	parsed := 0
	for _, tc := range fixture.ScopeParsing {
		checkDescription(t, "scope case "+tc.Scope, tc.Description)
		scope, err := auth.ParseScope(tc.Scope)
		if !tc.Valid {
			if err == nil {
				t.Errorf("scope parsing %q (%s): expected error, got nil", tc.Scope, tc.Description)
			}
			parsed++
			continue
		}
		if err != nil {
			t.Errorf("scope parsing %q (%s): expected valid, got: %v", tc.Scope, tc.Description, err)
			parsed++
			continue
		}
		if scope.Pattern != tc.Pattern {
			t.Errorf("scope %q pattern = %q, want %q", tc.Scope, scope.Pattern, tc.Pattern)
		}
		if scope.Actions.String() != tc.CanonicalActions {
			t.Errorf("scope %q canonical actions = %q, want %q", tc.Scope, scope.Actions.String(), tc.CanonicalActions)
		}
		// The actions array is the same set written out one action at a time, and a
		// reimplementation reads it rather than deriving it from the canonical string, so it
		// is checked against the parsed set rather than left as decoration.
		granted := auth.Actions{}
		for _, action := range tc.Actions {
			switch auth.Action(action) {
			case auth.ActionRead:
				granted.Read = true
			case auth.ActionWrite:
				granted.Write = true
			case auth.ActionCreate:
				granted.Create = true
			default:
				t.Errorf("scope %q lists unknown action %q", tc.Scope, action)
			}
		}
		if granted != scope.Actions {
			t.Errorf("scope %q lists actions %v, which parse to %q", tc.Scope, tc.Actions, scope.Actions.String())
		}
		parsed++
	}
	if parsed != scopeParsingCases {
		t.Errorf("%d scope parsing cases ran, want %d", parsed, scopeParsingCases)
	}

	evaluated := 0
	for _, tc := range fixture.Evaluations {
		checkDescription(t, "evaluation on "+tc.Repo, tc.Description)
		scopes, err := auth.ParseScopes(tc.Scopes)
		if err != nil {
			t.Fatalf("failed to parse evaluation scopes %v: %v", tc.Scopes, err)
		}
		if got := auth.Allows(scopes, auth.Action(tc.Action), tc.Repo); got != tc.Allowed {
			t.Errorf("evaluation %v on repo %q action %q (%s): got %v, want %v", tc.Scopes, tc.Repo, tc.Action, tc.Description, got, tc.Allowed)
		}
		evaluated++
	}
	if evaluated != scopeEvaluationCases {
		t.Errorf("%d scope evaluation cases ran, want %d", evaluated, scopeEvaluationCases)
	}
}

func TestBuiltinTokensFixture(t *testing.T) {
	var fixture struct {
		Version     string `json:"version"`
		Description string `json:"description"`
		Tokens      []struct {
			TokenID   string   `json:"token_id"`
			RawToken  string   `json:"raw_token"`
			TokenHash string   `json:"token_hash"`
			Scopes    []string `json:"scopes"`
			Revoked   bool     `json:"revoked"`
		} `json:"tokens"`
	}
	readFixture(t, "builtin_tokens.json", &fixture)
	checkVersion(t, "builtin_tokens.json", fixture.Version)
	checkDescription(t, "builtin_tokens.json", fixture.Description)

	if len(fixture.Tokens) != builtinTokenCases {
		t.Fatalf("builtin_tokens.json carries %d tokens, want %d", len(fixture.Tokens), builtinTokenCases)
	}

	ctx := context.Background()
	store := auth.NewMemoryTokenStore()
	authorizer := auth.NewBuiltinAuthorizer(store)

	type loaded struct {
		raw     string
		scopes  []auth.Scope
		revoked bool
	}
	tokens := make([]loaded, 0, len(fixture.Tokens))

	for _, tok := range fixture.Tokens {
		if computed := auth.HashToken(tok.RawToken); computed != tok.TokenHash {
			t.Errorf("token %s hash mismatch: computed %q, want %q", tok.TokenID, computed, tok.TokenHash)
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
		tokens = append(tokens, loaded{raw: tok.RawToken, scopes: scopes, revoked: tok.Revoked})
	}

	// Every token in the table is presented to the authorizer over the same probe matrix: a
	// live token must decide each probe exactly as its own scopes do, and a revoked one must
	// refuse every probe whatever its scopes say. That is section 3.4 asked through the store
	// — hash the bearer token, find the record, evaluate its scopes — rather than of the scope
	// evaluator directly, which is the half of this file the other tests do not reach.
	probeRepos := []string{"blog-alpha", "docs", "metrics-collector"}
	probeActions := []auth.Action{auth.ActionRead, auth.ActionWrite, auth.ActionCreate}

	ran := 0
	for _, tok := range tokens {
		for _, repo := range probeRepos {
			for _, action := range probeActions {
				ok, err := authorizer.Authorize(ctx, tok.raw, action, repo)
				if tok.revoked {
					if ok || !errors.Is(err, auth.ErrUnauthorized) {
						t.Errorf("revoked token on %s %q: got ok=%v, err=%v, want unauthorized", action, repo, ok, err)
					}
					continue
				}
				want := auth.Allows(tok.scopes, action, repo)
				if ok != want {
					t.Errorf("token on %s %q: got ok=%v, err=%v, want %v", action, repo, ok, err, want)
				}
			}
		}
		ran++
	}
	if ran != builtinTokenCases {
		t.Errorf("%d built-in token cases ran, want %d", ran, builtinTokenCases)
	}

	// Two literals, so that the probe matrix above is not the only thing saying what the
	// fixture tokens mean: the admin token reads any repository, and the revoked one reads
	// nothing.
	ok, err := authorizer.Authorize(ctx, "walden_sec_admin_0123456789abcdef", auth.ActionRead, "my-repo")
	if !ok || err != nil {
		t.Errorf("expected admin token read allowed, got ok=%v, err=%v", ok, err)
	}
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

// signedCapability is a capability the fixture carries a signature for.
type signedCapability struct {
	Payload            auth.CapabilityPayload `json:"payload"`
	CanonicalPayload   string                 `json:"canonical_payload"`
	Signature          string                 `json:"signature"`
	SignatureBase64URL string                 `json:"signature_base64url"`
	CompactToken       string                 `json:"compact_token"`
}

// refusedCapability is a capability verification must refuse, and the refusal it must give.
// expected_refusal names the refusal's category — the "<what>" of the single line, section 7's
// left-hand column — because the rest of the line carries the evaluation time.
type refusedCapability struct {
	Payload         auth.CapabilityPayload `json:"payload"`
	CompactToken    string                 `json:"compact_token"`
	ExpectedRefusal string                 `json:"expected_refusal"`
}

type capabilityFixture struct {
	Version            string            `json:"version"`
	Description        string            `json:"description"`
	TrustedPublicKey   string            `json:"trusted_public_key"`
	EvaluationTime     string            `json:"evaluation_time"`
	ValidCapability    signedCapability  `json:"valid_capability"`
	AdminCapability    signedCapability  `json:"admin_capability"`
	ExpiredCapability  refusedCapability `json:"expired_capability"`
	FutureCapability   refusedCapability `json:"future_capability"`
	TamperedCapability refusedCapability `json:"tampered_capability"`
	WrongKeyCapability refusedCapability `json:"wrong_key_capability"`
}

// capabilityEnvelope assembles the section 6.2 structured envelope for a capability the
// fixture signs. The fixture carries each capability as a compact token; the envelope is the
// same capability in the other accepted wire format, so it is derived through the published
// type rather than written down a second time and left free to drift from the token beside it.
func capabilityEnvelope(c signedCapability) auth.CapabilityEnvelope {
	return auth.CapabilityEnvelope{
		Version:   fixtureVersion,
		Payload:   c.Payload,
		Signature: c.Signature,
	}
}

// checkRefusedCapability verifies that a capability the fixture marks refused is refused, for
// the reason it names and with the error the package documents.
func checkRefusedCapability(t *testing.T, name string, c refusedCapability, pubKey ed25519.PublicKey, evalTime time.Time, want error) {
	t.Helper()
	_, _, err := auth.ParseAndVerifyCapability(c.CompactToken, pubKey, evalTime)
	if err == nil {
		t.Errorf("expected %s to be refused", name)
		return
	}
	if !errors.Is(err, want) {
		t.Errorf("%s: expected %v, got %v", name, want, err)
	}
	if strings.ContainsAny(err.Error(), "\n\r") {
		t.Errorf("%s: refusal is not a single line: %q", name, err.Error())
	}
	if !strings.HasPrefix(err.Error(), c.ExpectedRefusal+": ") {
		t.Errorf("%s: refusal %q does not open with the expected %q", name, err.Error(), c.ExpectedRefusal)
	}
}

func TestCapabilityTokensFixture(t *testing.T) {
	var fixture capabilityFixture
	readFixture(t, "capability_tokens.json", &fixture)
	checkVersion(t, "capability_tokens.json", fixture.Version)
	checkDescription(t, "capability_tokens.json", fixture.Description)

	pubKey, err := journal.ParsePublicKey(fixture.TrustedPublicKey)
	if err != nil {
		t.Fatalf("failed to parse trusted public key: %v", err)
	}
	evalTime, err := time.Parse(time.RFC3339, fixture.EvaluationTime)
	if err != nil {
		t.Fatalf("failed to parse evaluation time: %v", err)
	}

	verified := 0

	// The two signed capabilities: the canonical payload of section 6.4 is the byte sequence
	// the signature covers, so it is rebuilt and the signature checked against it directly,
	// then the compact token is put through verification the way a request would be.
	for _, signed := range []struct {
		name string
		c    signedCapability
	}{
		{"valid capability", fixture.ValidCapability},
		{"admin capability", fixture.AdminCapability},
	} {
		name, c := signed.name, signed.c
		canonical := string(auth.CanonicalCapabilityPayload(&c.Payload))
		if canonical != c.CanonicalPayload {
			t.Errorf("%s canonical payload mismatch:\ngot:\n%s\nwant:\n%s", name, canonical, c.CanonicalPayload)
		}
		sigBytes, err := hex.DecodeString(strings.TrimPrefix(c.Signature, "ed25519:"))
		if err != nil {
			t.Fatalf("%s: failed to hex decode signature: %v", name, err)
		}
		if !ed25519.Verify(pubKey, []byte(canonical), sigBytes) {
			t.Errorf("%s: direct ed25519 signature verification failed", name)
		}
		if encoded := base64.RawURLEncoding.EncodeToString(sigBytes); encoded != c.SignatureBase64URL {
			t.Errorf("%s: signature_base64url = %q, want %q", name, c.SignatureBase64URL, encoded)
		}

		parsed, scopes, err := auth.ParseAndVerifyCapability(c.CompactToken, pubKey, evalTime)
		if err != nil {
			t.Errorf("%s: ParseAndVerifyCapability failed: %v", name, err)
		} else {
			if parsed.ID != c.Payload.ID {
				t.Errorf("%s: parsed ID = %q, want %q", name, parsed.ID, c.Payload.ID)
			}
			if len(scopes) != len(c.Payload.Scopes) {
				t.Errorf("%s: parsed scopes count = %d, want %d", name, len(scopes), len(c.Payload.Scopes))
			}
		}

		// Section 6.2's other wire format. The envelope carries the same payload and the same
		// signature, so verification must reach the same answer through it.
		envelope, err := json.Marshal(capabilityEnvelope(c))
		if err != nil {
			t.Fatalf("%s: failed to marshal the capability envelope: %v", name, err)
		}
		if _, _, err := auth.ParseAndVerifyCapability(string(envelope), pubKey, evalTime); err != nil {
			t.Errorf("%s: ParseAndVerifyCapability failed on the JSON envelope: %v", name, err)
		}
		verified++
	}

	// The four capabilities verification must refuse, one per reason: past its expiry, before
	// its activation, a payload swapped under a good signature, and a signature from a key
	// this server does not trust.
	checkRefusedCapability(t, "expired capability", fixture.ExpiredCapability, pubKey, evalTime, auth.ErrExpired)
	checkRefusedCapability(t, "future capability", fixture.FutureCapability, pubKey, evalTime, auth.ErrNotYetValid)
	checkRefusedCapability(t, "tampered capability", fixture.TamperedCapability, pubKey, evalTime, auth.ErrInvalidSignature)
	checkRefusedCapability(t, "wrong key capability", fixture.WrongKeyCapability, pubKey, evalTime, auth.ErrInvalidSignature)
	verified += 4

	if verified != capabilityCases {
		t.Errorf("%d capabilities ran, want %d", verified, capabilityCases)
	}
}

// specJSONExamples pins every JSON example spec/auth/v1/README.md carries, in document order,
// to the fixture record it quotes. The specification is a published interface with a
// reimplementation grant: someone will write an implementation from the prose alone, so an
// example that has drifted from the fixtures is not a cosmetic defect.
//
// The journal specification's examples are whole fixture files and cite the file each one
// quotes, so its gate follows the link. The auth fixtures are case tables, and an example here
// is one record out of a table — there is no file to link — so the citation lives in this
// table instead. An example added to the document without a row added here fails for having no
// pin; a row without an example fails for the same reason from the other side.
//
// Two of the four are records of the *journal* format, written by the fixture generator in
// spec/journal/v1. They are quoted here because the token table is journaled to the meta
// stream, and holding them to the golden journal is what keeps the two published documents
// describing the same record.
var specJSONExamples = []struct {
	name string
	want func(t *testing.T) []byte
}{
	{"section 5.2, the token_create meta record", func(t *testing.T) []byte {
		return readJournalFixture(t, journal.TxKey(journal.MetaStreamID, 1))
	}},
	{"section 5.3, the token_revoke meta record", func(t *testing.T) []byte {
		return readJournalFixture(t, journal.TxKey(journal.MetaStreamID, 3))
	}},
	{"section 6.2, the structured JSON envelope", func(t *testing.T) []byte {
		return marshalExample(t, capabilityEnvelope(readCapabilityFixture(t).ValidCapability))
	}},
	{"section 6.3, the capability payload", func(t *testing.T) []byte {
		return marshalExample(t, readCapabilityFixture(t).ValidCapability.Payload)
	}},
}

// readJournalFixture reads one record of the golden journal, addressed by its object storage
// key the way spec/journal/v1's own tests address it.
func readJournalFixture(t *testing.T, key string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "spec", "journal", "v1", "fixtures", filepath.FromSlash(key))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read the journal fixture %s: %v", key, err)
	}
	return data
}

func readCapabilityFixture(t *testing.T) capabilityFixture {
	t.Helper()
	var fixture capabilityFixture
	readFixture(t, "capability_tokens.json", &fixture)
	return fixture
}

// marshalExample renders a fixture value the way the specification prints it: two-space
// indentation, one trailing newline.
func marshalExample(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal an expected example: %v", err)
	}
	return append(data, '\n')
}

// TestSpecExamplesMatchFixtures holds every JSON example in spec/auth/v1/README.md to the
// fixture record it quotes, byte for byte, and reports any JSON document the specification
// carries that is not such an example.
//
// Finding the examples is spectest.JSONExamples' job, and what it can and cannot see is
// documented there; spec/journal/v1 has the same gate over its own document and reads it
// through the same code.
func TestSpecExamplesMatchFixtures(t *testing.T) {
	specPath := filepath.Join(authSpecDir(), "README.md")
	data, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", specPath, err)
	}
	examples, stray, err := spectest.JSONExamples(strings.Split(string(data), "\n"))
	if err != nil {
		t.Fatalf("failed to read the examples of %s: %v", specPath, err)
	}

	for _, line := range stray {
		t.Errorf("%s:%d: this JSON document is not inside a ```json fence, so nothing holds it to a fixture", specPath, line+1)
	}

	if len(examples) != len(specJSONExamples) {
		t.Fatalf("the specification carries %d json examples, want %d", len(examples), len(specJSONExamples))
	}
	for i, example := range examples {
		pinned := specJSONExamples[i]
		want := pinned.want(t)
		if example.Body != string(want) {
			t.Errorf("%s:%d: the example and the fixture it quotes (%s) have drifted apart.\n"+
				"The examples are copied into the specification by hand, so paste the fixture over\n"+
				"the example and review the diff.\nspec:\n%s\nfixture:\n%s", specPath, example.Start, pinned.name, example.Body, want)
		}
	}
}
