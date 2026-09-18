package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/config"
	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
	"github.com/writtendev/walden/internal/store"
)

type allowList struct {
	entries []string
	set     bool
}

func (a *allowList) String() string {
	return strings.Join(a.entries, ",")
}

func (a *allowList) Set(val string) error {
	a.set = true
	for _, part := range strings.Split(val, ",") {
		a.entries = append(a.entries, part)
	}
	return nil
}

func resolveDataDir(flagDataDir string, dataDirSet bool) (string, error) {
	if dataDirSet {
		if flagDataDir == "" {
			return "", refusal.Refuse("invalid data-dir", "cannot be empty", "specify a valid directory path")
		}
		return flagDataDir, nil
	}
	if env := os.Getenv(config.EnvDataDir); env != "" {
		return env, nil
	}
	return config.DefaultDataDir, nil
}

func generateRandomTokenID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random token id: %w", err)
	}
	return "tok_" + hex.EncodeToString(b), nil
}

// resolveJournalFlag resolves the --journal / WALDEN_JOURNAL knob for a
// token subcommand exactly the way runRotateKey (rotate.go) resolves it
// for rotate-key: thread the flag through config.Load rather than
// reimplementing the knob's precedence, and pin every other knob
// config.Load's Validate also checks (--listen, --auth-trust, --data-dir)
// to an always-valid literal, since a token subcommand neither binds nor
// reads any of those from the *Config it gets back — dataDir here already
// comes from resolveDataDir, not cfg.DataDir. See rotate.go's own doc
// comment for the full reasoning behind pinning those three; this copies
// its technique rather than re-deriving it, and rotate.go itself is not
// touched (WALD-31 owns it). An empty result means journal-less mode: the
// append is skipped and the disk mutation is the whole operation.
func resolveJournalFlag(journalFlag string, journalSet bool, dataDir string) (string, error) {
	var configArgs []string
	if journalSet {
		configArgs = append(configArgs, "--journal", journalFlag)
	}
	configArgs = append(configArgs,
		"--auth-trust", "unused",
		"--listen", config.DefaultListenAddr,
		"--data-dir", dataDir,
	)
	cfg, _, err := config.Load(configArgs)
	if err != nil {
		return "", err
	}
	return cfg.JournalURL, nil
}

// tokenJournal is the open handle to _meta a token mutation needs: the
// client and lease to append through, the signing chain and rebuilt token
// table ReplayMetaTable produced, and the local signing key to sign with.
// It is nil-valued in every field when journalURL was empty at
// prepareTokenJournal's call site — journal-less mode — and callers check
// that by comparing the returned *tokenJournal itself to nil.
type tokenJournal struct {
	client *store.Client
	lease  *journal.Lease
	chain  *journal.SigningChain
	table  *journal.TokenTable
	priv   ed25519.PrivateKey
}

// prepareTokenJournal performs the read half of "journal then disk"
// (WALD-33) shared by `walden token create` and `walden token revoke`:
// resolve the journal URL, replay _meta into both the signing chain and
// the rebuilt token table (ReplayMetaTable, internal/store/tokens.go),
// load this instance's local signing key, and open a lease on the meta
// stream — everything a caller needs before it can itself check the
// rebuilt table and call AppendTokenCreate/AppendTokenRevoke. It returns
// (nil, nil) when journalURL is empty: journal-less mode, where the
// caller's disk mutation is the whole operation, exactly as it was before
// this ticket.
//
// This does not itself call AppendTokenCreate/AppendTokenRevoke: the
// uniqueness and hash-agreement checks against the rebuilt table differ
// between a create and a revoke (see runTokenCreate and runTokenRevoke),
// so each caller makes its own append call once it has checked table
// against its own tokenID.
//
// op names the caller ("token create" or "token revoke") for the one
// refusal this function itself shapes: a journal that carries no genesis
// record at all has no active signing key to journal against, the same
// condition RotateKey's own refuseNoGenesisToRotate (rotation.go) refuses
// for a rotation — store.ErrObjectNotFound is unwrapped and un-refusal-
// shaped by itself (ReplayMeta/ReplayMetaTable's own doc comment: that
// sentinel is for EnsureGenesis's mint path to distinguish, not for an
// operator to read), so it is turned into a one-line refusal here rather
// than reaching the CLI's stderr bare.
func prepareTokenJournal(ctx context.Context, op, journalURL, dataDir string) (*tokenJournal, error) {
	if journalURL == "" {
		return nil, nil
	}
	j, err := store.ResolveJournal(journalURL, os.LookupEnv)
	if err != nil {
		return nil, err
	}
	c := store.NewClient(j)
	chain, table, err := c.ReplayMetaTable(ctx)
	if err != nil {
		if errors.Is(err, store.ErrObjectNotFound) {
			return nil, refuseNoGenesisForToken(op)
		}
		return nil, err
	}
	priv, err := journal.LoadSigningKey(dataDir)
	if err != nil {
		switch {
		case os.IsNotExist(err):
			return nil, journal.RefuseNoSigningKey(dataDir)
		case errors.Is(err, journal.ErrSigningKeyUnavailable):
			return nil, journal.RefuseInvalidSigningKeyFile(dataDir, err)
		default:
			return nil, journal.RefuseSigningKeyUnreadable(err)
		}
	}
	leases := journal.NewLeases(c)
	lease, err := leases.Open(ctx, journal.MetaStreamID)
	if err != nil {
		return nil, err
	}
	return &tokenJournal{client: c, lease: lease, chain: chain, table: table, priv: priv}, nil
}

// refuseNoGenesisForToken returns a one-line refusal when the journal
// configured for a token mutation carries no genesis record at all:
// there is no active signing key to journal against, mirroring
// RotateKey's own refuseNoGenesisToRotate (rotation.go) for the same
// underlying condition on a different operation.
func refuseNoGenesisForToken(op string) error {
	return refusal.Refuse(
		op+" refused",
		"no genesis record found in the configured journal",
		"boot walden serve against this journal first so a signing identity exists",
	)
}

// refuseTokenIDAlreadyJournaled refuses a `walden token create` whose id
// the journal's rebuilt token table already holds, before any append: a
// token_create naming an id the journal already carries would poison
// every future replay under spec section 8.1 rule 10, so the local
// store's own ErrTokenExists (which only sees disk) is not a sufficient
// guard — the check has to run against the table the journal itself
// rebuilds to.
func refuseTokenIDAlreadyJournaled(tokenID string) error {
	return refusal.RefuseWithCause(
		"token create refused",
		fmt.Sprintf("token id %q already exists in the journal", tokenID),
		"choose a different token id",
		auth.ErrTokenExists,
	)
}

// refuseTokenUnknownInJournal refuses a `walden token revoke` naming an
// id the journal's rebuilt token table does not hold: appending a
// token_revoke for it would not chain to a creation, which spec section
// 8.1 rule 11 refuses on replay — refused here instead, before any
// append.
//
// The table not holding tokenID is reachable two ways that look
// identical to it: a typo'd or never-existed id, or a token that was
// created while journal-less (or before --journal/WALDEN_JOURNAL was
// ever set on this instance) and still lives only in tokens.json — the
// journal was simply never told about it (round 1 finding 3). This
// function cannot tell those two apart, so the refusal is worded to
// cover both truthfully rather than assume the id is bogus, and its fix
// names a step that actually works today instead of 'walden token
// list', which would only confirm the id exists on disk and leave the
// operator exactly as stuck. Unsetting the journal knob for one command
// reaches the same disk-only revoke path this instance used before any
// journal was configured — it is not a workaround, it is the operation
// this token has always supported. Whether a disk-only token should
// instead revoke through the journal, or be journaled retroactively, is
// the open question WALD-33's own plan left to WALD-57, and is not
// decided here: this function does not journal a token_create for an id
// that was never journaled in order to then revoke it — that would
// forge history.
func refuseTokenUnknownInJournal(tokenID string) error {
	return refusal.RefuseWithCause(
		"token revoke refused",
		fmt.Sprintf("token id %q is not recorded in the journal (unknown id, or a token created before a journal was configured)", tokenID),
		"if this token predates the journal, unset --journal/WALDEN_JOURNAL for this one command to revoke it on disk directly; otherwise verify the id with 'walden token list'",
		auth.ErrTokenNotFound,
	)
}

// refuseTokenAlreadyRevokedInJournal refuses a `walden token revoke`
// once both the journal's rebuilt table and tokens.json agree the token
// is already revoked, translating FileTokenStore.RevokeToken's own
// auth.ErrTokenAlreadyRevoked into wording that names the journal too.
// It is not a pre-append check by itself — see runTokenRevoke, which
// only reaches for this after store.RevokeToken has actually confirmed
// disk agrees, so a retry completing a half-finished revoke (round 1
// finding 2) is never short-circuited into this refusal before disk is
// given the chance to catch up.
func refuseTokenAlreadyRevokedInJournal(tokenID string) error {
	return refusal.RefuseWithCause(
		"token revoke refused",
		fmt.Sprintf("token id %q is already revoked in the journal", tokenID),
		"no action needed; the token is already inactive",
		auth.ErrTokenAlreadyRevoked,
	)
}

// refuseTokenRevokeDiskIncomplete refuses a `walden token revoke` whose
// journal half already landed — this call's own append just above, or an
// earlier attempt's — while the tokens.json mutation that was supposed
// to follow it failed. diskErr is FileTokenStore.RevokeToken's own
// error, wrapped rather than replaced so errors.Is against its sentinel
// (typically auth.ErrStoreUnavailable) still resolves.
//
// This is the round 1 finding 2 fix's one-line half: the plan accepted
// journal-lands/disk-fails as benign for a create (a row nobody holds the
// raw token for), but for a revoke the same failure leaves a credential
// the journal now calls dead still authenticating against tokens.json —
// the opposite of what the operator asked for, on a security operation.
// The wording says so plainly, rather than relaying diskErr bare, and the
// fix names the one thing that actually clears it: run the same command
// again once the data directory is writable. runTokenRevoke's own
// pre-check no longer refuses that retry outright the way it used to —
// see its doc comment — so re-running this exact command is a real path
// forward, not a dead end.
func refuseTokenRevokeDiskIncomplete(tokenID string, diskErr error) error {
	return refusal.RefuseWithCause(
		"token revoke refused",
		fmt.Sprintf("token id %q is now revoked in the journal, but tokens.json could not be updated: %s", tokenID, diskErr.Error()),
		fmt.Sprintf("the token may still authenticate locally until this succeeds; retry 'walden token revoke %s' once the data directory is writable", tokenID),
		diskErr,
	)
}

func runToken(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return refusal.Refuse("missing token subcommand", "no action specified", "expected create, list, or revoke")
	}

	switch args[0] {
	case "create":
		return runTokenCreate(args[1:], stdout, stderr)
	case "list":
		return runTokenList(args[1:], stdout, stderr)
	case "revoke":
		return runTokenRevoke(args[1:], stdout, stderr)
	default:
		return refusal.Refuse("unknown token subcommand", args[0], "expected create, list, or revoke")
	}
}

// runTokenCreate implements `walden token create`. When a journal is
// configured (--journal or WALDEN_JOURNAL, the same knob every other
// walden command reads it from — no sixth knob added here), it journals
// the token_create record to _meta before writing tokens.json: journal
// first, disk second (WALD-33), so a live token the journal never heard
// of is unrepresentable. The uniqueness check that guards against a
// reused token id runs against the journal's own rebuilt token table, not
// against tokens.json — a create reusing an id already in the journal
// would poison every future replay (spec section 8.1 rule 10), and the
// local store's ErrTokenExists only ever sees disk. With no journal
// configured, this behaves exactly as it did before this ticket.
func runTokenCreate(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("token create", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		flagDataDir   string
		flagID        string
		flagAuthTrust string
		flagJournal   string
		allows        allowList
	)

	fs.StringVar(&flagDataDir, "data-dir", "", "Path to bare git repository storage")
	fs.StringVar(&flagID, "id", "", "Custom token identifier")
	fs.StringVar(&flagAuthTrust, "auth-trust", "", "Public key for delegated capability token verification")
	fs.StringVar(&flagJournal, "journal", "", "S3-style URL for write-ahead log in object storage")
	fs.Var(&allows, "allow", "Scope grant for token (e.g. 'rw:blog-*', 'rwc:*')")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printUsage(stdout)
			return nil
		}
		return refusal.Refuse("token create refused", err.Error(), "run 'walden help' for usage")
	}

	if len(fs.Args()) > 0 {
		return refusal.Refuse("unexpected argument", fs.Args()[0], "token create accepts flags only")
	}

	setFlags := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})

	authTrust := os.Getenv(config.EnvAuthTrust)
	if setFlags["auth-trust"] {
		authTrust = flagAuthTrust
	}
	if strings.TrimSpace(authTrust) != "" {
		return refusal.Refuse(
			"token create refused",
			"cannot create built-in token when delegated auth is configured (auth-trust key is set)",
			"built-in tokens cannot authenticate while delegated mode is active; unset WALDEN_AUTH_TRUST to use built-in auth",
		)
	}

	dataDir, err := resolveDataDir(flagDataDir, setFlags["data-dir"])
	if err != nil {
		return err
	}

	journalURL, err := resolveJournalFlag(flagJournal, setFlags["journal"], dataDir)
	if err != nil {
		return err
	}

	var tokenID string
	if setFlags["id"] {
		if flagID == "" {
			return refusal.RefuseWithCause(
				"token create refused",
				"invalid token id: cannot be empty",
				"pass a token id containing only [a-zA-Z0-9._-]",
				journal.ErrInvalidTokenID,
			)
		}
		if err := journal.ValidateTokenID(flagID); err != nil {
			return refusal.RefuseWithCause(
				"token create refused",
				err.Error(),
				"pass a token id containing only [a-zA-Z0-9._-]",
				journal.ErrInvalidTokenID,
			)
		}
		tokenID = flagID
	} else {
		id, err := generateRandomTokenID()
		if err != nil {
			return refusal.Refuse("token create refused", err.Error(), "ensure system random source is available")
		}
		tokenID = id
	}

	rawScopes := allows.entries
	if !allows.set {
		rawScopes = []string{"rwc:*"}
	}

	scopes, err := auth.ParseScopes(rawScopes)
	if err != nil {
		return err
	}

	rawToken, tokenHash, err := auth.GenerateToken()
	if err != nil {
		return refusal.Refuse("token create refused", err.Error(), "ensure system random source is available")
	}

	createdAt := time.Now().UTC()
	record := &auth.TokenRecord{
		TokenID:   tokenID,
		TokenHash: tokenHash,
		Scopes:    scopes,
		CreatedAt: createdAt,
	}

	// Journal first, disk second (WALD-33). Bounded the same way
	// rotate-key's own journal work is (main.go's probeTimeout): this is a
	// one-shot CLI invocation with nothing to gracefully stop, so an
	// unreachable bucket refuses in bounded time rather than hanging.
	journalCtx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	tj, err := prepareTokenJournal(journalCtx, "token create", journalURL, dataDir)
	if err != nil {
		return err
	}
	if tj != nil {
		// The uniqueness pre-check runs against the journal's rebuilt
		// table, not against tokens.json — see this function's own doc
		// comment for why. Checked before any append.
		if _, exists := tj.table.Row(tokenID); exists {
			return refuseTokenIDAlreadyJournaled(tokenID)
		}
		// scopes reach the record as Scope.String() values, the same
		// "<actions>:<pattern>" text tokens.json itself carries
		// (diskToken's own doc comment, internal/auth/filestore.go).
		scopeStrs := make([]string, len(scopes))
		for i, s := range scopes {
			scopeStrs[i] = s.String()
		}
		// now is a closure over createdAt, not time.Now itself, so the
		// journal record and the disk record carry the identical instant.
		now := func() time.Time { return createdAt }
		if _, err := tj.client.AppendTokenCreate(journalCtx, tj.lease, tj.priv, tj.chain, tokenID, tokenHash, scopeStrs, now); err != nil {
			return err
		}
	}

	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return refusal.RefuseWithCause(
			"token store unavailable",
			fmt.Sprintf("cannot create data directory %s: %s", dataDir, err.Error()),
			"verify the data directory path and permissions",
			auth.ErrStoreUnavailable,
		)
	}

	store := auth.NewFileTokenStore(dataDir)
	if err := store.CreateToken(context.Background(), record); err != nil {
		return err
	}

	fmt.Fprintln(stdout, rawToken)
	return nil
}

func runTokenList(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("token list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var flagDataDir string
	fs.StringVar(&flagDataDir, "data-dir", "", "Path to bare git repository storage")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printUsage(stdout)
			return nil
		}
		return refusal.Refuse("token list refused", err.Error(), "run 'walden help' for usage")
	}

	if len(fs.Args()) > 0 {
		return refusal.Refuse("unexpected argument", fs.Args()[0], "token list accepts flags only")
	}

	setFlags := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})

	dataDir, err := resolveDataDir(flagDataDir, setFlags["data-dir"])
	if err != nil {
		return err
	}

	store := auth.NewFileTokenStore(dataDir)
	records, err := store.ListTokens(context.Background())
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSCOPES\tSTATUS\tCREATED")
	for _, rec := range records {
		scopeStrs := make([]string, len(rec.Scopes))
		for i, s := range rec.Scopes {
			scopeStrs[i] = s.String()
		}
		status := "active"
		if rec.Revoked {
			status = "revoked"
		}
		created := rec.CreatedAt.UTC().Format(time.RFC3339)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", rec.TokenID, strings.Join(scopeStrs, ","), status, created)
	}
	return w.Flush()
}

// runTokenRevoke implements `walden token revoke`. Like runTokenCreate, it
// journals the token_revoke record to _meta before mutating tokens.json
// when a journal is configured (WALD-33) — no new flag, --journal /
// WALDEN_JOURNAL is the same knob every other walden command reads it
// from. Revoking a token this way gives `walden token revoke` a network
// dependency it did not have before: an unreachable bucket refuses the
// revocation rather than applying it only to disk, correct per "never
// guess" but worth an operator knowing about on a security operation.
//
// The token's identity and hash are both taken from the journal's own
// rebuilt table, not recomputed locally: an unknown id refuses (mirroring
// spec section 8.1 rule 11), before any append. Because the row's own
// token_hash is what gets journaled, rule 12's hash-agreement check can
// never trip here — there is no second, operator-supplied hash for it to
// disagree with.
//
// An already-revoked row is handled differently from an unknown one
// (round 1 finding 2): this function no longer refuses the moment the
// journal's table shows the row revoked, because that table alone cannot
// tell "already revoked, nothing to do" apart from "a previous attempt's
// append landed but its tokens.json write failed, and this is the
// retry" — and short-circuiting on the first case used to make the
// second one permanently unrecoverable except by hand-editing
// tokens.json, leaving a credential the journal calls dead still
// authenticating. Instead: the append is skipped when the table already
// shows the row revoked (so a retry never journals a second
// token_revoke for the same id), but store.RevokeToken always still
// runs. Disk itself is what now draws the line between the two cases —
// if it also already shows the token revoked, RevokeToken's own
// auth.ErrTokenAlreadyRevoked says so and this refuses with
// refuseTokenAlreadyRevokedInJournal; if disk still shows the token
// live, RevokeToken applies the mutation this retry exists to complete.
// Any other disk failure — including the first attempt's original
// failure, before any retry — is refused through
// refuseTokenRevokeDiskIncomplete, which says plainly that the journal
// already calls this token dead while tokens.json does not yet agree,
// rather than relaying a bare disk error that leaves that gap unstated.
func runTokenRevoke(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("token revoke", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		flagDataDir string
		flagJournal string
	)
	fs.StringVar(&flagDataDir, "data-dir", "", "Path to bare git repository storage")
	fs.StringVar(&flagJournal, "journal", "", "S3-style URL for write-ahead log in object storage")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printUsage(stdout)
			return nil
		}
		return refusal.Refuse("token revoke refused", err.Error(), "run 'walden help' for usage")
	}

	setFlags := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})

	dataDir, err := resolveDataDir(flagDataDir, setFlags["data-dir"])
	if err != nil {
		return err
	}

	journalURL, err := resolveJournalFlag(flagJournal, setFlags["journal"], dataDir)
	if err != nil {
		return err
	}

	positionals := fs.Args()
	if len(positionals) == 0 || strings.TrimSpace(positionals[0]) == "" {
		return refusal.Refuse(
			"missing token id",
			"no token id specified",
			"provide token id to revoke (e.g. 'walden token revoke <token-id>')",
		)
	}
	if len(positionals) > 1 {
		return refusal.Refuse(
			"unexpected argument",
			positionals[1],
			"expected single token id to revoke",
		)
	}
	tokenID := strings.TrimSpace(positionals[0])

	revokedAt := time.Now().UTC()

	// Journal first, disk second (WALD-33). Bounded the same way
	// runTokenCreate's own journal work is.
	journalCtx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	tj, err := prepareTokenJournal(journalCtx, "token revoke", journalURL, dataDir)
	if err != nil {
		return err
	}
	// journaled is whether this invocation found (or itself just left) a
	// journal row for tokenID — nil in journal-less mode, non-nil
	// otherwise. It gates two things below: whether store.RevokeToken's
	// own ErrTokenAlreadyRevoked gets the journal-flavored refusal or
	// passes through as-is (journal-less mode never mentions a journal it
	// does not have), and whether any other disk failure is reported as
	// an incomplete revoke (round 1 finding 2) rather than a bare error.
	var journaled bool
	if tj != nil {
		row, exists := tj.table.Row(tokenID)
		if !exists {
			return refuseTokenUnknownInJournal(tokenID)
		}
		journaled = true
		if !row.Revoked {
			now := func() time.Time { return revokedAt }
			if _, err := tj.client.AppendTokenRevoke(journalCtx, tj.lease, tj.priv, tj.chain, tokenID, row.TokenHash, now); err != nil {
				return err
			}
		}
	}

	store := auth.NewFileTokenStore(dataDir)
	if err := store.RevokeToken(context.Background(), tokenID, revokedAt); err != nil {
		if journaled && errors.Is(err, auth.ErrTokenAlreadyRevoked) {
			return refuseTokenAlreadyRevokedInJournal(tokenID)
		}
		if journaled {
			return refuseTokenRevokeDiskIncomplete(tokenID, err)
		}
		return err
	}

	fmt.Fprintf(stdout, "revoked token %s\n", tokenID)
	return nil
}
