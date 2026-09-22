// Package main implements walden: a small, self-sufficient git server with a write-ahead log.
package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/config"
	"github.com/writtendev/walden/internal/githttp"
	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
	"github.com/writtendev/walden/internal/store"
)

// Version can be set via ldflags at build time.
var Version = "dev"

// probeTimeout bounds boot-time preflights against object storage — the
// compare-and-swap probe (ProbeCAS) and, when it runs, EnsureGenesis's
// genesis GET plus conditional PUT — and, in rotate.go, the same shape of
// preflight rotate-key performs from a long-lived operator command instead
// of at boot: ReplayMeta's walk of _meta plus the rotation's own append.
// Not a knob: walden's five knobs don't include tuning this, so there is
// no flag or env var. The client's own transport timeouts and retry cap
// bound each individual request anyway; this is a backstop on the whole of
// a walk against an out-of-contract provider — see meta.go's
// maxMetaGrowRetries doc comment for the specific hazard rotate-key's use
// of this bound closes — rather than a single request.
const probeTimeout = 2 * time.Minute

func main() {
	if err := run(context.Background(), os.Args, os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "walden: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return dispatchServe(ctx, nil, stdout, stderr)
	}

	prog := filepath.Base(args[0])

	// Dispatched by argv[0] when executed directly as git hook
	if prog == "pre-receive" {
		return runPreReceive(ctx, args[1:], stdin, stdout, stderr)
	}

	if len(args) < 2 {
		return dispatchServe(ctx, args[1:], stdout, stderr)
	}

	switch args[1] {
	case "serve":
		return dispatchServe(ctx, args[2:], stdout, stderr)
	case "token":
		return runToken(args[2:], stdout, stderr)
	case "rotate-key":
		return runRotateKey(args[2:], stdout, stderr)
	case "pre-receive":
		return runPreReceive(ctx, args[2:], stdin, stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "walden %s\n", Version)
		return nil
	case "help", "--help", "-h":
		printUsage(stdout)
		return nil
	default:
		if strings.HasPrefix(args[1], "-") {
			return dispatchServe(ctx, args[1:], stdout, stderr)
		}
		return refusal.Refuse("unknown command", args[1], "run 'walden help' for usage")
	}
}

// dispatchServe installs the SIGINT/SIGTERM handling that runServe relies on
// to close its listener and return -- scoped to the serve path alone.
// Installing it any earlier (once in main, ahead of the dispatch above)
// would leave every subcommand's process catching those signals whether or
// not it reads ctx: token create/list/revoke and the pre-receive hook don't,
// so a blocked tokens.lock wait would swallow Ctrl-C and SIGTERM instead of
// exiting on them the way the Go default handler does.
func dispatchServe(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runServe(ctx, args, stdout, stderr)
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  walden serve [flags]      Start the walden git server
  walden token <cmd>        Manage authentication tokens
  walden rotate-key [flags] Rotate the server's journal signing key
  walden pre-receive        Execute journal pre-receive hook
  walden version            Show version information

Flags for serve:
  --data-dir PATH       Path to bare git repository storage (default: /data, env: WALDEN_DATA_DIR)
  --journal URL         S3 URL for write-ahead journal (default: off, env: WALDEN_JOURNAL)
  --auth-trust KEY      Public key for delegated token verification (default: off, env: WALDEN_AUTH_TRUST)
  --listen ADDR         HTTP listen address (default: :8470, env: WALDEN_LISTEN_ADDR)
  --print-config        Print resolved configuration and exit

Commands for token:
  create [flags]        Create a new authentication token
  list [flags]          List existing tokens
  revoke [flags] <id>   Revoke an authentication token

Flags for rotate-key:
  --data-dir PATH       Path to bare git repository storage (default: /data, env: WALDEN_DATA_DIR)
  --journal URL         S3 URL for write-ahead journal (required, env: WALDEN_JOURNAL)`)
}

func runServe(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	// Deliberately context.Background(), not ctx: this is a one-off,
	// sub-second preflight check with nothing yet to gracefully stop, and
	// exec.CommandContext refuses to even start a subprocess when handed
	// a context that is already done (as ctx legitimately may be here --
	// see the end-to-end test's use of an already-cancelled ctx to make
	// boot return once it has bound and printed). Tying this check to the
	// shutdown context would make the git-floor probe spuriously fail
	// whenever serve is asked to stop before this line runs.
	gitVer, err := githttp.AssertGitFloor(context.Background(), githttp.MinGitVersion)
	if err != nil {
		return err
	}

	cfg, printConfig, err := config.Load(args)
	if err != nil {
		return err
	}

	// Resolve the journal URL here, at boot, so a malformed WALDEN_JOURNAL
	// stops walden now rather than on the first push. --print-config
	// resolves the location but not the credentials, so an operator can
	// check a URL on a machine that holds no secrets; it still names where
	// the credentials would come from, so it cannot report an unresolved
	// journal that would in fact boot.
	// Named jrnl, not journal: this function also needs the internal/journal
	// package below (leases, MetaStreamID) to build the admin token's
	// journalFn (WALD-33), and a local variable named journal would shadow
	// that package import for the rest of this function.
	var jrnl *store.Journal
	if cfg.JournalURL != "" {
		if printConfig {
			jrnl, err = store.ParseJournalURL(cfg.JournalURL, os.LookupEnv)
		} else {
			jrnl, err = store.ResolveJournal(cfg.JournalURL, os.LookupEnv)
		}
		if err != nil {
			return err
		}
	}

	if printConfig {
		fmt.Fprintln(stdout, cfg.String())
		if jrnl != nil {
			fmt.Fprintln(stdout, jrnl.String())
		}
		return nil
	}

	// The boot-time compare-and-swap probe (WALD-23, spec/journal/v1
	// section 11.6) is the sole enforcement of the CAS requirement: it
	// replaces a hostname pre-flight with two real conditional writes
	// against the real bucket, and doubles as the credentials and
	// reachability check. It runs here, before anything else has side
	// effects (no data dir, no tokens.json, no admin token, no bound
	// port), so a refused probe leaves nothing behind to clean up.
	// Deliberately after the --print-config return above (--print-config
	// makes no request to the bucket) and only when a journal is
	// configured at all (journal-less mode never probes). Like the
	// git-floor check above, this uses context.Background() rather than
	// ctx: it is a bounded, sub-second-to-low-second preflight with
	// nothing yet to gracefully stop, and the end-to-end tests boot with
	// an already-cancelled ctx to make boot return once it has bound and
	// printed - tying the probe to that ctx would make it spuriously fail
	// before it ever reaches the bucket.
	// journalClient is created once, here, when a journal is configured at
	// all, and reused below for EnsureGenesis and (WALD-33) for journaling
	// the first-boot admin token — rather than a fresh store.NewClient(jrnl)
	// at each call site, which is all the pre-WALD-33 code did because it
	// had only one caller after this point.
	var journalClient *store.Client
	if jrnl != nil {
		journalClient = store.NewClient(jrnl)
		probeCtx, cancel := context.WithTimeout(context.Background(), probeTimeout)
		cleanup, err := journalClient.ProbeCAS(probeCtx)
		cancel()
		if cleanup != nil {
			fmt.Fprintf(stderr, "walden: WARNING: %v\n", cleanup)
		}
		if err != nil {
			return err
		}
	}

	// The local repository store needs the data directory in both auth
	// modes, so this refusal is hoisted above the mode branch below rather
	// than living inside it.
	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		return refusal.RefuseWithCause(
			"token store unavailable",
			fmt.Sprintf("cannot create data directory %s: %s", cfg.DataDir, err.Error()),
			"verify the data directory path and permissions",
			auth.ErrStoreUnavailable,
		)
	}

	// The journal's first act is to declare who is writing it (WALD-28,
	// spec/journal/v1 sections 2.1, 3.2): a journal with no genesis record
	// gets one minted here, on first boot; a journal that already has one is
	// adopted rather than overwritten. This runs after ProbeCAS (so a
	// bucket that fails the CAS probe never reaches this point) and after
	// os.MkdirAll above (the minted signing key needs the data directory
	// that just came into being), but still before net.Listen: a refused
	// boot binds no port. Journal-less mode never calls it — the identity
	// is born with the journal, and there is no journal to be born with.
	// Like ProbeCAS above, this deliberately uses context.Background()
	// rather than ctx: it is a bounded, sub-second-to-low-second preflight
	// with nothing yet to gracefully stop, and the end-to-end tests boot
	// with an already-cancelled ctx to make boot return once it has bound
	// and printed — tying this to that ctx would make it spuriously fail
	// before it ever reaches the bucket.
	// signingPriv is set only when jrnl != nil, exactly the condition
	// journalFn below is built under: EnsureGenesis is the one place this
	// process learns the private key active at _meta's head. journalFn
	// (WALD-33) does not also reuse EnsureGenesis's signing chain: it
	// needs the token table ReplayMeta discards (see journalFn's own doc
	// comment below), so it replays _meta a second time through
	// ReplayMetaTable and gets a fresh chain from that call instead.
	var signingPriv ed25519.PrivateKey
	if jrnl != nil {
		genesisCtx, cancel := context.WithTimeout(context.Background(), probeTimeout)
		chain, priv, minted, err := journalClient.EnsureGenesis(genesisCtx, cfg.DataDir, time.Now)
		cancel()
		if err != nil {
			return err
		}
		signingPriv = priv
		outcome := "adopted"
		if minted {
			outcome = "minted"
		}
		fmt.Fprintf(stdout, "journal identity %s: %s\n", outcome, chain.ActiveKey())
	}

	// The authorizer's mode is decided exactly once, here: an empty
	// AuthTrustKey selects the built-in token store, a non-empty one
	// selects delegated capability verification. No other construction
	// site decides which mode is live.
	tokenStore := auth.NewFileTokenStore(cfg.DataDir)
	authorizer, err := auth.NewAuthorizer(cfg.AuthTrustKey, tokenStore)
	if err != nil {
		return err
	}

	// Bind before minting: a boot refused for a busy port has no side
	// effects -- no tokens.json written, and no admin token printed and
	// then thrown away.
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return refusal.RefuseWithCause(
			"listen unavailable",
			err.Error(),
			"choose a free address with --listen or WALDEN_LISTEN_ADDR",
			err,
		)
	}

	// journalFn (WALD-33) is non-nil only when a journal is configured: it
	// journals the first-boot admin token to _meta before EnsureAdminToken
	// commits it to tokenStore, the same journal-then-disk order
	// cmd/walden/token.go's helper gives `walden token create`. It opens
	// its own *journal.Lease on journalClient's registry — a fresh Leases
	// per boot, since this process has appended nothing to _meta yet.
	//
	// Unlike the rest of this function, journalFn does not reuse
	// EnsureGenesis's own replay: it needs the rebuilt token table
	// alongside the chain, so it calls ReplayMetaTable itself.
	// ReplayMeta (genesis.go, out of this ticket's scope to touch) keeps
	// its pre-WALD-33 signature and discards the very table it also
	// builds, so EnsureGenesis's walk has nothing this closure could
	// reuse for that purpose — replaying again is the only option left
	// short of changing genesis.go. This is the same uniqueness pre-check
	// runTokenCreate (token.go) runs against ReplayMetaTable's table
	// before any append, applied here to close round 1 finding 1: without
	// it, a first-boot admin mint landing on a local store that is empty
	// only because it was emptied after an earlier boot already journaled
	// AdminTokenID (a lost or never-written tokens.json, a restore onto
	// an empty data directory, or a first boot whose disk half failed or
	// whose append outcome was unprovable) appends a second token_create
	// for the same constant id and poisons every future replay under spec
	// section 8.1 rule 10 — recoverable only by hand-editing the bucket.
	//
	// When the table already carries AdminTokenID, journalFn refuses
	// under auth.ErrTokenExists without opening a lease or appending:
	// EnsureAdminToken already treats that sentinel as "someone else
	// already has this" (the existing lost-race handling around
	// store.CreateToken), extended here to the journal side, so boot
	// proceeds without minting or printing a token rather than refusing
	// forever — an operator meeting this is left with a working server,
	// not a bricked one. Because EnsureAdminToken swallows that error
	// (the same swallow the disk-side race already gets), the one place
	// left to tell the operator anything happened is here, so this prints
	// a WARNING to stderr naming the real next step: mint a fresh,
	// differently-identified token with `walden token create` once boot
	// completes. The original admin token's raw value cannot be
	// recovered — only its hash was ever journaled — but a new credential
	// with equivalent rwc:* scope can be minted under a different id.
	//
	// Like ProbeCAS and EnsureGenesis above, this ignores the ctx
	// EnsureAdminToken hands it and uses its own bounded
	// context.Background(), for the identical reason those two give: this
	// runs during boot, before anything has a reason to gracefully stop,
	// and the end-to-end tests boot with an already-cancelled ctx to make
	// boot return once it has bound and printed — tying this call to that
	// ctx would make it spuriously fail before it ever reaches the bucket.
	var journalFn func(context.Context, *auth.TokenRecord) error
	if journalClient != nil {
		leases := journal.NewLeases(journalClient)
		journalFn = func(_ context.Context, rec *auth.TokenRecord) error {
			journalCtx, cancel := context.WithTimeout(context.Background(), probeTimeout)
			defer cancel()
			chain, table, err := journalClient.ReplayMetaTable(journalCtx)
			if err != nil {
				return err
			}
			if _, exists := table.Row(rec.TokenID); exists {
				fmt.Fprintf(stderr, "walden: WARNING: the journal already holds a token_create for id %q; not minting a duplicate admin token. Run 'walden token create' once boot completes to mint a new credential.\n", rec.TokenID)
				return refuseAdminTokenAlreadyJournaled(rec.TokenID)
			}
			lease, err := leases.Open(journalCtx, journal.MetaStreamID)
			if err != nil {
				return err
			}
			scopes := make([]string, len(rec.Scopes))
			for i, s := range rec.Scopes {
				scopes[i] = s.String()
			}
			_, err = journalClient.AppendTokenCreate(journalCtx, lease, signingPriv, chain, rec.TokenID, rec.TokenHash, scopes, time.Now)
			return err
		}
	}

	if cfg.AuthTrustKey == "" {
		adminToken, err := auth.EnsureAdminToken(ctx, tokenStore, journalFn)
		if err != nil {
			ln.Close()
			return err
		}
		if adminToken != "" {
			fmt.Fprintf(stdout, "admin token: %s\n", adminToken)
		}
	}

	if cfg.JournalURL == "" {
		fmt.Fprintln(stderr, "walden: WARNING: journal-less mode: WALDEN_JOURNAL is unset, so durability is this disk alone")
	}

	// cfg.ListenAddr already passed config.Validate's net.SplitHostPort
	// check, so the host is well-formed here. Printing
	// net.JoinHostPort(host, <bound port>) rather than cfg.ListenAddr
	// itself means a fixed address like ":8470" still prints ":8470", and
	// a ":0"-style address prints the port the kernel actually chose.
	host, _, _ := net.SplitHostPort(cfg.ListenAddr)
	boundAddr := net.JoinHostPort(host, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	fmt.Fprintf(stdout, "walden server starting on %s (data: %s, git: %s)\n", boundAddr, cfg.DataDir, gitVer)

	h := githttp.NewHandler(authorizer, store.New(cfg.DataDir), cfg.JournalURL)
	// IdleTimeout closes keep-alive connections that go quiet, so an
	// unauthenticated client can't pin a file descriptor forever by
	// opening a connection and never sending a second request.
	// ReadTimeout/WriteTimeout are deliberately unset: git transfers
	// can legitimately run long once a request is underway.
	srv := &http.Server{Handler: h, ReadHeaderTimeout: time.Minute, IdleTimeout: time.Minute}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return refusal.RefuseWithCause("serve failed", err.Error(), "check the listen address", err)
	}
	return nil
}

// runPreReceive implements walden dispatched as git's pre-receive hook
// (WALD-43): it parses the old/new/ref triples git writes to stdin, then
// resolves the repository, data directory, and journal purely from the
// environment internal/githttp/receivepack.go sets, and stops there.
// args is unused -- the hook takes no flags, only stdin and environment,
// the same shape git itself invokes it with.
//
// Stdin at EOF with no lines parsed exits 0 without resolving anything
// from the environment: there is nothing to look up a repository, data
// directory, or journal for. This is what keeps `walden pre-receive` (or
// the pre-receive symlink) harmless to invoke by hand with no
// WALDEN_REPO/WALDEN_DATA_DIR set, exactly the shape the argv-dispatch
// tests use to prove the dispatch itself works.
//
// Deliberately not done here: appending anything to the journal. A green
// WALD-43 exits 0 having parsed and resolved, and nothing more --
// journaling the quarantined packfile is WALD-44, and making exit 0 depend
// on that append landing is WALD-46.
func runPreReceive(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	updates, err := parseRefUpdates(stdin)
	if err != nil {
		return err
	}
	if len(updates) == 0 {
		return nil
	}
	if _, err := resolveHook(ctx, os.LookupEnv, updates); err != nil {
		return err
	}
	return nil
}

// refuseAdminTokenAlreadyJournaled refuses to mint a first-boot admin
// token when the journal's rebuilt token table already carries
// auth.AdminTokenID: appending another token_create for the same
// constant id would reuse a token_id the journal already holds, which
// spec section 8.1 rule 10 refuses on every future replay (round 1
// finding 1). Wrapped under auth.ErrTokenExists so EnsureAdminToken's
// existing lost-race handling around store.CreateToken applies here too
// — the error is swallowed there, not surfaced as a boot failure, so
// this refusal's own text is never shown to an operator; the WARNING at
// this function's one call site (runServe) is what an operator actually
// sees, since it fires whether or not this returned error's shape ever
// changes.
func refuseAdminTokenAlreadyJournaled(tokenID string) error {
	return refusal.RefuseWithCause(
		"admin token refused",
		fmt.Sprintf("token id %q already exists in the journal", tokenID),
		"mint a differently-identified token with 'walden token create' once boot completes",
		auth.ErrTokenExists,
	)
}
