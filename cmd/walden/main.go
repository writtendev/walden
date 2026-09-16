// Package main implements walden: a small, self-sufficient git server with a write-ahead log.
package main

import (
	"context"
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
	"github.com/writtendev/walden/internal/refusal"
	"github.com/writtendev/walden/internal/store"
)

// Version can be set via ldflags at build time.
var Version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "walden: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return runServe(ctx, nil, stdout, stderr)
	}

	prog := filepath.Base(args[0])

	// Dispatched by argv[0] when executed directly as git hook
	if prog == "pre-receive" {
		return runPreReceive(args[1:], stdout, stderr)
	}

	if len(args) < 2 {
		return runServe(ctx, args[1:], stdout, stderr)
	}

	switch args[1] {
	case "serve":
		return runServe(ctx, args[2:], stdout, stderr)
	case "token":
		return runToken(args[2:], stdout, stderr)
	case "pre-receive":
		return runPreReceive(args[2:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "walden %s\n", Version)
		return nil
	case "help", "--help", "-h":
		printUsage(stdout)
		return nil
	default:
		if strings.HasPrefix(args[1], "-") {
			return runServe(ctx, args[1:], stdout, stderr)
		}
		return refusal.Refuse("unknown command", args[1], "run 'walden help' for usage")
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  walden serve [flags]  Start the walden git server
  walden token <cmd>    Manage authentication tokens
  walden pre-receive    Execute journal pre-receive hook
  walden version        Show version information

Flags for serve:
  --data-dir PATH       Path to bare git repository storage (default: /data, env: WALDEN_DATA_DIR)
  --journal URL         S3 URL for write-ahead journal (default: off, env: WALDEN_JOURNAL)
  --auth-trust KEY      Public key for delegated token verification (default: off, env: WALDEN_AUTH_TRUST)
  --listen ADDR         HTTP listen address (default: :8470, env: WALDEN_LISTEN_ADDR)
  --print-config        Print resolved configuration and exit

Commands for token:
  create [flags]        Create a new authentication token
  list [flags]          List existing tokens
  revoke [flags] <id>   Revoke an authentication token`)
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
	var journal *store.Journal
	if cfg.JournalURL != "" {
		if printConfig {
			journal, err = store.ParseJournalURL(cfg.JournalURL, os.LookupEnv)
		} else {
			journal, err = store.ResolveJournal(cfg.JournalURL, os.LookupEnv)
		}
		if err != nil {
			return err
		}
	}

	if printConfig {
		fmt.Fprintln(stdout, cfg.String())
		if journal != nil {
			fmt.Fprintln(stdout, journal.String())
		}
		return nil
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

	if cfg.AuthTrustKey == "" {
		adminToken, err := auth.EnsureAdminToken(ctx, tokenStore)
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
	srv := &http.Server{Handler: h, ReadHeaderTimeout: time.Minute}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return refusal.RefuseWithCause("serve failed", err.Error(), "check the listen address", err)
	}
	return nil
}

func runPreReceive(args []string, stdout, stderr io.Writer) error {
	// Journal hook dispatched during git receive-pack push
	return nil
}
