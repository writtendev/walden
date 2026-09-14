package main

import (
	"context"
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

func runTokenCreate(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("token create", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		flagDataDir   string
		flagID        string
		flagAuthTrust string
		allows        allowList
	)

	fs.StringVar(&flagDataDir, "data-dir", "", "Path to bare git repository storage")
	fs.StringVar(&flagID, "id", "", "Custom token identifier")
	fs.StringVar(&flagAuthTrust, "auth-trust", "", "Public key for delegated capability token verification")
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

	record := &auth.TokenRecord{
		TokenID:   tokenID,
		TokenHash: tokenHash,
		Scopes:    scopes,
		CreatedAt: time.Now().UTC(),
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

func runTokenRevoke(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("token revoke", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var flagDataDir string
	fs.StringVar(&flagDataDir, "data-dir", "", "Path to bare git repository storage")

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

	store := auth.NewFileTokenStore(dataDir)
	if err := store.RevokeToken(context.Background(), tokenID, time.Now().UTC()); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "revoked token %s\n", tokenID)
	return nil
}
