package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/writtendev/walden/internal/config"
	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
	"github.com/writtendev/walden/internal/store"
)

// runRotateKey implements `walden rotate-key`: it appends a key_rotation
// record to _meta and swaps the local signing.key to the new key, through
// (*store.Client).RotateKey (internal/store/rotation.go). It takes the same
// --data-dir and --journal flags runServe does, with the same
// WALDEN_DATA_DIR/WALDEN_JOURNAL fallbacks and the same
// store.ResolveJournal path -- this adds an operator command, not a
// configuration knob: no new flag or environment variable joins the five
// walden already has.
//
// A missing journal is a one-line refusal: there is nothing to rotate in
// journal-less mode, since the signing identity is born with the journal
// (spec/journal/v1 section 2.1) and journal-less walden never has one.
func runRotateKey(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("rotate-key", flag.ContinueOnError)
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
		return refusal.Refuse("rotate-key refused", err.Error(), "run 'walden help' for usage")
	}
	if len(fs.Args()) > 0 {
		return refusal.Refuse("unexpected argument", fs.Args()[0], "rotate-key accepts flags only")
	}

	setFlags := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})

	dataDir, err := resolveDataDir(flagDataDir, setFlags["data-dir"])
	if err != nil {
		return err
	}

	journalURL := os.Getenv(config.EnvJournal)
	if setFlags["journal"] {
		journalURL = flagJournal
	}
	journalURL = strings.TrimSpace(journalURL)
	if journalURL == "" {
		return refusal.Refuse(
			"rotate-key refused",
			"no journal configured",
			"set --journal or WALDEN_JOURNAL; there is nothing to rotate in journal-less mode",
		)
	}

	j, err := store.ResolveJournal(journalURL, os.LookupEnv)
	if err != nil {
		return err
	}

	c := store.NewClient(j)
	leases := journal.NewLeases(c)

	retired, active, err := c.RotateKey(context.Background(), dataDir, leases, time.Now)
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "key rotated: retired %s, active %s\n", retired, active)
	return nil
}
