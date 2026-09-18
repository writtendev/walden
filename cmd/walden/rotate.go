package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
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
// The --journal / WALDEN_JOURNAL knob's precedence and refusals are
// resolved by handing config.Load the exact flag this command's own
// --journal parse captured, rather than reimplementing that resolution
// here (round 1 minor finding): the earlier version of this function
// collapsed an explicitly empty --journal and a whitespace-only value into
// the same generic "no journal configured" refusal meant for an unset
// knob, so `walden rotate-key --journal "$UNSET_VAR"` told the operator to
// set a flag they had just set, and gave a different answer than `walden
// serve` would for the identical input. config.Load already carries both
// of those refusals (config.go: the explicit-empty check ahead of
// refuseWhitespaceJournal) for the one command that already resolves this
// knob correctly; only --journal is threaded through, not --data-dir,
// which resolveDataDir below continues to resolve on its own (token.go) --
// this does not also change data-dir's refusal wording, and reuses no
// flag rotate-key does not already define, so the five-knob surface is
// unchanged.
//
// A missing journal is still a one-line refusal: there is nothing to
// rotate in journal-less mode, since the signing identity is born with the
// journal (spec/journal/v1 section 2.1) and journal-less walden never has
// one.
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

	// Only --journal is passed through to config.Load, and only when this
	// command's own parse found it explicitly set -- fs.Visit here is what
	// proves an empty value was typed rather than left unset, the same
	// proof config.Load's own fs.Visit relies on for the explicit-empty
	// refusal. An unset --journal leaves configArgs empty, so config.Load
	// falls through to its own WALDEN_JOURNAL / "" resolution unchanged.
	var configArgs []string
	if setFlags["journal"] {
		configArgs = append(configArgs, "--journal", flagJournal)
	}
	cfg, _, err := config.Load(configArgs)
	if err != nil {
		return err
	}
	journalURL := cfg.JournalURL
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
