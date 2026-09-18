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
//
// Sharing config.Load also means sharing its Validate call, which checks
// --listen, --auth-trust, and --data-dir alongside --journal -- three
// knobs this command does not use the returned *Config for at all. See the
// comment beside configArgs below (round 2 minor finding) for how those
// three are kept from ever being able to fail Validate on this command's
// behalf.
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
	// config.Load's Validate also checks --listen, --auth-trust, and
	// --data-dir -- three knobs rotate-key neither binds nor reads from
	// the *Config it gets back (dataDir above already comes from
	// resolveDataDir, not cfg.DataDir). Left to their own environment
	// fallbacks, those three can still fail Validate on nothing rotate-key
	// itself did wrong: a stray WALDEN_LISTEN=8080 or a whitespace-only
	// WALDEN_AUTH_TRUST, plausible on a host that also runs `walden
	// serve`, would otherwise block a key rotation with a refusal about a
	// port rotate-key never binds (round 2 minor finding). Validate has no
	// per-knob mode, and config.Load returns a nil *Config on any failure
	// -- there would be no cfg left to pull JournalURL from even if the
	// failure were caught and filtered afterward -- so the fix has to keep
	// those three from ever reaching Validate in a state that could fail
	// it, not react to the failure once it happens. Passing an
	// always-valid literal for each, explicitly, on every call (a flag
	// always outranks its environment variable in config.Load) does that:
	// this command never reads cfg.AuthTrustKey or cfg.ListenAddr at all,
	// and cfg.DataDir here is thrown away in favor of resolveDataDir's own
	// result above, so which literal wins is immaterial -- only whichever
	// --journal value setFlags["journal"] contributed above still comes
	// from the operator, and internal/config/config.go itself is untouched
	// (it is not in this ticket's owned files).
	configArgs = append(configArgs,
		"--auth-trust", "unused",
		"--listen", config.DefaultListenAddr,
		"--data-dir", dataDir,
	)
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
