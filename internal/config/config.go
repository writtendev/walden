// Package config manages configuration for walden.
// Per ARCHITECTURE.md, config imports nothing internal.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Default configuration values.
const (
	DefaultDataDir    = "/data"
	DefaultListenAddr = ":8470"
)

// Environment variable names.
const (
	EnvDataDir    = "WALDEN_DATA_DIR"
	EnvJournal    = "WALDEN_JOURNAL"
	EnvAuthTrust  = "WALDEN_AUTH_TRUST"
	EnvListenAddr = "WALDEN_LISTEN_ADDR"
	EnvListen     = "WALDEN_LISTEN"
)

// Config represents walden's five knobs.
type Config struct {
	// DataDir is where bare git repositories (the cache) live.
	DataDir string

	// JournalURL is the S3-style URL for object storage.
	// Empty indicates journal-less mode.
	JournalURL string

	// AuthTrustKey is the public key for delegated capability token verification.
	// Empty indicates built-in token mode.
	AuthTrustKey string

	// ListenAddr is the HTTP listen address (e.g. ":8470").
	ListenAddr string
}

// String returns a human-readable representation of the resolved configuration.
//
// The journal URL itself is never rendered. It may carry an object-storage
// secret, and deciding which parts of it are safe to print is the rule
// internal/store already owns, in guardCredentials: a second, weaker copy here
// printed most of a MinIO password whose secret held an unencoded '/'. So this
// says only whether the journal is on, and walden serve --print-config prints
// the resolved provider, endpoint, region, bucket, prefix, style, and
// credential source from store.Journal.String(), all of them past that gate.
func (c *Config) String() string {
	journal := "(configured)"
	if c.JournalURL == "" {
		journal = "(disabled)"
	}
	authTrust := c.AuthTrustKey
	if authTrust == "" {
		authTrust = "(builtin)"
	}
	return fmt.Sprintf("data-dir: %s\njournal: %s\nauth-trust: %s\nlisten: %s",
		c.DataDir,
		journal,
		authTrust,
		c.ListenAddr,
	)
}

// refuseWhitespaceJournal refuses a journal value that was given but holds
// nothing but whitespace.
//
// Trimming alone would make it indistinguishable from unset, and unset means
// journal-less: walden would boot without durability and say nothing. A
// Kubernetes secret file holding one newline, or a Helm value that renders
// blank, is a mistake, not a decision to run without a journal — and walden's
// first promise is that an acknowledged push is in the journal. Journal-less
// mode stays reachable by leaving the knob unset, deliberately.
func refuseWhitespaceJournal(raw string) error {
	if raw == "" || strings.TrimSpace(raw) != "" {
		return nil
	}
	return errors.New("invalid journal: value is only whitespace (give a URL such as s3://bucket/prefix, or leave the journal unset for journal-less mode)")
}

// Validate checks that all runtime configuration values are valid.
// Every invalid value produces a single-line error naming the knob.
func (c *Config) Validate() error {
	if c.DataDir == "" {
		return errors.New("invalid data-dir: cannot be empty")
	}

	if err := refuseWhitespaceJournal(c.JournalURL); err != nil {
		return err
	}

	// A journal URL is trimmed before it is read. A value out of a file-backed
	// secret or a .env line arrives with a trailing newline more often than it
	// arrives malformed, and Validate runs before the deep parse in
	// internal/store, so the trim there would never see it.
	if journal := strings.TrimSpace(c.JournalURL); journal != "" {
		// net/url's parse errors quote the whole URL back, userinfo and
		// all, so the reason is reported without it. The journal URL may
		// carry an object-storage secret, and stderr is a container log.
		u, err := url.Parse(journal)
		if err != nil {
			return errors.New("invalid journal: URL is malformed; it is not echoed because it may carry credentials (expected s3://bucket/path)")
		}
		if u.Scheme == "" {
			return errors.New("invalid journal: missing URL scheme (e.g. s3://bucket/path)")
		}
	}

	if c.AuthTrustKey != "" {
		if strings.TrimSpace(c.AuthTrustKey) == "" {
			return errors.New("invalid auth-trust: key cannot be empty or whitespace")
		}
	}

	if c.ListenAddr == "" {
		return errors.New("invalid listen: cannot be empty")
	}

	_, portStr, err := net.SplitHostPort(c.ListenAddr)
	if err != nil {
		return fmt.Errorf("invalid listen: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid listen: port must be between 1 and 65535, got %q", portStr)
	}

	return nil
}

// Load loads and resolves configuration from CLI arguments, environment variables,
// and defaults according to the precedence order: Flag > Environment > Default.
// It also validates the resolved configuration.
func Load(args []string) (*Config, bool, error) {
	return LoadWithEnv(args, os.LookupEnv)
}

// LoadWithEnv loads and resolves configuration using the provided environment lookup function.
func LoadWithEnv(args []string, lookupEnv func(string) (string, bool)) (*Config, bool, error) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		flagDataDir     string
		flagJournal     string
		flagAuthTrust   string
		flagListen      string
		flagListenAddr  string
		flagPrintConfig bool
	)

	fs.StringVar(&flagDataDir, "data-dir", "", "where bare git repositories (the cache) live")
	fs.StringVar(&flagJournal, "journal", "", "S3-style URL for write-ahead log in object storage")
	fs.StringVar(&flagAuthTrust, "auth-trust", "", "public key for delegated capability token verification")
	fs.StringVar(&flagListen, "listen", "", "HTTP listen address")
	fs.StringVar(&flagListenAddr, "listen-addr", "", "HTTP listen address (alias for --listen)")
	fs.BoolVar(&flagPrintConfig, "print-config", false, "print resolved configuration and exit")

	if err := fs.Parse(args); err != nil {
		return nil, false, err
	}

	// Track which flags were explicitly specified on the CLI.
	setFlags := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})

	cfg := &Config{
		DataDir:    DefaultDataDir,
		ListenAddr: DefaultListenAddr,
	}

	// 1. DataDir: Flag > WALDEN_DATA_DIR > DefaultDataDir
	if setFlags["data-dir"] {
		cfg.DataDir = flagDataDir
	} else if val, ok := lookupEnv(EnvDataDir); ok && val != "" {
		cfg.DataDir = val
	}

	// 2. JournalURL: Flag > WALDEN_JOURNAL > ""
	// Trimmed once, here, so that every later reader — Validate, String,
	// and the deep parse in internal/store — sees the same value. A value
	// that was given and is only whitespace is refused rather than trimmed
	// down to unset; see refuseWhitespaceJournal.
	if setFlags["journal"] {
		if err := refuseWhitespaceJournal(flagJournal); err != nil {
			return nil, flagPrintConfig, err
		}
		cfg.JournalURL = strings.TrimSpace(flagJournal)
	} else if val, ok := lookupEnv(EnvJournal); ok && val != "" {
		if err := refuseWhitespaceJournal(val); err != nil {
			return nil, flagPrintConfig, err
		}
		cfg.JournalURL = strings.TrimSpace(val)
	}

	// 3. AuthTrustKey: Flag > WALDEN_AUTH_TRUST > ""
	if setFlags["auth-trust"] {
		cfg.AuthTrustKey = flagAuthTrust
	} else if val, ok := lookupEnv(EnvAuthTrust); ok && val != "" {
		cfg.AuthTrustKey = val
	}

	// 4. ListenAddr: Flag > WALDEN_LISTEN_ADDR / WALDEN_LISTEN > DefaultListenAddr
	if setFlags["listen"] {
		cfg.ListenAddr = flagListen
	} else if setFlags["listen-addr"] {
		cfg.ListenAddr = flagListenAddr
	} else if val, ok := lookupEnv(EnvListenAddr); ok && val != "" {
		cfg.ListenAddr = val
	} else if val, ok := lookupEnv(EnvListen); ok && val != "" {
		cfg.ListenAddr = val
	}

	if err := cfg.Validate(); err != nil {
		return nil, flagPrintConfig, err
	}

	return cfg, flagPrintConfig, nil
}

// LoadFromEnv loads configuration from environment variables with defaults.
func LoadFromEnv() *Config {
	cfg, _, _ := LoadWithEnv(nil, os.LookupEnv)
	if cfg == nil {
		return &Config{
			DataDir:    DefaultDataDir,
			ListenAddr: DefaultListenAddr,
		}
	}
	return cfg
}
