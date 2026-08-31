// Package config manages configuration for walden.
// Per ARCHITECTURE.md, config imports nothing internal.
package config

import (
	"os"
)

// Default configuration values.
const (
	DefaultDataDir    = "/data"
	DefaultListenAddr = ":8470"
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

// LoadFromEnv loads configuration from environment variables with defaults.
func LoadFromEnv() *Config {
	cfg := &Config{
		DataDir:    DefaultDataDir,
		ListenAddr: DefaultListenAddr,
	}

	if val := os.Getenv("WALDEN_DATA_DIR"); val != "" {
		cfg.DataDir = val
	}
	if val := os.Getenv("WALDEN_JOURNAL"); val != "" {
		cfg.JournalURL = val
	}
	if val := os.Getenv("WALDEN_AUTH_TRUST"); val != "" {
		cfg.AuthTrustKey = val
	}
	if val := os.Getenv("WALDEN_LISTEN_ADDR"); val != "" {
		cfg.ListenAddr = val
	}

	return cfg
}
