package config_test

import (
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/config"
)

func TestConfigDefaults(t *testing.T) {
	emptyEnv := func(string) (string, bool) { return "", false }
	cfg, printConfig, err := config.LoadWithEnv(nil, emptyEnv)
	if err != nil {
		t.Fatalf("unexpected error with defaults: %v", err)
	}
	if printConfig {
		t.Errorf("expected printConfig to be false, got true")
	}

	if cfg.DataDir != config.DefaultDataDir {
		t.Errorf("expected DataDir %q, got %q", config.DefaultDataDir, cfg.DataDir)
	}
	if cfg.JournalURL != "" {
		t.Errorf("expected empty JournalURL, got %q", cfg.JournalURL)
	}
	if cfg.AuthTrustKey != "" {
		t.Errorf("expected empty AuthTrustKey, got %q", cfg.AuthTrustKey)
	}
	if cfg.ListenAddr != config.DefaultListenAddr {
		t.Errorf("expected ListenAddr %q, got %q", config.DefaultListenAddr, cfg.ListenAddr)
	}

	expectedStr := "data-dir: /data\njournal: (disabled)\nauth-trust: (builtin)\nlisten: :8470"
	if cfg.String() != expectedStr {
		t.Errorf("expected cfg.String() %q, got %q", expectedStr, cfg.String())
	}
}

func TestConfigPrecedence(t *testing.T) {
	env := map[string]string{
		config.EnvDataDir:    "/env/data",
		config.EnvJournal:    "s3://env-bucket/walden",
		config.EnvAuthTrust:  "env-key-12345",
		config.EnvListenAddr: ":9000",
	}
	lookupEnv := func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}

	// 1. Env overrides defaults
	cfg, _, err := config.LoadWithEnv(nil, lookupEnv)
	if err != nil {
		t.Fatalf("unexpected error loading env: %v", err)
	}
	if cfg.DataDir != "/env/data" {
		t.Errorf("expected DataDir /env/data, got %q", cfg.DataDir)
	}
	if cfg.JournalURL != "s3://env-bucket/walden" {
		t.Errorf("expected JournalURL s3://env-bucket/walden, got %q", cfg.JournalURL)
	}
	if cfg.AuthTrustKey != "env-key-12345" {
		t.Errorf("expected AuthTrustKey env-key-12345, got %q", cfg.AuthTrustKey)
	}
	if cfg.ListenAddr != ":9000" {
		t.Errorf("expected ListenAddr :9000, got %q", cfg.ListenAddr)
	}

	// 2. Flags override env vars and defaults
	args := []string{
		"--data-dir", "/cli/data",
		"--journal", "s3://cli-bucket/walden",
		"--auth-trust", "cli-key-67890",
		"--listen", ":9999",
		"--print-config",
	}
	cfg, printConfig, err := config.LoadWithEnv(args, lookupEnv)
	if err != nil {
		t.Fatalf("unexpected error loading flags: %v", err)
	}
	if !printConfig {
		t.Errorf("expected printConfig to be true")
	}
	if cfg.DataDir != "/cli/data" {
		t.Errorf("expected DataDir /cli/data, got %q", cfg.DataDir)
	}
	if cfg.JournalURL != "s3://cli-bucket/walden" {
		t.Errorf("expected JournalURL s3://cli-bucket/walden, got %q", cfg.JournalURL)
	}
	if cfg.AuthTrustKey != "cli-key-67890" {
		t.Errorf("expected AuthTrustKey cli-key-67890, got %q", cfg.AuthTrustKey)
	}
	if cfg.ListenAddr != ":9999" {
		t.Errorf("expected ListenAddr :9999, got %q", cfg.ListenAddr)
	}

	expectedStr := "data-dir: /cli/data\njournal: s3://cli-bucket/walden\nauth-trust: cli-key-67890\nlisten: :9999"
	if cfg.String() != expectedStr {
		t.Errorf("expected cfg.String() %q, got %q", expectedStr, cfg.String())
	}
}

func TestConfigListenAliases(t *testing.T) {
	// WALDEN_LISTEN alias
	env := map[string]string{config.EnvListen: ":8080"}
	cfg, _, err := config.LoadWithEnv(nil, func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("expected ListenAddr :8080, got %q", cfg.ListenAddr)
	}

	// --listen-addr flag alias
	cfg, _, err = config.LoadWithEnv([]string{"--listen-addr", ":8081"}, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ListenAddr != ":8081" {
		t.Errorf("expected ListenAddr :8081, got %q", cfg.ListenAddr)
	}
}

func TestConfigValidationErrors(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		wantErrSub string
	}{
		{
			name:       "empty-data-dir-flag",
			args:       []string{"--data-dir", ""},
			wantErrSub: "invalid data-dir: cannot be empty",
		},
		{
			name:       "invalid-journal-no-scheme",
			args:       []string{"--journal", "no-scheme-bucket/path"},
			wantErrSub: "invalid journal: missing URL scheme",
		},
		{
			name:       "invalid-journal-bad-url",
			args:       []string{"--journal", "://invalid-url"},
			wantErrSub: "invalid journal:",
		},
		{
			name:       "invalid-auth-trust-whitespace",
			args:       []string{"--auth-trust", "   "},
			wantErrSub: "invalid auth-trust: key cannot be empty or whitespace",
		},
		{
			name:       "invalid-listen-empty",
			args:       []string{"--listen", ""},
			wantErrSub: "invalid listen: cannot be empty",
		},
		{
			name:       "invalid-listen-missing-port",
			args:       []string{"--listen", "localhost"},
			wantErrSub: "invalid listen:",
		},
		{
			name:       "invalid-listen-port-out-of-range",
			args:       []string{"--listen", ":70000"},
			wantErrSub: "invalid listen: port must be between 1 and 65535",
		},
		{
			name:       "invalid-listen-non-numeric-port",
			args:       []string{"--listen", ":abc"},
			wantErrSub: "invalid listen: port must be between 1 and 65535",
		},
		{
			name: "invalid-env-listen",
			env: map[string]string{
				config.EnvListenAddr: "bad-addr",
			},
			wantErrSub: "invalid listen:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookupEnv := func(key string) (string, bool) {
				if tt.env == nil {
					return "", false
				}
				v, ok := tt.env[key]
				return v, ok
			}
			_, _, err := config.LoadWithEnv(tt.args, lookupEnv)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErrSub)
			}
			if !strings.Contains(err.Error(), tt.wantErrSub) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErrSub)
			}
			// Verify error is a single line
			if strings.Contains(err.Error(), "\n") {
				t.Errorf("expected single-line error, got: %q", err.Error())
			}
		})
	}
}

func TestLoadFromEnvFallback(t *testing.T) {
	cfg := config.LoadFromEnv()
	if cfg == nil {
		t.Fatal("expected non-nil config from LoadFromEnv")
	}
	if cfg.DataDir == "" || cfg.ListenAddr == "" {
		t.Errorf("expected non-empty defaults in LoadFromEnv: %+v", cfg)
	}
}
