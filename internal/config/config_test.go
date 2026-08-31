package config_test

import (
	"testing"

	"github.com/writtendev/walden/internal/config"
)

func TestConfigDefaults(t *testing.T) {
	cfg := config.LoadFromEnv()
	if cfg.DataDir == "" {
		t.Error("expected default DataDir to be non-empty")
	}
	if cfg.ListenAddr == "" {
		t.Error("expected default ListenAddr to be non-empty")
	}
}
