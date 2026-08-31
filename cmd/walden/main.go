// Package main implements walden: a small, self-sufficient git server with a write-ahead log.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/writtendev/walden/internal/config"
)

// Version can be set via ldflags at build time.
var Version = "dev"

func main() {
	if err := run(os.Args, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "walden: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return runServe(nil, stdout, stderr)
	}

	prog := filepath.Base(args[0])

	// Dispatched by argv[0] when executed directly as git hook
	if prog == "pre-receive" {
		return runPreReceive(args[1:], stdout, stderr)
	}

	if len(args) < 2 {
		return runServe(args[1:], stdout, stderr)
	}

	switch args[1] {
	case "serve":
		return runServe(args[2:], stdout, stderr)
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
		return fmt.Errorf("unknown command: %s (run 'walden help' for usage)", args[1])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  walden serve         Start the walden git server
  walden token <cmd>   Manage authentication tokens
  walden pre-receive   Execute journal pre-receive hook
  walden version       Show version information`)
}

func runServe(args []string, stdout, stderr io.Writer) error {
	cfg := config.LoadFromEnv()
	fmt.Fprintf(stdout, "walden server starting on %s (data: %s)\n", cfg.ListenAddr, cfg.DataDir)
	return nil
}

func runToken(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("missing token subcommand (create, list, revoke)")
	}
	switch args[0] {
	case "create", "list", "revoke":
		fmt.Fprintf(stdout, "walden token %s: not yet implemented\n", args[0])
		return nil
	default:
		return fmt.Errorf("unknown token subcommand: %s (expected create, list, or revoke)", args[0])
	}
}

func runPreReceive(args []string, stdout, stderr io.Writer) error {
	// Journal hook dispatched during git receive-pack push
	return nil
}
