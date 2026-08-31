// Package main implements walden: a small, self-sufficient git server with a write-ahead log.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/writtendev/walden/internal/config"
)

func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "walden: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	prog := filepath.Base(args[0])

	// Dispatched by argv[0] when executed directly as git hook
	if prog == "pre-receive" {
		return runPreReceive(args[1:])
	}

	if len(args) < 2 {
		return runServe(args[1:])
	}

	switch args[1] {
	case "serve":
		return runServe(args[2:])
	case "token":
		return runToken(args[2:])
	case "pre-receive":
		return runPreReceive(args[2:])
	case "version", "--version", "-v":
		fmt.Println("walden dev")
		return nil
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command: %s (run 'walden help' for usage)", args[1])
	}
}

func printUsage() {
	fmt.Println(`Usage:
  walden serve         Start the walden git server
  walden token <cmd>   Manage authentication tokens
  walden pre-receive   Execute journal pre-receive hook
  walden version       Show version information`)
}

func runServe(args []string) error {
	cfg := config.LoadFromEnv()
	fmt.Printf("walden server starting on %s (data: %s)\n", cfg.ListenAddr, cfg.DataDir)
	return nil
}

func runToken(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing token subcommand (create, list, revoke)")
	}
	switch args[0] {
	case "create", "list", "revoke":
		fmt.Printf("walden token %s: not yet implemented\n", args[0])
		return nil
	default:
		return fmt.Errorf("unknown token subcommand: %s", args[0])
	}
}

func runPreReceive(args []string) error {
	// Journal hook dispatched during git receive-pack push
	return nil
}
