package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
	"github.com/writtendev/walden/internal/store"
)

// hookRequest is the parsed shape of one pre-receive invocation: the
// environment resolveHook read (WALD-43) plus the ref updates
// parseRefUpdates read off stdin. WALD-44 adds the quarantine path and the
// captured pack segment; WALD-46 makes the exit code depend on whether the
// journal append landed. Nothing else needs to grow.
type hookRequest struct {
	Repo     string         // WALDEN_REPO
	DataDir  string         // WALDEN_DATA_DIR
	RepoPath string         // resolved bare repo path
	Journal  *store.Journal // nil in journal-less mode
	Updates  []journal.RefUpdate
}

// parseRefUpdates reads git's pre-receive stdin protocol: one
// "<old-oid> SP <new-oid> SP <ref-name>" triple per line. Spec §5.2
// forbids a space in a ref name (ValidateRefName below refuses one as a
// control/whitespace character), so splitting on the first two spaces only
// is exact: everything after the second space is the ref name, taken
// verbatim, with no trimming or normalization, preserving its raw bytes.
//
// Each triple is checked with journal.ValidateRefUpdate, which already
// composes the ref name, OID shape, mismatched-length, zero-to-zero, and
// no-op rules, and the set as a whole is checked for a duplicate ref name,
// which spec §5.1 refuses. scanner.Err() is checked once scanning ends, so
// a line longer than the scanner's buffer is a refusal, not a silent
// truncation.
func parseRefUpdates(r io.Reader) ([]journal.RefUpdate, error) {
	var updates []journal.RefUpdate
	seenRefs := make(map[string]bool)

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		firstSP := strings.IndexByte(line, ' ')
		if firstSP < 0 {
			return nil, refusePreReceiveLine(line)
		}
		rest := line[firstSP+1:]
		secondSP := strings.IndexByte(rest, ' ')
		if secondSP < 0 {
			return nil, refusePreReceiveLine(line)
		}

		u := journal.RefUpdate{
			OldOID: line[:firstSP],
			NewOID: rest[:secondSP],
			Ref:    rest[secondSP+1:],
		}
		if err := journal.ValidateRefUpdate(u); err != nil {
			return nil, refusal.RefuseWithCause("pre-receive refused", err.Error(), "", err)
		}
		if seenRefs[u.Ref] {
			return nil, refusal.Refuse(
				"pre-receive refused",
				fmt.Sprintf("duplicate ref update for %q", u.Ref),
				"",
			)
		}
		seenRefs[u.Ref] = true
		updates = append(updates, u)
	}
	if err := scanner.Err(); err != nil {
		return nil, refusal.RefuseWithCause(
			"pre-receive refused",
			fmt.Sprintf("reading stdin: %s", err.Error()),
			"",
			err,
		)
	}
	return updates, nil
}

// refusePreReceiveLine refuses a pre-receive stdin line that does not carry
// two spaces, so old_oid, new_oid, and ref cannot all be present.
func refusePreReceiveLine(line string) error {
	return refusal.Refuse(
		"pre-receive refused",
		fmt.Sprintf("malformed line: expected \"<old-oid> <new-oid> <ref>\", got %q", line),
		"",
	)
}

// resolveHook resolves one pre-receive invocation's repository, data
// directory, and journal purely from the environment
// internal/githttp/receivepack.go already sets (WALDEN_REPO,
// WALDEN_DATA_DIR, WALDEN_JOURNAL), through an injected lookupEnv so tests
// do not depend on process environment.
//
// It deliberately does not call config.Load: the hook takes no flags and
// has no defaults to fall back on -- a missing WALDEN_DATA_DIR means
// something other than walden's own receive-pack handler ran this binary,
// and guessing /data there is exactly the guess PHILOSOPHY.md's "failures
// must be legible" section forbids. The repo path comes from
// store.New(dataDir).RepoPath(repo) and its existence from RepoExists, so
// identifier syntax and data-directory containment are checked by the one
// place that already owns those rules, not re-derived here. The journal,
// when WALDEN_JOURNAL is set, is resolved with store.ResolveJournal --
// URL and credentials, no network request; the boot path's ProbeCAS is not
// repeated on every push.
func resolveHook(ctx context.Context, lookupEnv func(string) (string, bool), updates []journal.RefUpdate) (*hookRequest, error) {
	repo, ok := lookupEnv("WALDEN_REPO")
	if !ok || repo == "" {
		return nil, refusePreReceiveEnv("WALDEN_REPO")
	}
	dataDir, ok := lookupEnv("WALDEN_DATA_DIR")
	if !ok || dataDir == "" {
		return nil, refusePreReceiveEnv("WALDEN_DATA_DIR")
	}

	s := store.New(dataDir)
	repoPath, err := s.RepoPath(repo)
	if err != nil {
		return nil, err
	}
	exists, err := s.RepoExists(ctx, repo)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, refusal.RefuseWithCause(
			"pre-receive refused",
			fmt.Sprintf("repository %q does not exist under %s", repo, dataDir),
			"",
			store.ErrRepoNotFound,
		)
	}

	var jrnl *store.Journal
	if journalURL, ok := lookupEnv("WALDEN_JOURNAL"); ok && journalURL != "" {
		jrnl, err = store.ResolveJournal(journalURL, lookupEnv)
		if err != nil {
			return nil, err
		}
	}

	return &hookRequest{
		Repo:     repo,
		DataDir:  dataDir,
		RepoPath: repoPath,
		Journal:  jrnl,
		Updates:  updates,
	}, nil
}

// refusePreReceiveEnv refuses a pre-receive invocation missing one of the
// environment variables internal/githttp/receivepack.go always sets before
// exec'ing git receive-pack: seeing this refusal means something other
// than walden's own receive-pack handler invoked this binary as the hook.
func refusePreReceiveEnv(name string) error {
	return refusal.Refuse(
		"pre-receive refused",
		fmt.Sprintf("%s is not set", name),
		"run this binary only as git's pre-receive hook, invoked by walden's own receive-pack handler",
	)
}
