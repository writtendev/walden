// refprepare.go implements WALD-128's Option A: before journaling a push,
// ask git itself which of the push's ref updates it will accept, and
// journal only that subset -- leaving git to refuse the rest, in its own
// words, exactly as it would if walden asked nothing at all.
//
// One shape of push is refused outright instead, before git is asked
// anything: one whose own ref set puts two surviving refs in a
// directory/file conflict (refuseDirFileConflict below). That is WALD-128's
// 2026-09-28 amendment, and it is the only case where walden is
// deliberately stricter than git.
//
// The instrument is `git update-ref --stdin`'s start/prepare/abort
// sub-protocol: `prepare` validates a whole batch of ref updates --
// directory/file conflicts, stale old_oid, a nonexistent new_oid -- without
// writing anything, and `abort` releases whatever it locked. Run from
// inside pre-receive, in the same environment git already built for the
// quarantine, it answers the identical question receive-pack itself
// answers moments later; from the hook it produced the same error string
// receive-pack went on to produce. That is wrapping git, not reimplementing
// it (mechanical rule 5): walden never decides a ref's fate itself, it
// only asks, once per candidate set, and reads git's own verdict.
//
// What this does not cover: the four receive.deny* policy knobs (walden
// pins them off on its own receive-pack invocation instead --
// internal/githttp/receivepack.go) and the one race described in
// probePrepare's doc comment below, which this file answers conservatively
// rather than closes.
//
// Every behavioural claim in this file's comments was re-checked against
// git 2.50.1 in a scratch repository as part of this change, not inherited
// from the ticket or its plan -- see WALD-128's own "standing lesson"
// section for why that discipline is load-bearing on this project.
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
)

// refPrepareWaitDelay bounds how long a probe's cmd.Wait may block after
// cmd.Cancel (SIGTERM, below) has been sent. Mirrors
// internal/githttp/gitcmd.go's gitWaitDelay for the identical reason: this
// package has no context that is ever actually cancelled today (the hook's
// ctx is context.Background(), passed down from run() in main.go), but
// exec.CommandContext still requires *a* WaitDelay whenever Cancel is
// overridden, and copying an established constant is simpler than
// inventing a second one with no basis for a different value.
const refPrepareWaitDelay = 5 * time.Second

// prepareRefUpdates asks git which of updates it will accept, applying them
// in order on top of the repository's current state, and returns exactly
// that accepted subset -- never more, never fewer. It makes no journal
// write and no network call; every exec here is local, against
// repoPath's own working copy of its refs, in the variant-C environment
// refPrepareEnv builds.
//
// The full set is tried first: one exec, ~15ms, and the overwhelmingly
// common outcome (every ref of a clean push applies). Only when that
// fails does it fall back to walking updates one at a time, in the exact
// order they arrived on pre-receive's stdin -- git's own apply order,
// confirmed against 2.50.1 by observing a delete sorted ahead of a create
// in one test, which ruled out "sort them some sensible way" as a
// available shortcut -- building the accepted slice up by asking whether
// already-accepted ∪ {next} still prepares. That is the exact question
// git itself answers when it comes to apply that ref after its
// predecessors, so the inference "accepted ∪ {R} fails, therefore R is
// what git will refuse" needs no knowledge of *why* -- confirmed
// separately: the whole-set failure on a D/F conflict names *both* sides
// of the collision ("cannot process 'a' and 'a/x' at the same time"),
// identifying neither as the loser, which is exactly why this cannot be
// done in one exec by reading the error.
//
// The returned slice may be empty -- git will refuse every update -- which
// is not an error: the caller journals no ref transaction in that case and
// lets git refuse everything with its own per-ref messages (WALD-128
// Done-when 9).
//
// There are two error returns, and the caller treats them identically by
// refusing the whole push. The first is refuseDirFileConflict's: this
// push's own ref set is one walden will not journal any part of, decided
// without asking git at all. The second is git could not answer at all,
// for any of the candidate sets asked about (Done-when 3): a probe that
// cannot answer must never be read as "no problem found".
func prepareRefUpdates(ctx context.Context, repoPath, quarantine string, updates []journal.RefUpdate) ([]journal.RefUpdate, error) {
	if len(updates) == 0 {
		return nil, nil
	}
	if err := refuseDirFileConflict(updates); err != nil {
		return nil, err
	}

	ok, err := probePrepare(ctx, repoPath, quarantine, updates)
	if err != nil {
		return nil, err
	}
	if ok {
		return updates, nil
	}

	accepted := make([]journal.RefUpdate, 0, len(updates))
	for _, u := range updates {
		candidate := make([]journal.RefUpdate, len(accepted)+1)
		copy(candidate, accepted)
		candidate[len(accepted)] = u

		ok, err := probePrepare(ctx, repoPath, quarantine, candidate)
		if err != nil {
			return nil, err
		}
		if ok {
			accepted = candidate
		}
	}
	return accepted, nil
}

// refuseDirFileConflict refuses a push whose own ref set carries a
// directory/file conflict: two refs the push would leave in place where
// one name is a path prefix of the other, as "refs/heads/feature" is of
// "refs/heads/feature/x". It returns nil for every other push, including
// the single-ref case where the conflict is against a ref already on disk
// rather than against another ref in the same push -- that one is not this
// function's to find, and probePrepare already refuses it as an ordinary
// per-ref no.
//
// This is the one place walden is deliberately stricter than git, and the
// one place it declines a push git would partly apply (WALD-128's
// 2026-09-28 amendment). git applies one side of such a push and refuses
// the other, but which side survives is not stable across git versions:
// against git 2.50.1 the ref named first on the wire survived, and against
// git 2.55.0 "refs/heads/feature/x" survived in both orders, the loser
// reported as "refname conflict". Journaling a guess at the winner is how
// this ticket's own reproduction ended up with the journal holding
// refs/heads/feature while the disk held only refs/heads/feature/x: a
// signed record of a move that never happened, and a missing record of one
// that did. Refusing the whole push in one line is what walden does
// everywhere else it cannot get a definitive answer, and it is the cheap
// direction to be wrong in: the client still holds everything it was
// pushing and loses nothing by retrying with one of the two names
// changed.
//
// The conflict is found in the push's ref names, never in git's error
// text: the two versions above spell the refusal differently, and matching
// a message is what made the behaviour version-dependent in the first
// place. A path-prefix relationship between two names is a property of
// this function's input alone, so it reads the same on every git.
//
// Deletions are excluded because only refs that exist after the push can
// collide: a push that deletes refs/heads/feature and creates
// refs/heads/feature/x is an ordinary, legitimate push, and both git
// 2.50.1 and git 2.55.0 applied both of its updates, in both wire orders.
func refuseDirFileConflict(updates []journal.RefUpdate) error {
	remaining := make(map[string]bool, len(updates))
	for _, u := range updates {
		if !isRefDeletion(u) {
			remaining[u.Ref] = true
		}
	}
	// updates in order, and each name's prefixes shortest-first, so a push
	// carrying more than one conflict always names the same pair.
	for _, u := range updates {
		if isRefDeletion(u) {
			continue
		}
		for i := 0; i < len(u.Ref); i++ {
			if u.Ref[i] != '/' || !remaining[u.Ref[:i]] {
				continue
			}
			return refusal.Refuse(
				"pre-receive refused",
				fmt.Sprintf("this push would leave both %q and %q in place, and git will apply only one of them: one ref name is a directory prefix of the other", u.Ref[:i], u.Ref),
				"rename one of the two so that neither ref name is a path prefix of the other, and push again",
			)
		}
	}
	return nil
}

// isRefDeletion reports whether u removes its ref rather than leaving one
// behind, which git spells as an all-zero new_oid.
// journal.ValidateRefUpdate -- already run over every update on this path
// before journalPush is reached -- refuses an OID that is neither 40 nor
// 64 hex characters, so these two constants are the whole of the shape.
func isRefDeletion(u journal.RefUpdate) bool {
	return u.NewOID == journal.ZeroOID40 || u.NewOID == journal.ZeroOID64
}

// probePrepare runs exactly one `git update-ref --stdin` start/prepare/
// abort exec, asking whether updates -- applied together, in order, on top
// of repoPath's current refs -- would all succeed. It returns one of three
// outcomes:
//
//   - (true, nil): git says yes. stdout carried "prepare: ok" and the
//     process exited 0.
//   - (false, nil): git says no. The process exited non-zero, stdout
//     carried "start: ok" but not "prepare: ok", and stderr's first line
//     is prefixed "fatal: prepare:" -- the failure came from the prepare
//     command itself, evaluating the batch, not from something malformed
//     in how walden built it. This is git having answered the question,
//     definitively, and the caller narrows its candidate set accordingly.
//   - (false, err): git could not answer, and err is a one-line refusal
//     (Done-when 3). This covers two different shapes on purpose. First,
//     everything that is not the row above: no "start: ok" at all, a
//     fatal from an earlier command (a malformed line -- one of walden's
//     own bugs, not git refusing content), an exec/fork failure, a
//     cancelled context, a signal death. Second, and the one this ticket
//     added deliberately: a "fatal: prepare:" that *is* shaped like row
//     two but whose message is git failing to acquire a ref's on-disk
//     lock (isLockAcquisitionFailure) rather than refusing its content.
//     Two of this probe's own processes -- or this probe racing an
//     unrelated git process -- can collide on the same ref's lock file
//     within the ~15ms one exec takes; reading that collision as "git
//     says no" would have walden narrow the accepted set on a transient
//     condition that says nothing about whether the ref update is valid,
//     which is the WALD-46-class under-claim this ticket exists to close
//     (see the decision recorded on WALD-128 itself). Refusing the whole
//     push is always the safe direction here: the client retries, and
//     nothing is ever journaled on a guess.
func probePrepare(ctx context.Context, repoPath, quarantine string, updates []journal.RefUpdate) (bool, error) {
	cmd := exec.CommandContext(ctx, "git", "update-ref", "--stdin")
	cmd.Dir = repoPath
	cmd.Env = refPrepareEnv(quarantine)
	cmd.Stdin = bytes.NewReader(refPrepareCommandBlock(updates))
	cmd.WaitDelay = refPrepareWaitDelay
	// exec.CommandContext's default cancellation calls Process.Kill
	// (SIGKILL): fatal here, because SIGKILL delivered while a transaction
	// is prepared leaks refs/heads/*.lock permanently -- confirmed against
	// git 2.50.1, and confirmed separately that SIGTERM releases the same
	// lock cleanly. This process never forks a grandchild the way
	// receive-pack does (index-pack, pack-objects), so there is no process
	// group to signal -- just this one process.
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return cmd.Process.Signal(syscall.SIGTERM)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	out := stdout.String()
	errLine := firstLine(stderr.String())

	if runErr == nil && strings.Contains(out, "prepare: ok\n") {
		return true, nil
	}

	if strings.Contains(out, "start: ok\n") && strings.HasPrefix(errLine, "fatal: prepare:") {
		if isLockAcquisitionFailure(stderr.String()) {
			return false, refusePrepareUnknown(errLine + " (a ref lock could not be acquired to check this push)")
		}
		return false, nil
	}

	reason := errLine
	switch {
	case reason != "":
	case runErr != nil:
		reason = runErr.Error()
	default:
		reason = fmt.Sprintf("unexpected probe output (stdout %q, stderr %q)", out, stderr.String())
	}
	return false, refusePrepareUnknown(reason)
}

// refPrepareEnv builds the environment for the update-ref --stdin probe:
// the walden process's own environment, with exactly three edits -- the
// "variant C" recipe, confirmed empirically against git 2.50.1 rather than
// assumed from the ticket:
//
//   - GIT_QUARANTINE_PATH unset. update-ref refuses any ref update at all
//     inside a quarantine environment ("ref updates forbidden inside
//     quarantine environment"), so leaving this set makes every prepare
//     fail regardless of what it is asked.
//   - GIT_OBJECT_DIRECTORY unset. With it unset, $GIT_DIR/objects becomes
//     the primary object directory again, and that directory's own
//     objects/info/alternates is read regardless of this variable.
//   - GIT_ALTERNATE_OBJECT_DIRECTORIES overwritten with quarantine alone,
//     not appended to. This is the detail the ticket's own research
//     summary missed and the plan flags explicitly: git has *already* set
//     this variable, for the hook's environment, to the repository's own
//     objects directory (observed as "<repo>/./objects") -- because that
//     is what GIT_OBJECT_DIRECTORY pointed at before quarantine existed.
//     Once GIT_OBJECT_DIRECTORY is unset above, that inherited value is
//     redundant (the repo's own objects/ is primary again and reads its
//     own alternates file regardless), so overwriting it with just the
//     quarantine path is correct and is one path, no ":"-join, nothing to
//     get wrong. Confirmed by direct inspection of a real hook's
//     environment. When quarantine is "" (a delete-only push has none),
//     no alternates entry is added at all -- there is nothing incoming to
//     make visible.
//
// cmd.Dir is set to repoPath by probePrepare's caller rather than relying
// on an inherited GIT_DIR: confirmed that plain `git`, run with its
// working directory inside a bare repository, finds that repository with
// no GIT_DIR at all, and setting cmd.Dir explicitly is what keeps this
// probe correct in a unit test process that never had git set GIT_DIR in
// its environment to begin with (git only does that when invoking a real
// hook), rather than depending on an ambient value this package does not
// control. GIT_DIR itself is left exactly as the base environment carries
// it (present and "." in a real hook invocation, absent in a test): an
// explicit cmd.Dir and either state of GIT_DIR agree on the same
// repository, and forcing a fourth edit here to a value that is already
// correct either way would be a change with no observable effect.
func refPrepareEnv(quarantine string) []string {
	base := os.Environ()
	out := make([]string, 0, len(base)+1)
	for _, kv := range base {
		switch {
		case strings.HasPrefix(kv, "GIT_QUARANTINE_PATH="),
			strings.HasPrefix(kv, "GIT_OBJECT_DIRECTORY="),
			strings.HasPrefix(kv, "GIT_ALTERNATE_OBJECT_DIRECTORIES="):
			continue
		}
		out = append(out, kv)
	}
	if quarantine != "" {
		out = append(out, "GIT_ALTERNATE_OBJECT_DIRECTORIES="+quarantine)
	}
	return out
}

// refPrepareCommandBlock builds the update-ref --stdin transaction body:
// "start", one "update <ref> <new_oid> <old_oid>" line per update -- this
// probe never distinguishes a create, an update, or a delete as a separate
// shape, because update-ref doesn't either: a create is simply old_oid
// journal.ZeroOID40, a delete simply new_oid journal.ZeroOID40, both
// ordinary "update" lines, confirmed working against real git -- then
// "prepare" and "abort". abort always follows prepare in the command
// block, whether or not prepare succeeds: when it does, abort is what
// releases the lock this probe never intends to keep past its own exec
// (Done-when 4); when it doesn't, git has already exited on the fatal
// before reading the abort line at all, and separately confirmed to leave
// no lock behind on that path either. This probe never runs "commit" --
// it exists to ask a question, never to write a ref.
//
// Deliberately not the NUL-terminated (-z) form: this is the plain,
// space-separated line format git-update-ref(1) documents, which quotes a
// ref name containing a space -- but journal.ValidateRefUpdate (reftx.go),
// already run over every update on this path before journalPush is ever
// reached, refuses any ref name carrying a byte <= 0x20, so no input this
// function ever sees can contain one.
func refPrepareCommandBlock(updates []journal.RefUpdate) []byte {
	var b bytes.Buffer
	b.WriteString("start\n")
	for _, u := range updates {
		fmt.Fprintf(&b, "update %s %s %s\n", u.Ref, u.NewOID, u.OldOID)
	}
	b.WriteString("prepare\n")
	b.WriteString("abort\n")
	return b.Bytes()
}

// isLockAcquisitionFailure reports whether stderrText is git's own
// diagnostic for failing to acquire a ref's on-disk lock file, as opposed
// to refusing an update for a content reason (a D/F conflict, a stale
// old_oid, a nonexistent object) or committing an already-acquired
// transaction. Confirmed against git 2.50.1 by racing two `update-ref
// --stdin` processes over the same ref: the loser's prepare produces
//
//	fatal: prepare: cannot lock ref 'refs/heads/main': Unable to create
//	'<path>/refs/heads/main.lock': File exists.
//
//	Another git process seems to be running in this repository, ...
//
// -- multi-line, which is exactly why mechanical rule 6 means composing a
// one-line refusal rather than relaying it (see firstLine, and
// probePrepare's caller). "Unable to create" paired with ".lock" is git's
// own wording for a lock file that could not be created at all -- whether
// because another process (this probe's own concurrent invocation for a
// different push, or a foreign git process) already holds it, or for any
// other reason the lock file itself could not be written -- never for a
// lock that was acquired and then found the update itself invalid. The
// pairing, not either substring alone, is what keeps this from also
// matching an unrelated message that happens to mention a lock in
// passing.
func isLockAcquisitionFailure(stderrText string) bool {
	return strings.Contains(stderrText, "Unable to create") && strings.Contains(stderrText, ".lock")
}

// firstLine returns s up to its first '\n' (with any trailing '\r'
// trimmed), or the whole string when it carries no newline. git's own
// diagnostics here are sometimes multi-line (isLockAcquisitionFailure's
// doc comment shows one); mechanical rule 6 is why walden composes its own
// one-line refusal out of git's first line, rather than splicing the rest
// of stderr into it.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimRight(s, "\r")
}

// refusePrepareUnknown composes Done-when 3's refusal: the probe could not
// determine whether git will accept this push, so walden refuses rather
// than guessing either way. reason is git's own first stderr line, or,
// when the probe never reached git's output at all (an exec/fork failure,
// a cancelled context), a description of that failure.
func refusePrepareUnknown(reason string) error {
	return refusal.Refuse(
		"pre-receive refused",
		fmt.Sprintf("could not determine whether git will accept this push: %s", reason),
		"retry the push",
	)
}
