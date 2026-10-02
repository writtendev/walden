package githttp

import (
	"context"
	"errors"
	"fmt"

	"github.com/writtendev/walden/internal/auth"
	"github.com/writtendev/walden/internal/refusal"
	"github.com/writtendev/walden/internal/store"
)

// ensureRepoForPush is the one place that decides whether a push may create a repository.
//
// Order matters and is the whole point: existence is established first, because asking for
// Actions{Write: true, Create: true} against a repository that already exists would refuse a
// perfectly good rw-only push for want of a scope it does not need. Only a repository that
// does not yet exist requires Create in addition to Write. Then Authorize is asked exactly
// once, with the action set that case requires, so the w AND c conjunction of spec/auth/v1
// §3.4 is never re-derived outside internal/auth.
//
// On success, a missing repository is created before its path is returned. On refusal, the
// error is passed through unchanged — except when the repository was missing and the refusal
// is specifically for lack of create scope (errors.Is(err, auth.ErrCreateForbidden)), which is
// rewritten into §3.4's published "repository not found" refusal naming the missing scope. A
// read-only token pushing to a new repository still gets the generic "forbidden" refusal
// naming 'w', because auth.Missing reports the first missing action in canonical r, w, c
// order — so neither refusal ever misdescribes what the token is short of.
//
// A lost creation race is success, not refusal. store.ErrRepoExists can only reach this point
// when exists was false above and another push for the same repo won CreateRepo's publishing
// rename in between — a second rwc:* push arriving while the first is still running git init.
// The caller already cleared Authorize with Create, demonstrating it holds the create scope;
// now that the repository exists, the Write it also holds is all §3.4 requires, so the push
// proceeds against the winner's repository instead of being told to retry the exact push that
// just failed. Any other CreateRepo error still refuses.
//
// Last, two checks on the repository itself, both only for a push and both on the
// re-resolved path. A repository that reached disk some other way than CreateRepo —
// placed there by an operator, restored from a backup, migrated off another server —
// brings its own config and its own hooks directory, and walden wrote neither.
// store.VouchRepoConfig refuses one whose config carries a repository-scope key walden
// did not write; store.EnsureHook verifies, and repairs where it safely can, the
// pre-receive hook a push would otherwise move refs past unjournaled. See the call site
// below for the order, and for why both sit here rather than in store.ResolveRepo.
//
// The two differ in what they do to reads, which is not an inconsistency but the
// difference between the failures: a hook-less repository still serves clones (a clone
// off it is harmless), while an unvouched config is refused on every route, because
// serving such a repository is what runs its command. resolveRepoDir carries the read
// half of the config check; nothing carries a read half of the hook check.
//
// ensureRepoForPush is called by POST /{repo}/git-receive-pack to authorize the push and,
// if the repository does not yet exist, create it. It is fully exercised by its own
// tests here.
func (h *Handler) ensureRepoForPush(ctx context.Context, token, repo string) (string, error) {
	if h.auth == nil {
		return "", refusal.Refuse(
			"server misconfigured",
			"authorizer is not configured",
			"contact the operator",
		)
	}
	_, exists, err := h.store.ResolveRepo(ctx, repo)
	if err != nil {
		return "", err
	}

	required := auth.Actions{Write: true, Create: !exists}

	if err := h.auth.Authorize(ctx, token, required, repo); err != nil {
		if !exists && errors.Is(err, auth.ErrCreateForbidden) {
			return "", refusal.RefuseWithCause(
				"repository not found",
				fmt.Sprintf("repository '%s' does not exist and token lacks create scope 'c'", repo),
				"request create scope 'c' or push to an existing repository",
				store.ErrRepoNotFound,
			)
		}
		return "", err
	}

	if !exists {
		if err := h.store.CreateRepo(ctx, repo); err != nil && !errors.Is(err, store.ErrRepoExists) {
			return "", &repoCreateError{err}
		}
	}

	// Resolve the path last, not from the ResolveRepo call above: when exists was true,
	// CreateRepo never ran, so nothing has re-checked containment since then. A symlink
	// swapped in for the repository directory during the Authorize window would otherwise
	// reach handleReceivePack unchecked. RepoPath's own containment check is what refuses
	// that case, and create_test.go's
	// TestEnsureRepoForPushRefusesEscapingSymlinkSwappedDuringAuthorize drives exactly that
	// swap against the exists == true branch, so removing this line fails the suite.
	path, err := h.store.RepoPath(repo)
	if err != nil {
		return "", err
	}

	// The repository's own config is vouched for first, on the path the re-resolve above
	// just returned. This is the one route resolveRepoDir does not cover: the receive-pack
	// POST comes through here instead. walden will not hand a git child a repository
	// carrying a repository-scope config key it did not write.
	//
	// It sits here rather than in store.ResolveRepo for the reason the EnsureHook block
	// below gives about itself — ResolveRepo is called before Authorize, and a check there
	// would exec git for an unauthenticated caller — but it is not the same check and does
	// not refuse the same repositories. A repository without walden's hook still serves
	// reads; a repository whose config names a command for git to run does not, because
	// serving it is what runs the command. resolveRepoDir carries that half.
	//
	// Before EnsureHook rather than after it, and the order is deliberate. EnsureHook
	// execs git against this directory and may write a symlink into it, and neither
	// belongs to a repository walden has already decided it will not serve. Asking the
	// narrower question first also means the operator of a repository that is both
	// unvouched and redirected hears about the config, which is the condition that has to
	// be fixed before the hook refusal could even be reached.
	if err := h.store.VouchRepoConfig(ctx, path); err != nil {
		return "", err
	}

	// The hook is verified here — on the path the re-resolve above just returned, which is
	// the directory `git receive-pack` is about to be pointed at, including one swapped in
	// during the Authorize window — and nowhere else. Not inside store.ResolveRepo: all
	// three routes share that call, and a repository that lost its hook must still serve
	// clones (info/refs and upload-pack behave exactly as they did before this line
	// existed). Not in the hook process either: by the time a hook runs, git has already
	// taken the pack, and a hook that is running is by construction present.
	//
	// It is also the last thing this function does, so the repair it may perform only ever
	// runs for a caller that has already cleared Authorize with write scope: nobody else
	// can probe a repository's hook state or provoke a write to its hooks directory.
	//
	// It gets the request's context: establishing which hook git will run is itself an
	// exec, and a data directory that has stopped answering must not park this goroutine
	// past the client's disconnect.
	if err := h.store.EnsureHook(ctx, path); err != nil {
		return "", err
	}
	return path, nil
}

// repoCreateError marks an error CreateRepo returned, as distinct from one
// store.ResolveRepo (or a bare store.RepoPath) returned while merely resolving
// or classifying a repository's path. Both can wrap store.ErrStoreUnavailable,
// but they describe different failures — one happened while working out where
// the repository is, the other while writing it to disk — and
// writeAuthRefusal uses errors.As to tell them apart so the operator-facing
// wording says which one actually happened. It changes nothing about
// errors.Is(err, store.ErrStoreUnavailable): Unwrap delegates to the
// underlying error, so that still holds.
type repoCreateError struct {
	err error
}

func (e *repoCreateError) Error() string { return e.err.Error() }
func (e *repoCreateError) Unwrap() error { return e.err }
