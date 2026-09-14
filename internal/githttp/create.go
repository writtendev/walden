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
	exists, err := h.store.RepoExists(ctx, repo)
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
			return "", err
		}
	}

	return h.store.RepoPath(repo)
}
