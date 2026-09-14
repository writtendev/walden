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
// ensureRepoForPush has no caller yet: WALD-52 wires it into
// POST /{repo}/git-receive-pack once that handler has a token to pass it. It is fully
// exercised by its own tests here.
func (h *Handler) ensureRepoForPush(ctx context.Context, token, repo string) (string, error) {
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
		if err := h.store.CreateRepo(ctx, repo); err != nil {
			return "", err
		}
	}

	return h.store.RepoPath(repo)
}
