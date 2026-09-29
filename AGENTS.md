# Agent brief

walden is a small, self-sufficient git server with a write-ahead log,
written in Go. It speaks git's smart HTTP protocol, authenticates with
scoped tokens, and journals every accepted write to object storage
before acknowledging the push.

Before proposing or implementing anything, read `PHILOSOPHY.md` (the
kind of software this is trying to be, and why) and `ARCHITECTURE.md`
(how it works, and where it ends). Those two are the fence around this
project — PHILOSOPHY.md says outright that code conflicting with it is
wrong even if the code works. When a proposal conflicts with them, the
proposal loses or the document is amended deliberately — never by
drift.

## This file

AGENTS.md is the only agent brief here. CLAUDE.md and GEMINI.md are
one-line `@AGENTS.md` imports, so every toolchain reads the same text
and there is nothing to keep in sync. Edit AGENTS.md; leave the two
stubs alone. Same pattern as lerp/ and writ/.

## How we work

Every change starts from a Linear ticket. There is no cold, ticket-less
work — if it's worth doing, it's worth a ticket first.

1. Claim the ticket and move it to **In Progress** at the start of the
   session, not the end.
2. Implement in a dedicated git worktree, never directly on `main` or
   a shared checkout.
3. Commit the change there.
4. Push the branch and open a PR.
5. Wait for CI (plain GitHub Actions) to go green before asking for
   review.
6. From there it's human review: merged as-is, amended, or sent back.
   The agent's job ends at a green, reviewable PR — it does not merge
   its own work.

## Mechanical review rules

Code review is mechanical against these rules:

- **No dependencies outside the standard library.** Standard-library
  maximalism (`net/http`, `crypto`, `os/exec`). Dependencies approach
  zero; the object storage client is owned outright.
- **No sixth knob.** walden's configuration surface is five knobs: data
  directory, journal URL, trust key, listen port, and token CLI.
- **No meaning in the storage layer.** Accounts, teams, pull requests,
  issues, and webhooks belong above walden. walden is authenticated,
  journaled bytes.
- **A spec change requires a fixture change in the same commit.**
  Changes to format or protocol specs under `spec/` must include
  corresponding golden fixtures.
- **Wrap git; never reimplement pack handling, delta resolution, or
  protocol negotiation.** Exec the real `git` binary as a subprocess.
- **Every operator-facing refusal is one line.** When walden refuses an
  operation or detects a conflict, it states the reason in one line and
  stops — never guesses.

## House rules

- Boring, small, direct. Standard-library maximalism.
- Match the style of surrounding code. Write it like it's already old:
  it should read the same to a Go programmer in ten years as it does
  today.
- Treat scope growth, speculative abstraction, and framework-building
  as bugs.
- When you file a Linear ticket, set a priority and an estimate — your
  best judgment, stated once, not discussed.

## Layout

```
/cmd/walden     — the binary: serve, token CLI, pre-receive hook
/internal
  journal       — append-only streams, ref transactions, fencing
  store         — object-storage client (PUT/GET/LIST/conditional PUT/DELETE)
    storetest   — fake S3 endpoint with fault injection (test support only)
  githttp       — smart HTTP handlers, execs git upload-pack/receive-pack
  auth          — token verification, built-in and delegated modes
  config        — the five-knob configuration surface
  refusal       — the one-line operator-facing refusal convention
  spectest      — reads the JSON examples out of a published spec, for
                  the fixture conformance gates (test support only)
```

`config` imports nothing internal; no package imports another in a
cycle. A `/spec` directory (published, versioned formats with golden
fixtures — see ARCHITECTURE.md) lands with the journal format work.

## Build and test

```
go build ./...
go test ./...
```

## Orchestrate

The `factory` pipeline — `orchestrate`, `implement-ticket`,
`adversarial-review`, `merge-queue`, `decision-queue` — reads this
section and nothing else for its repo-specific configuration. A field
left out is a field those skills refuse to guess: they say which one
is missing and stop.

| Field        | Value                                     |
| ------------ | ----------------------------------------- |
| Linear team  | `WALD`                                    |
| Base branch  | `main`                                    |
| Worktrees    | `$HOME/ops/worktrees/writtendev/walden/`  |
| Write window | `none`                                    |

Per-ticket worktrees live outside the repo, so no ancestor
`AGENTS.md`/`CLAUDE.md` loads into a ticket's run and there is nothing
to gitignore. Expand `$HOME` to an absolute path before using it.
Per-run state is local to the machine that ran it and is not
committed.

**Getting the pipeline.** `factory` is installed once per machine at
user scope, not pinned by this repo. `.claude/settings.json` only
declares the `mattwalters` marketplace (github `mattwalters/skills`).
On a machine that does not have it installed yet, run:

```
claude plugin install factory@mattwalters --scope user
```

Do not install it at project scope or add it to `enabledPlugins` here.

Codex and Antigravity have no plugin mechanism and read skills from
`.agents/skills/<name>` instead; those are symlinks into a local
checkout of `mattwalters/skills`, ignored deliberately because the
checkout's location is per machine. One-time setup, from the repo root,
with that checkout at `~/src/mattwalters/skills`:

```
mkdir -p .agents/skills
for s in orchestrate implement-ticket adversarial-review merge-queue decision-queue; do
  ln -sfn "$HOME/src/mattwalters/skills/plugins/factory/skills/$s" ".agents/skills/$s"
done
```

`ln -sfn` so re-running this is a no-op instead of following an
existing link and writing a stray symlink inside the target.

**Check command.** An implementer or fixer runs this and passes it
before pushing:

```
go build ./... && go vet ./... && test -z "$(gofmt -l .)" && go test -race ./...
```

Wider than `## Build and test` above, deliberately. That one is what a
person runs while working; this is what CI gates on, so that a local
pass and a green pull request mean the same thing. The formatting
check is spelled `test -z` rather than a bare `gofmt -l .` because
`gofmt -l` lists the offending files and still exits zero — chained
with `&&` it would never fail, and unformatted code would reach CI
with the check reporting success.

**Review invariants.** `## Mechanical review rules` above is the
review contract. A reviewer works against those six rules and reports
findings in their terms.

They are deliberately not restated here. This file is the single
source — `## This file` says as much, and CLAUDE.md and GEMINI.md are
one-line imports for that reason. A second copy of the rules under a
second heading is the same drift in miniature, and the copy that goes
stale is the one a reviewer would be reading.
