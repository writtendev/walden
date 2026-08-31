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
  store         — object-storage client (PUT/GET/LIST/conditional PUT)
  githttp       — smart HTTP handlers, execs git upload-pack/receive-pack
  auth          — token verification, built-in and delegated modes
  config        — the five-knob configuration surface
```

`config` imports nothing internal; no package imports another in a
cycle. A `/spec` directory (published, versioned formats with golden
fixtures — see ARCHITECTURE.md) lands with the journal format work.

## Build and test

```
go build ./...
go test ./...
```
