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

## House rules

- Boring, small, direct. Standard-library maximalism — net/http,
  crypto, os/exec cover nearly everything walden does. Dependencies
  approach zero; a new one needs a reason strong enough to survive
  PHILOSOPHY.md's "five knobs" bar.
- Wrap git, never reimplement it. Pack handling, delta resolution, and
  protocol negotiation live in the real `git` binary, execed as a
  subprocess — not in this codebase.
- Treat scope growth, speculative abstraction, and framework-building
  as bugs. walden is a storage layer and only a storage layer; feature
  requests that add meaning to it belong above it, not in it.
- Match the style of surrounding code. Write it like it's already old:
  it should read the same to a Go programmer in ten years as it does
  today.
- Failures must be legible. When walden refuses or loses a race, it
  detects it, says so in one line, and stops — never guesses.
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
