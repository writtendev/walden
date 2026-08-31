# Philosophy

> "Simplify, simplify."
> — Henry David Thoreau, _Walden_

walden is a small, self-sufficient git server with a write-ahead log. It holds
your history so nothing is ever lost.

This document explains the kind of software walden is trying to be. It is the
most important document in the repository. Code that conflicts with it is
wrong, even if the code works.

## The highest tier of boring

There is a tier of infrastructure that people stop thinking about. sshd. cron.
SQLite. The git object store itself. Software in this tier shares a set of
properties:

- It does one thing, and the thing can be stated in a paragraph.
- It runs for years between restarts and decades between redesigns.
- Its behavior tomorrow is exactly its behavior today.
- When it does fail, the failure is legible and the recovery is obvious.
- Nobody is excited about it. Everybody trusts it.

walden aims for this tier. Not "fairly reliable." Not "boring, for now." The
target is: **you deploy walden, and you plausibly do not redeploy it for ten
years.** Every decision in this codebase should be made as if that sentence
were a contract.

## What walden is

walden's entire job, stated in one paragraph:

It speaks git's smart HTTP protocol for exactly two verbs: `upload-pack`
(fetch/clone) and `receive-pack` (push). Before serving anything, it answers
one question: does this token grant read, write, or create on this repository?
Every accepted write is recorded in an append-only journal in object storage
_before_ the push is acknowledged. Given an empty disk and a journal, walden
rebuilds everything. That's it.

## What walden is not

walden has no user accounts, no organizations, no pull requests, no issues,
no web UI beyond a read-only status page, no webhooks, no CI, and no opinions
about how you work. Those things are meaning, and meaning belongs to whatever
you choose to run above walden — a forge, a review tool, a script, or nothing
at all. walden is bytes, authenticated and journaled.

This is not modesty. It is the design. A component can only be finished if its
scope can be finished, and walden's scope is chosen to be completable. Feature
requests that add meaning to the storage layer will be declined with gratitude
and a pointer to this paragraph.

## Design principles

### 1. Finished is a feature

Most software treats change as a sign of life. Infrastructure at the tier
walden targets treats change as risk. The roadmap converges to zero. Releases
should become rare, then boring, then mostly security bumps of the underlying
git binary. A year without a commit is not abandonment; for this project it
is success. (The distinction is documented liveness: maintained-and-finished,
not dead.)

### 2. Wrap git, never reimplement it

The correctness-critical code in any git server is pack handling, delta
resolution, and protocol negotiation. walden does not contain that code. It
execs the real `git` binary — the same one battle-tested by every server on
earth — and confines itself to plumbing bytes, checking tokens, and keeping
the journal. The most dangerous dependency here is maintained by the git
project, not by this one. That is the single decision that makes a small,
ten-year-stasis storage daemon possible.

### 3. The disk is a cache; the journal is the truth

A conventional git server trusts a disk, so someone must babysit the machine
under it. walden trusts nothing local. The journal in object storage is the
source of truth; the local repositories are a materialized view that any
fresh machine can rebuild by replay. Machines are cattle. Disks are
disposable. The acknowledgment of a push _means_ "this is in the journal."
There is no backup job, because the write path is the backup. There is no
restore procedure, because recovery is just running walden again.

### 4. Write it like it's already old

walden is written in Go, in the most conservative dialect we can manage:

- Standard library maximalism. net/http, crypto, os/exec cover nearly
  everything walden does.
- Dependencies approach zero. The object-storage client surface walden needs
  (PUT, GET, LIST, conditional PUT) is small enough to own outright.
- No frameworks, no clever abstractions, no fashionable idioms. Code should
  read the same to a Go programmer in 2036 as it does today.

The Go 1 compatibility promise is the closest thing in mainstream software to
a stasis guarantee. This project intends to collect on it.

### 5. Five knobs

walden's complete configuration surface: a data directory, an optional
journal URL, an optional trust key, a listen port, and a token CLI. A person
should be able to hold the entire mental model in their head after one
screenful of documentation. Every proposed sixth knob must justify itself
against the sentence: _simple enough to trust_.

### 6. The format outlives the binary

The journal format is a published, versioned specification with golden
fixtures ([spec/journal/](spec/journal/)). Anyone may reimplement it, in any
language, for any purpose, without asking. If every walden binary vanished,
the spec and fixtures are sufficient to recover every byte ever journaled. A
format only becomes trustworthy when it requires no permission and no
particular software to read.

### 7. Failures must be legible

When walden refuses to do something, the reason should be printable in one
line. When walden loses a race (a fenced-out stale writer, a conditional-put
conflict), it should detect it, say so plainly, and stop — never guess. The
operator at 3am is the design persona. There are only a handful of failure
modes by construction; each one is documented, and each one's recovery is
"run it again" or "read the one-line error."

## Self-sufficiency

walden is named for a cabin by a pond: a small thing, built deliberately,
holding everything its occupant needs, owing nothing to anyone. It runs
anywhere a container runs — a Raspberry Pi, a five-dollar VPS, a NAS in a
closet, any cloud. With no configuration it is a working git server. With one
URL it becomes a git server that survives anything. It does not phone home,
does not require an account, and does not know or care what sits above it.

## The promise

To the person who runs walden:

1. An acknowledged push is in the journal. Not scheduled to be. In.
2. Any machine holding your repositories may die at any moment and you lose
   nothing.
3. The software you run today will behave identically for as long as you
   choose to run it.
4. You can read all of it in an afternoon, and you are encouraged to.

Everything else — every line of code, every declined feature, every year
without a release — is in service of those four sentences.
