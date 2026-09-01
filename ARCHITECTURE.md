# Architecture

This document describes how walden works and, just as importantly, where
walden ends. For why it is built this way, read
[PHILOSOPHY.md](PHILOSOPHY.md) first.

## One paragraph

walden is a single Go binary that serves git's smart HTTP protocol by exec'ing
the real `git` binary, authenticates requests with scoped tokens, and records
every accepted write to an append-only journal in S3-compatible object
storage _before_ acknowledging the push. Local disk is a cache; the journal
is the truth; any empty machine can rebuild the full state by replaying the
journal.

## Where walden sits

walden is a storage layer, and only a storage layer.

    ┌─────────────────────────────────────────────┐
    │  whatever you run above walden              │
    │  (a forge, a review tool, a script,         │
    │   plain git on your laptop — or nothing)    │
    └──────────────────┬──────────────────────────┘
                       │ git smart HTTP + tokens
    ┌──────────────────▼──────────────────────────┐
    │  walden                                     │
    │  authenticated git bytes + journal          │
    │  "may this token touch this repo"           │
    └──────────────────┬──────────────────────────┘
                       │ append-only journal
    ┌──────────────────▼──────────────────────────┐
    │  object storage (requires compare-and-swap) │
    └─────────────────────────────────────────────┘

walden never learns who its users are, how repositories relate to each other,
or what the commits mean. Any richer model — accounts, teams, human-readable
names — belongs to the layer above and must compile down to walden's entire
vocabulary: _token T may read/write/create repo R_. walden is independently
useful with nothing above it at all; anything above it can treat walden as an
ordinary git remote, because that is what it is.

## Repository model

- A flat namespace of caller-chosen identifiers, no nesting, no hierarchy.
- Each repo is an ordinary bare git repository on the data volume.
- Repos are created implicitly on first authorized push carrying the `c` (create) scope.
- walden serves exactly three routes per repo:
  - `GET  /{repo}/info/refs` — ref advertisement
  - `POST /{repo}/git-upload-pack` — fetch/clone
  - `POST /{repo}/git-receive-pack` — push

The handlers authenticate, then exec `git upload-pack` / `git receive-pack`
against the bare repo, streaming stdin/stdout. walden contains no pack
parsing, no delta code, no protocol negotiation logic. That code lives in
git, where it belongs.

## The journal

The journal is the design. Everything else is plumbing around it.

The journal is organized into append-only **streams** identified by
`(stream-id, seq)` rather than per-repo journals. A repository is one stream.
The instance's own configuration state — the token table and key rotations —
is recorded in a second stream, the **meta stream**.

The server's signing identity is born with the journal (as its genesis record)
and lives in it. Journal signing provides tamper-evidence of history, not
protection from a malicious server — a server that wants to lie can sign its
lies.

Object storage requires compare-and-swap (conditional write) support from the
bucket provider; see the provider support table in [spec/](spec/).

### What gets written

Every accepted push appends two kinds of immutable record to the bucket:

1. **Pack segments.** The packfile the client sent, stored verbatim,
   content-addressed. walden already has these bytes in hand; journaling them
   costs one PUT.
2. **Ref transactions.** A small record: stream ID, sequence number, and the
   set of ref updates ("`refs/heads/main`: X → Y"), signed by the server's
   signing identity.

Nothing on the write path is ever mutated or deleted. Garbage collection and
repacking on the _local_ disk are irrelevant to durability — they are cache
maintenance.

### The durability handshake

git's `pre-receive` hook runs after the client's packfile is fully received
but _before_ any ref moves. walden's hook (the same binary, dispatched by
argv) performs the journal append and exits 0 only once object storage has
acknowledged both records. Only then does git move the refs and does the
client see success.

Consequence, and the core promise: **an acknowledged push is already in
object storage.** The cost is one object-storage round trip of added latency
on pushes (~50–150 ms). Pushes are rare, human-initiated, and
latency-tolerant; lost commits are none of those things.

### Fencing (single-writer safety)

Exactly one walden process may append to a given stream at a time.
The journal itself is the arbiter: every ref-transaction append is a
**conditional put** carrying the expected previous sequence number. A stale
writer — a process presumed dead that isn't, a second instance started by
mistake — fails the condition, concludes it has been fenced, and stops
serving writes immediately. It never guesses.

This is the most correctness-critical code in walden (on the order of a
hundred lines), and it is specified by fixtures and exercised by a chaos test
before it is trusted with anyone's bytes.

### Compaction

A background task periodically writes a consolidated snapshot pack per stream
plus a "replay from here" marker, so that materialization does not require
replaying all of history. Compaction runs off the critical path, writes new
objects before publishing the marker, and may retain superseded segments for
months — object storage is nearly free, and paranoia is on brand.

### Materialization

Given an empty data directory, walden lists the journal, replays each stream —
apply snapshot, fetch pack segments in order, apply ref transactions — then
verifies (`git fsck`, refs identical to the journal head) and marks the repo
ready. This is the boot path, the restore path, and the migration path,
because they are the same path. There is no separate restore procedure to
rot: **recovery is just running walden again**, pointed at the same journal.

The continuous test loop in CI restores random repositories from journals and
diffs them against live state, so the replay path is exercised thousands of
times before it is ever needed in anger.

## Auth

One question, one pluggable answer: _may this token read, write, or create this repo?_

- **Built-in mode (default).** Tokens are minted by the server's own CLI
  (`walden token create --allow 'rw:*'`), stored hashed in a small local
  store (journaled to the meta stream, so restore restores your tokens too).
  Scopes are read/write/create (`r`, `w`, `c`) against repo-name globs. No
  accounts, no email, no OAuth — a token list is the entire identity model.
- **Delegated mode.** walden is given one public key
  (`WALDEN_AUTH_TRUST=<key>`) and accepts signed capability tokens minted by
  an external system: "bearer may write repo-name until <time>." Verification
  is local; no callback, no network dependency — the issuing system can be
  down and git keeps working. Revocation is lazy by TTL, so capabilities are
  short-lived. What that external system is — an identity provider, a forge,
  a shell script with a keypair — is deliberately not walden's business.

Same binary, same code path; the only difference is where the yes/no comes
from. The token format and scope vocabulary are part of the published
interface.

## Configuration surface

The complete list. A sixth knob requires amending this document, which is
intended as friction.

| Knob                | Flag           | Environment Variable | Meaning                                     | Default            |
| ------------------- | -------------- | -------------------- | ------------------------------------------- | ------------------ |
| data directory      | `--data-dir`   | `WALDEN_DATA_DIR`    | where bare repos (the cache) live           | `/data`            |
| `WALDEN_JOURNAL`    | `--journal`    | `WALDEN_JOURNAL`     | S3-style URL; presence enables the journal  | off (loud warning) |
| `WALDEN_AUTH_TRUST` | `--auth-trust` | `WALDEN_AUTH_TRUST`  | public key; presence enables delegated auth | built-in tokens    |
| listen address      | `--listen`     | `WALDEN_LISTEN_ADDR` | HTTP listen address                         | `:8470`            |
| token CLI           | —              | —                    | `walden token create/list/revoke`           | —                  |

Configuration resolves through a single documented precedence order:
1. **CLI flag** (highest priority)
2. **Environment variable**
3. **Default value** (lowest priority)

Every invalid value produces a single-line error naming the knob and stops
immediately. Running `walden serve --print-config` displays the resolved
configuration set and exits without starting the server.

`WALDEN_JOURNAL` is the whole journal configuration: one URL carrying
endpoint, region, bucket, and prefix, in either addressing style —
`s3://bucket/prefix`, `https://endpoint/bucket/prefix` (path-style, and the
reading for any host walden does not recognise), or
`https://bucket.endpoint/prefix` (virtual-hosted). Two query parameters, and
only two, may override what the host implies: `region` and `style`. The URL is
resolved at boot, so a malformed value — or a provider the support table marks
as lacking compare-and-swap — stops walden immediately rather than on the
first push.

Object-storage credentials are not a sixth knob. They resolve through one
documented order, first hit wins: credentials in the journal URL's userinfo
(`s3://KEY:SECRET@bucket/prefix`), then the conventional `AWS_ACCESS_KEY_ID`
and `AWS_SECRET_ACCESS_KEY` (plus `AWS_SESSION_TOKEN` when set), then a
one-line refusal. The signing region falls back the same way, to `AWS_REGION`
and then `AWS_DEFAULT_REGION`. Those are AWS conventions walden reads, not
walden configuration; there is no `WALDEN_*` credential variable, and the
shared credentials file, instance metadata, and role providers are
deliberately not consulted.

Zero-config boot is a working (journal-less) git server that prints a
one-time admin token to stdout on first start.

## Process model

One binary, argv-dispatched:

- `walden serve` — PID 1 in the container: HTTP server, background compactor,
  status page.
- `walden token …` — admin CLI against the local store (typically via
  `docker exec`).
- invoked as `pre-receive` — the journal hook, run by git during a push.

No sidecar, no companion CLI to version-match, no separate restore tool.

## Scope boundary

walden has no concept of tenants, quotas, metering, or suspension, and this
is a load-bearing omission, not a roadmap gap. One walden instance serves one
trust domain: one data directory, one journal, one token store. If you need
many isolated domains, run many waldens — the instance boundary _is_ the
isolation boundary, and each instance remains the identical, bone-stock
artifact. Anything that would require walden to distinguish one group of
repositories from another belongs above it.

## Failure modes

By construction there are few, and each is legible:

| Failure                    | Effect                                                  | Recovery                                      |
| -------------------------- | ------------------------------------------------------- | --------------------------------------------- |
| machine/disk dies          | none durable; cache lost                                | boot walden against the same journal          |
| object storage unreachable | pushes fail loudly; reads keep serving                  | pushes succeed when storage returns           |
| fenced-out writer          | conditional put fails; writes stop on that instance     | traffic already belongs to the current writer |
| crash mid-push             | refs never moved; journal may hold an unreferenced pack | harmless; compaction tidies                   |
| journal-less mode          | durability = the disk, as warned                        | enable `WALDEN_JOURNAL`                       |

Losing an acknowledged push does not appear in this table. That is the
entire product.

## The published interface

Three things are contract, versioned, and specified with golden fixtures
under [spec/](spec/):

1. The journal format (`journal/v1/`) — layout, record encodings,
   conditional-append semantics.
2. The capability token format and scope vocabulary.
3. The two-operation HTTP surface (which is git's, and stable for a decade
   already).

Everything else — internal packages, the status page, log lines — is
implementation and may change (though, per the philosophy, it mostly won't).

## Dependencies

- The `git` binary (pinned in the image; security bumps are the expected
  cadence of releases).
- The Go standard library.
- A hand-rolled object-storage client covering PUT, GET, LIST, and
  conditional PUT against the S3 REST API — small enough to own, kept
  dependency-free on purpose.

The dependency graph is intended to be legible in one sitting and stable for
ten years.
