package store

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/writtendev/walden/internal/refusal"
)

// initBareConfigKeys is the set of repository-scope config keys walden will
// serve: exactly the keys `git init --bare` writes, and nothing else.
//
// It is an allowlist, and that is the whole design. walden does not keep a
// list of config keys that are dangerous to hand to git, because such a list
// is only as good as its last update and nothing tells walden when git's own
// line moves — keys gain and lose the ability to run a command between
// releases, and a stale list goes on reading like a check while silently
// admitting the one key that matters. An allowlist cannot rot that way. When
// git changes, it rots toward refusing a repository walden would have served
// — one line, naming the key, with `git config --unset` as the remedy —
// rather than toward serving one it should not.
//
// Every entry was produced by running `git init --bare --template=` and
// reading the keys back through vouchProbeArgs, on git 2.47.2 (the image's
// pin) and 2.54.0 on Alpine Linux and 2.50.1 (Apple Git-155) on macOS:
//
//   - core.repositoryformatversion, core.filemode and core.bare on all three.
//   - core.ignorecase and core.precomposeunicode additionally on macOS.
//   - extensions.objectformat and extensions.refstorage on all three, from
//     `--object-format=sha256` and `--ref-format=reftable` respectively.
//     walden passes neither flag, so these appear only if a future git
//     changes which format `git init` defaults to. They are admitted ahead
//     of that so the upgrade does not make walden refuse every repository it
//     created itself; TestInitBareKeysAreAllowlisted is what notices if the
//     relationship ever stops holding.
//
// Keys that `git init --bare` does not write are deliberately absent, even
// where they are plainly inert. core.logallrefupdates is the instructive one:
// a non-bare `git init` writes it (verified on all three), a bare one never
// does, so it is not walden's to vouch for. The same goes for the remote.*,
// gc.* and pack.* keys an ordinary `git clone --mirror` leaves behind. This
// is the accepted cost of the allowlist, not an oversight: a repository that
// reached the data directory by mirror or by out-of-band backup is refused
// until the key is unset. walden's own restore path is materialization from
// the journal, which produces repositories walden created.
//
// It is a compiled-in constant and must stay one. Making it configurable
// would be a sixth knob, and a knob whose setting is "serve this repository
// anyway" is the one setting that cannot be audited.
var initBareConfigKeys = map[string]struct{}{
	"core.repositoryformatversion": {},
	"core.filemode":                {},
	"core.bare":                    {},
	"core.ignorecase":              {},
	"core.precomposeunicode":       {},
	"extensions.objectformat":      {},
	"extensions.refstorage":        {},
}

// vouchedScopes are the git config scopes this check holds to the allowlist:
// the two that a repository's own directory can supply.
//
// This enumerates git's scope vocabulary, which is git's own and short, not a
// set of keys, which is neither. `local` is <repo>/config and everything an
// include.path in it pulls in; `worktree` is <repo>/config.worktree, which
// extensions.worktreeConfig turns on. Both travel with a repository directory,
// so both are what this check is about.
//
// The scopes left out are left out for a reason each, and the filter is
// explicit rather than "everything git reports must be allowlisted" because
// that spelling is wrong on a developer's Mac: Apple Git reads
// /Library/Developer/CommandLineTools/usr/share/git-core/gitconfig and reports
// its entries with scope `unknown` even with GIT_CONFIG_SYSTEM=/dev/null —
// verified on 2.50.1 (Apple Git-155), where a repository fresh out of `git
// init --bare` reports credential.helper and init.defaultbranch at that scope.
// A blanket rule would pass CI on Alpine, where only `local` ever appears, and
// refuse every repository on a Mac. `system` and `global` are pinned to
// /dev/null by the environment this probe and every other git child walden
// execs are given, so they describe nothing a repository carries; `command`
// is walden's own argv.
var vouchedScopes = map[string]struct{}{
	"local":    {},
	"worktree": {},
}

// maxVouchedKeyReport bounds how much of a key name reaches the refusal.
// Section and variable names are short and git-defined, but a subsection name
// between the two is arbitrary text out of the repository's own config file,
// and the refusal has to stay printable on one line.
const maxVouchedKeyReport = 120

// vouchProbeArgs are the arguments of the one question this check asks git,
// in the one place that spells them, so the probe the tests measure is the
// probe that runs.
//
// `--show-scope` is what makes the question answerable. The narrower
// `--list --local` cannot be used and the distinction is the whole check:
// `--local` does not expand include.path, and `git config --local --get`
// reports an included key as unset, exiting 1, while that key is in full
// effect for every other git command. Verified on 2.47.2, 2.50.1 and 2.54.0:
// on each, a config pulling in a file that sets a key listed `include.path`
// under `--list --local --name-only` while never listing the included key at
// all, exited 1 for `--local --get` of that key, and listed it at scope
// `local` under the arguments below. An audit built on `--local` fails open,
// which is the one way a check like this is worse than no check at all.
//
// `--name-only` is what keeps walden out of the business of config values:
// the output carries key names and no values whatsoever, so a hostile value
// is never read, never parsed and never logged. `-z` makes the framing
// unambiguous for the same reason a value would otherwise have to be quoted.
var vouchProbeArgs = []string{"config", "--list", "--show-scope", "--name-only", "-z"}

// VouchRepoConfig refuses, in one line, to serve the repository at repoPath
// if its own config carries a repository-scope key walden did not write.
//
// A config file travels with a repository directory, and a repository can
// reach the data directory by routes walden had no part in: a backup restored
// from elsewhere, a migration off another git server, a copy between walden
// instances. Some config keys name a command for git to run. walden pins the
// system and global scopes off for every git child it execs, which settles
// what the host can contribute and nothing about what the repository itself
// can — a repository-local key is honoured whatever those scopes say. So
// before a resolved path becomes an argument to a git child, walden asks what
// that repository's config sets and declines to serve one it cannot vouch
// for. See initBareConfigKeys for why the rule is an allowlist and what it
// costs.
//
// It takes a path rather than a repository identifier, as EnsureHook does and
// for the same reason: its callers have already resolved the path they are
// about to hand to git, and this has to be asked about that exact directory,
// not one resolved again afterwards.
//
// The question is put to git rather than answered from Go. Reading
// <repoPath>/config directly would mean owning git's config parser —
// include.path and its conditional forms, extensions.worktreeConfig,
// quoting, case folding — which is the reimplementation AGENTS.md's "wrap
// git" rule forbids and the mistake gitHookPath records having made three
// times. One exec answers it, and `git upload-pack` or `git receive-pack` is
// an exec a moment later anyway.
//
// A probe that cannot answer refuses. There is deliberately no "git printed
// nothing, so the repository is clean" branch: git exits non-zero here for
// reasons that have nothing to do with the repository — a fork that failed
// with EAGAIN or EMFILE, a data directory that stopped answering — and
// reading that as "clean" is the fail-open the check exists to prevent. Note
// that a vouched repository is not the empty case: `git init --bare` writes
// keys, so a probe that prints nothing at all has not answered either.
//
// The exec gets the request's context, a WaitDelay and its own process group,
// like every other git walden runs: it sits on the request path, and without
// them a stalled data directory would park the handler goroutine past the
// client's disconnect.
func (s *Store) VouchRepoConfig(ctx context.Context, repoPath string) error {
	env := []string{"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null"}
	if p := os.Getenv("PATH"); p != "" {
		env = append(env, "PATH="+p)
	}

	args := append([]string{"-C", repoPath}, vouchProbeArgs...)
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = env
	cmd.WaitDelay = gitWaitDelay
	setupProcessGroup(cmd)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// Both refusals below are path-free in every field, so githttp can put
	// either on the wire as it stands rather than replacing it with
	// something true of both — which is what writeAuthRefusal has to do for
	// ErrHookUnavailable, and why its wording had to be weakened to the one
	// thing true of five different failures. Keeping git's stderr and the
	// repository path in the log and out of the refusal is what buys that:
	// the operator log line is the detailed one, and it is written on every
	// branch that refuses.
	out, err := cmd.Output()
	if err != nil {
		log.Printf("store: %s: git %s failed: %v: %s",
			repoPath, strings.Join(vouchProbeArgs, " "), err, strings.TrimSpace(stderr.String()))
		return unvouchedProbeRefusal()
	}

	key, err := firstUnvouchedKey(out)
	if err != nil {
		log.Printf("store: %s: git %s: %v", repoPath, strings.Join(vouchProbeArgs, " "), err)
		return unvouchedProbeRefusal()
	}
	if key == "" {
		return nil
	}

	// The operator log carries the path, because the operator has to find the
	// repository; the refusal itself carries only the key, which is the
	// repository's own rather than anything about the server, and is the one
	// thing the remedy needs. The value is in neither: --name-only never read
	// it.
	log.Printf("store: %s: repository config sets %q, which walden did not write", repoPath, key)

	// The remedy names the key to unset only while the key is reported whole.
	// A subsection name is arbitrary text out of the repository's own config
	// file, so an absurdly long one is elided to keep the refusal on one line
	// — and a `git config --unset` of an elided key would be a command that
	// does not work, so that case gets the remedy that does.
	if len(key) > maxVouchedKeyReport {
		return refusal.RefuseWithCause(
			"repository config unvouched",
			fmt.Sprintf("this repository's config sets %s..., which walden did not write", key[:maxVouchedKeyReport]),
			"unset that key in the repository, or serve a repository walden created",
			ErrRepoConfigUnvouched,
		)
	}
	return refusal.RefuseWithCause(
		"repository config unvouched",
		fmt.Sprintf("this repository's config sets %s, which walden did not write", key),
		fmt.Sprintf("unset it in the repository — git config --unset %s — or serve a repository walden created", key),
		ErrRepoConfigUnvouched,
	)
}

// unvouchedProbeRefusal is the refusal for a probe that could not answer, as
// distinct from one that answered with a key walden cannot vouch for. It
// claims no cause beyond that, because the thing that says which failure it
// was — git's stderr, or what its output looked like — is in the log line
// its caller has just written, and is the one part of this check that could
// carry a server path.
func unvouchedProbeRefusal() error {
	return refusal.RefuseWithCause(
		"repository config unvouched",
		"walden could not read this repository's own config, so it will not serve it",
		"contact the operator",
		ErrRepoConfigUnvouched,
	)
}

// firstUnvouchedKey returns the first key in a vouchProbeArgs output that is
// at a vouched scope and outside initBareConfigKeys, or "" when every such key
// is allowlisted. An output it cannot read as scope/key pairs is an error, not
// an empty answer.
//
// The framing is `scope\0key\0` repeated, NUL-terminated, with no values and
// no newlines — verified byte-for-byte on 2.47.2, 2.50.1 and 2.54.0, where a
// freshly initialized bare repository printed
// "local\x00core.repositoryformatversion\x00local\x00core.filemode\x00local\x00core.bare\x00".
// Splitting on NUL therefore yields pairs followed by one empty trailing
// field; an odd count means the output was not what this parser was written
// against, and it says so rather than vouching for what it could read.
//
// git lowercases section and variable names and preserves a subsection's
// case, so an allowlist of keys that take no subsection is matched exactly as
// printed: `[CORE] BARE` reaches here as core.bare, while any key carrying a
// subsection has a third component and cannot collide with an entry.
func firstUnvouchedKey(out []byte) (string, error) {
	fields := strings.Split(string(out), "\x00")
	if n := len(fields); n == 0 || fields[n-1] != "" {
		return "", fmt.Errorf("git printed a config listing that is not NUL-terminated")
	}
	fields = fields[:len(fields)-1]
	if len(fields) == 0 {
		return "", fmt.Errorf("git printed no config keys at all for this repository")
	}
	if len(fields)%2 != 0 {
		return "", fmt.Errorf("git printed %d config fields, which do not pair into scopes and keys", len(fields))
	}

	for i := 0; i < len(fields); i += 2 {
		scope, key := fields[i], fields[i+1]
		if _, ok := vouchedScopes[scope]; !ok {
			continue
		}
		if _, ok := initBareConfigKeys[key]; ok {
			continue
		}
		return key, nil
	}
	return "", nil
}
