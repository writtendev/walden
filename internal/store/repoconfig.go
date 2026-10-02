package store

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"unicode/utf8"

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
//   - core.symlinks when the git directory's own filesystem has no real
//     symlink support. Measured on 2.47.2 against a FAT32 volume, where the
//     same `git init --bare --template=` wrote repositoryformatversion,
//     filemode, symlinks and ignorecase under [core], all at scope local.
//     git writes it from create_default_files, in the block that probes the
//     git directory for symlink support — which sits outside the
//     is_bare_repository() branch that gates core.logallrefupdates, so a
//     bare init reaches it like any other. It is the third of three
//     filesystem-conditional keys here, alongside core.ignorecase and
//     core.precomposeunicode, and it is as plainly inert as those two.
//   - extensions.objectformat and extensions.refstorage on all three, from
//     `--object-format=sha256` and `--ref-format=reftable` respectively.
//     walden passes neither flag, so these appear only if a future git
//     changes which format `git init` defaults to. They are admitted ahead
//     of that so the upgrade does not make walden refuse every repository it
//     created itself.
//
// TestInitBareKeysAreAllowlisted is what notices if the relationship stops
// holding, and what it covers is narrower than it looks: it runs a real `git
// init --bare` on the filesystem the test host gives it, so it catches
// version drift and only such host drift as that filesystem exhibits. No
// single host shows all three filesystem-conditional keys — a Linux CI
// runner shows none of them, a Mac shows two, and a volume without symlink
// support shows core.symlinks, which that test does observe when pointed at
// one but no machine in regular use here can arrange.
// TestVouchRepoConfigAcceptsConditionalInitKeys holds that key on every host
// instead; both tests state in their own words what they do and do not see.
//
// Keys that `git init --bare` does not write are deliberately absent, even
// where they are plainly inert. core.logallrefupdates is the instructive one:
// a non-bare `git init` writes it (verified on all three), a bare one never
// does, so it is not walden's to vouch for. A `git clone --bare` or `git
// clone --mirror` output is outside the allowlist for the same reason, on the
// remote.origin.* keys clone writes: measured on 2.47.2, a bare clone adds
// remote.origin.url and a mirror adds remote.origin.url, remote.origin.fetch
// and remote.origin.mirror (2.50.1 adds remote.origin.tagopt to the mirror as
// well), and neither adds anything beyond those — in particular not
// core.logallrefupdates, which a clone can only get from the non-bare branch
// above, and a mirror or bare clone is bare. This is the accepted cost of the
// allowlist, not an oversight: a repository that reached the data directory by
// mirror or by out-of-band backup is refused until the key is unset. walden's
// own restore path is materialization from the journal, which produces
// repositories walden created.
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
	"core.symlinks":                {},
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
//
// It bounds the whole rendered key, not one shape of it, because git's config
// parser bounds none of a key's three components. A section, a subsection and
// a variable are each as long as the repository's own config file made them,
// and the refusal has to stay printable on one line. Measured on 2.50.1
// (Apple Git-155), a repository whose config carried a 4096-byte dot-free
// section — and separately one whose config carried a 4096-byte variable
// under a short section — was listed by vouchProbeArgs with that run intact
// in the key name, so a renderer that bounds only some shapes puts the file's
// own length on the wire.
const maxVouchedKeyReport = 120

// redactedSubsection stands in for a subsection name in the refusal a
// requester receives.
//
// A key's section and variable are git's own vocabulary; a subsection between
// them is arbitrary text the repository supplied, and in the keys most likely
// to travel with a repository that came from somewhere else it is a URL —
// which is how a credential ends up in a key *name*. `--name-only` withholds
// every config value, but it cannot withhold that, and the refusal body goes
// to whoever made the request: any holder of a valid token for the
// repository, over routes that need only `r`. <repo>/config is not otherwise
// readable over the git protocol, so putting a subsection on the wire would
// be a disclosure walden does not currently make.
//
// So the wire gets the section.variable shape and the operator log gets the
// key whole. That is the same split this file already applies to the
// repository path and to git's stderr, and the same rule the contributor
// guidance states for a journal URL and for any hash-shaped field that might
// be a live credential. The refusal still tells an operator which key is at
// issue to within its section and variable, which is what done-when #5 asks
// of it; `git config --list --show-scope` on the box holding the repository
// gives them the subsection, and that is a place the secret already is.
const redactedSubsection = "<redacted>"

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
	// repository, and the key whole, because that is where the remedy is
	// spelled out in full. The value is in neither: --name-only never read it.
	// This line is written on every branch that refuses, so whatever the wire
	// withholds, the operator has it.
	log.Printf("store: %s: repository config sets %q, which walden did not write", repoPath, key)

	// The remedy names the key to unset only while the key reaches the wire
	// whole — a `git config --unset` of a redacted or elided key would be a
	// command that does not work, so those cases get the remedy that does.
	// Both forms report the key through %q: a key name carries arbitrary
	// bytes out of the repository's own config file, and this refusal is
	// rendered on an operator's terminal and in an HTTP response body.
	// Quoting is what keeps a control byte in it from being acted on there,
	// and it makes the unset command copy-pasteable for a key that needs it.
	shown, whole := reportableKey(key)
	if !whole {
		return refusal.RefuseWithCause(
			"repository config unvouched",
			fmt.Sprintf("this repository's config sets %q, which walden did not write", shown),
			"unset that key in the repository, or serve a repository walden created",
			ErrRepoConfigUnvouched,
		)
	}
	return refusal.RefuseWithCause(
		"repository config unvouched",
		fmt.Sprintf("this repository's config sets %q, which walden did not write", shown),
		fmt.Sprintf("unset it in the repository — git config --unset %q — or serve a repository walden created", shown),
		ErrRepoConfigUnvouched,
	)
}

// reportableKey renders key for the refusal a requester receives, and reports
// whether what it returns is the whole key — which is what decides whether the
// remedy can name a `git config --unset` that would work.
//
// git prints a key canonically as section.variable or
// section.subsection.variable. Section and variable names carry no dots and
// are lowercased by git; a subsection is arbitrary text and may contain any
// number of them. So the first dot ends the section, the last begins the
// variable, and anything between the two is subsection — redacted, for the
// reason redactedSubsection gives.
//
// The two things this does compose, in this order, rather than sitting on
// separate paths: redaction first, so a subsection never reaches the wire
// whole or in part, then maxVouchedKeyReport over whatever redaction left.
// Both are needed on the same key. Redaction alone leaves the section and
// variable, which git does not bound either; the bound alone would put a
// subsection on the wire. A key with no subsection and inside the bound comes
// back untouched and whole, which is what lets the remedy name an unset
// command that works.
//
// The bound cuts on a rune boundary: slicing bytes would put a partial rune on
// the wire, which is how an elided key stops being valid UTF-8.
func reportableKey(key string) (shown string, whole bool) {
	shown, whole = key, true
	first := strings.Index(key, ".")
	if last := strings.LastIndex(key, "."); first >= 0 && first != last {
		shown, whole = key[:first+1]+redactedSubsection+key[last:], false
	}
	if len(shown) > maxVouchedKeyReport {
		shown, whole = truncateAtRune(shown, maxVouchedKeyReport)+"...", false
	}
	return shown, whole
}

// truncateAtRune returns the longest prefix of s that is at most max bytes and
// does not end inside a rune.
func truncateAtRune(s string, max int) string {
	if len(s) <= max {
		return s
	}
	for max > 0 && !utf8.RuneStart(s[max]) {
		max--
	}
	return s[:max]
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
