package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
	"github.com/writtendev/walden/internal/store"
)

// hookRequest is the parsed shape of one pre-receive invocation: the
// environment resolveHook read (WALD-43, plus WALD-44's quarantine
// directory) and the ref updates parseRefUpdates read off stdin. WALD-46
// makes the exit code depend on whether the journal append landed.
// Nothing else needs to grow.
type hookRequest struct {
	Repo     string         // WALDEN_REPO
	DataDir  string         // WALDEN_DATA_DIR
	RepoPath string         // resolved bare repo path
	Journal  *store.Journal // nil in journal-less mode
	// Quarantine is GIT_QUARANTINE_PATH, cleaned and absolute. Empty
	// means git created no quarantine directory for this push, which is
	// what a delete-only push looks like: no objects were received, so
	// there is nothing to capture. It is not a refusal.
	Quarantine string
	Updates    []journal.RefUpdate
}

// parseRefUpdates reads git's pre-receive stdin protocol: one
// "<old-oid> SP <new-oid> SP <ref-name>" triple per line. Spec §5.2
// forbids a space in a ref name (ValidateRefName below refuses one as a
// control/whitespace character), so splitting on the first two spaces only
// is exact: everything after the second space is the ref name, taken
// verbatim, with no trimming or normalization, preserving its raw bytes.
//
// Each triple is checked with journal.ValidateRefUpdate, which already
// composes the ref name, OID shape, mismatched-length, zero-to-zero, and
// no-op rules, and the set as a whole is checked for a duplicate ref name,
// which spec §5.1 refuses. scanner.Err() is checked once scanning ends, so
// a line longer than the scanner's buffer is a refusal, not a silent
// truncation.
func parseRefUpdates(r io.Reader) ([]journal.RefUpdate, error) {
	var updates []journal.RefUpdate
	seenRefs := make(map[string]bool)

	scanner := bufio.NewScanner(r)
	scanner.Split(splitRawLines)
	for scanner.Scan() {
		line := scanner.Text()

		firstSP := strings.IndexByte(line, ' ')
		if firstSP < 0 {
			return nil, refusePreReceiveLine(line)
		}
		rest := line[firstSP+1:]
		secondSP := strings.IndexByte(rest, ' ')
		if secondSP < 0 {
			return nil, refusePreReceiveLine(line)
		}

		u := journal.RefUpdate{
			OldOID: line[:firstSP],
			NewOID: rest[:secondSP],
			Ref:    rest[secondSP+1:],
		}
		if err := journal.ValidateRefUpdate(u); err != nil {
			return nil, refusal.RefuseWithCause("pre-receive refused", err.Error(), "", err)
		}
		if seenRefs[u.Ref] {
			return nil, refusal.Refuse(
				"pre-receive refused",
				fmt.Sprintf("duplicate ref update for %q", u.Ref),
				"",
			)
		}
		seenRefs[u.Ref] = true
		updates = append(updates, u)
	}
	if err := scanner.Err(); err != nil {
		return nil, refusal.RefuseWithCause(
			"pre-receive refused",
			fmt.Sprintf("reading stdin: %s", err.Error()),
			"",
			err,
		)
	}
	return updates, nil
}

// splitRawLines is a bufio.SplitFunc that splits stdin on '\n' and nothing
// else. It exists because bufio.ScanLines, the Scanner default, drops a
// trailing '\r' unconditionally, which would rewrite a ref name ending in
// a carriage return into a different, shorter name. git receive-pack does
// not check refname format before running pre-receive -- its "funny
// refname" check runs afterwards -- so a hostile client can put
// "refs/heads/x\r" on this reader, and ScanLines would normalize it into
// "refs/heads/x": a ref name nobody pushed, which ValidateRefName would
// then accept. Spec §5.2 requires ref names to be treated as exact,
// opaque byte sequences, so the '\r' stays in the token and
// journal.ValidateRefName -- which owns the question and refuses any byte
// <= 0x20 -- refuses it.
//
// Apart from the missing dropCR this is bufio.ScanLines: a final line with
// no newline is still a token, and an empty line is still an empty token
// (refused below for carrying no spaces). Returning 0, nil, nil when no
// newline is in the buffer leaves Scanner's own ErrTooLong intact for a
// line longer than its buffer.
func splitRawLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// refusePreReceiveLine refuses a pre-receive stdin line that does not carry
// two spaces, so old_oid, new_oid, and ref cannot all be present.
func refusePreReceiveLine(line string) error {
	return refusal.Refuse(
		"pre-receive refused",
		fmt.Sprintf("malformed line: expected \"<old-oid> <new-oid> <ref>\", got %q", line),
		"",
	)
}

// resolveHook resolves one pre-receive invocation's repository, data
// directory, and journal purely from the environment
// internal/githttp/receivepack.go already sets (WALDEN_REPO,
// WALDEN_DATA_DIR, WALDEN_JOURNAL), through an injected lookupEnv so tests
// do not depend on process environment.
//
// It deliberately does not call config.Load: the hook takes no flags and
// has no defaults to fall back on -- a missing WALDEN_DATA_DIR means
// something other than walden's own receive-pack handler ran this binary,
// and guessing /data there is exactly the guess PHILOSOPHY.md's "failures
// must be legible" section forbids. The repo path comes from
// store.New(dataDir).RepoPath(repo) and its existence from RepoExists, so
// identifier syntax and data-directory containment are checked by the one
// place that already owns those rules, not re-derived here. The journal,
// when WALDEN_JOURNAL is set, is resolved with store.ResolveJournal --
// URL and credentials, no network request; the boot path's ProbeCAS is not
// repeated on every push.
func resolveHook(ctx context.Context, lookupEnv func(string) (string, bool), updates []journal.RefUpdate) (*hookRequest, error) {
	repo, ok := lookupEnv("WALDEN_REPO")
	if !ok || repo == "" {
		return nil, refusePreReceiveEnv("WALDEN_REPO")
	}
	dataDir, ok := lookupEnv("WALDEN_DATA_DIR")
	if !ok || dataDir == "" {
		return nil, refusePreReceiveEnv("WALDEN_DATA_DIR")
	}

	s := store.New(dataDir)
	repoPath, err := s.RepoPath(repo)
	if err != nil {
		return nil, err
	}
	exists, err := s.RepoExists(ctx, repo)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, refusal.RefuseWithCause(
			"pre-receive refused",
			fmt.Sprintf("repository %q does not exist under %s", repo, dataDir),
			"",
			store.ErrRepoNotFound,
		)
	}

	var jrnl *store.Journal
	if journalURL, ok := lookupEnv("WALDEN_JOURNAL"); ok && journalURL != "" {
		jrnl, err = store.ResolveJournal(journalURL, lookupEnv)
		if err != nil {
			return nil, err
		}
	}

	quarantine, err := resolveQuarantine(lookupEnv, repoPath)
	if err != nil {
		return nil, err
	}

	return &hookRequest{
		Repo:       repo,
		DataDir:    dataDir,
		RepoPath:   repoPath,
		Journal:    jrnl,
		Quarantine: quarantine,
		Updates:    updates,
	}, nil
}

// resolveQuarantine locates the directory git received this push's objects
// into (WALD-44). There are three cases and deliberately no fourth:
//
//   - GIT_QUARANTINE_PATH set: cleaned, made absolute, and required to sit
//     inside repoPath. git spells it "<repo.git>/./objects/tmp_objdir-
//     incoming-XXXXXX" -- the "/./" comes from GIT_DIR being "." -- so the
//     clean is load-bearing, not cosmetic. A path resolving outside the
//     repository is a one-line refusal.
//   - Neither variable set: the empty string. This is a delete-only push;
//     git creates no quarantine directory when no objects are received, so
//     there is genuinely nothing to capture.
//   - GIT_QUARANTINE_PATH unset but GIT_OBJECT_DIRECTORY set: a one-line
//     refusal. Objects landed somewhere walden is not looking, and
//     journaling nothing for them would be a guess. internal/githttp/
//     receivepack.go builds an explicit allowlist environment, so no
//     inherited GIT_OBJECT_DIRECTORY can reach the hook and produce this
//     state innocently.
//
// The two variables are deliberately not required to be byte-equal even
// though git sets them to the same value today: githooks(5) documents
// GIT_QUARANTINE_PATH as the variable a pre-receive hook reads, so it is
// the single authority here, and an equality check would turn a future
// git's harmless divergence into a refused push.
//
// The containment test runs against a symlink-resolved repoPath because
// git's side is already resolved: it derives GIT_QUARANTINE_PATH from
// getcwd() after chdir'ing into the repository, so every symlink in the
// path it was handed is gone by the time the hook reads it. store.RepoPath
// resolves the data directory but deliberately leaves the "<repo>.git"
// leaf as written, so a repository that is itself a symlink -- an operator
// moving one big repository onto another volume -- would otherwise put the
// test on two spellings of the same directory and refuse every push to it
// (round 1 finding 2). abs is left as git wrote it, since git sets that
// variable and creates the directory itself, so there is no
// attacker-influenced input on this path to resolve away.
func resolveQuarantine(lookupEnv func(string) (string, bool), repoPath string) (string, error) {
	quarantine, _ := lookupEnv("GIT_QUARANTINE_PATH")
	if quarantine == "" {
		if objectDir, _ := lookupEnv("GIT_OBJECT_DIRECTORY"); objectDir != "" {
			return "", refusal.Refuse(
				"pre-receive refused",
				fmt.Sprintf("GIT_QUARANTINE_PATH is not set but GIT_OBJECT_DIRECTORY is (%s), so the received objects are somewhere walden cannot journal them from", objectDir),
				"push through walden's own receive-pack handler, which leaves git's quarantine mechanism alone",
			)
		}
		return "", nil
	}

	abs, err := filepath.Abs(quarantine)
	if err != nil {
		return "", refusal.RefuseWithCause(
			"pre-receive refused",
			fmt.Sprintf("cannot resolve GIT_QUARANTINE_PATH %q: %s", quarantine, err.Error()),
			"",
			err,
		)
	}
	abs = filepath.Clean(abs)
	root, err := filepath.EvalSymlinks(repoPath)
	if err != nil {
		return "", refusal.RefuseWithCause(
			"pre-receive refused",
			fmt.Sprintf("cannot resolve the repository path %s: %s", repoPath, err.Error()),
			"verify the repository path is accessible",
			err,
		)
	}
	within, err := dirWithin(abs, root)
	if err != nil {
		return "", refusal.RefuseWithCause(
			"pre-receive refused",
			fmt.Sprintf("cannot tell whether GIT_QUARANTINE_PATH %s is inside the repository at %s: %s", abs, root, err.Error()),
			"verify both paths are readable by the user running receive-pack",
			err,
		)
	}
	if !within {
		return "", refusal.Refuse(
			"pre-receive refused",
			fmt.Sprintf("GIT_QUARANTINE_PATH %s is not inside the repository directory %s", abs, root),
			"these are different directories on disk, not two spellings of one: check --data-dir against the path git serves this repository from",
		)
	}
	return abs, nil
}

// dirWithin reports whether path is root itself or a descendant of it,
// asking the filesystem rather than comparing spellings: it walks path's
// ancestors and stops at the first one os.SameFile says is root. Both
// arguments must already be absolute and cleaned.
//
// A separator-terminated prefix test -- what internal/store/store.go's
// pathWithinRoot makes of two paths walden itself constructed -- is the
// wrong instrument for these two, because walden constructs neither side.
// root carries the operator's spelling of --data-dir; abs carries the
// on-disk spelling, because git builds GIT_QUARANTINE_PATH from getcwd().
// On a case-insensitive filesystem -- APFS, NTFS, the SMB and exFAT
// volumes PHILOSOPHY.md's NAS in a closet is made of -- a --data-dir
// cased differently from the directory it names makes those two spellings
// differ in nothing but case, and a prefix test refuses every push to
// every repository (round 2 finding 1). Case-folding the comparison would
// fix that one filesystem by breaking another: where case is significant,
// two paths differing only in case are two directories, and folding them
// together would make this check pass on a quarantine outside the
// repository. Identity is the question actually being asked, and stat
// answers it in the filesystem's own terms on both kinds.
//
// Resolving the ancestors this way follows a symlink where a prefix test
// would not, which is the same correction in another spelling and not a
// loosening: a path whose ancestor *is* the repository directory is a
// path inside the repository, however it is written. Cost is one Stat per
// component of a path that is about to be read anyway.
func dirWithin(path, root string) (bool, error) {
	rootInfo, err := os.Stat(root)
	if err != nil {
		return false, err
	}
	for p := path; ; {
		// A leaf that is not there yet still has ancestors worth asking
		// about, so a missing component is not an answer.
		switch info, err := os.Stat(p); {
		case err == nil:
			if os.SameFile(info, rootInfo) {
				return true, nil
			}
		case !errors.Is(err, fs.ErrNotExist):
			return false, err
		}
		parent := filepath.Dir(p)
		if parent == p {
			return false, nil
		}
		p = parent
	}
}

// captureSegment opens the packfile git's index-pack left in this push's
// quarantine directory, ready to be appended as one segment. It returns a
// nil file when this push has no segment to journal, which is not an
// error: a delete-only push has no quarantine directory at all, and a push
// that only moves a ref to an object the repository already holds leaves a
// 32-byte pack whose header declares zero objects. Both journal a ref
// transaction with no segments, which spec/journal/v1 section 5.1 permits
// explicitly.
//
// "No packfile" and "no objects" are not the same statement, and
// quarantineWithoutPack below is what keeps them apart: git unpacks a
// small push into loose objects rather than a pack unless
// receive.unpackLimit=0 is set, and internal/githttp/receivepack.go sets
// it on every receive-pack it starts. Trusting that knob alone would mean
// journaling "this push introduced no objects" for a quarantine full of
// objects the moment the knob ever failed to take -- a future git, a
// receive-pack walden did not start -- with nothing on the machine
// noticing. So the absence of a pack is a question, not an answer.
//
// Only the pack's leading header bytes are read here, through
// journal.PackfileObjectCount; the returned *os.File is handed to
// (*store.Client).AppendSegment as the io.ReaderAt it wants, so the pack's
// bytes are streamed from disk and never buffered in memory. walden does
// not decompress an entry or resolve a delta -- git already did all of
// that, and this opens the file git wrote and PUTs it verbatim.
//
// The caller closes a non-nil file.
func captureSegment(req *hookRequest) (*os.File, int64, error) {
	if req.Quarantine == "" {
		return nil, 0, nil
	}

	packDir := filepath.Join(req.Quarantine, "pack")
	entries, err := os.ReadDir(packDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// git creates pack/ lazily; no directory means index-pack
			// wrote no pack. Whether that means this push carried no
			// objects is the quarantine directory's own contents to
			// answer, not pack/'s absence.
			return nil, 0, quarantineWithoutPack(req.Quarantine, nil)
		}
		return nil, 0, refusal.RefuseWithCause(
			"pre-receive refused",
			fmt.Sprintf("cannot read the quarantine pack directory %s: %s", packDir, err.Error()),
			"",
			err,
		)
	}

	// index-pack writes a .idx, a .keep, and a .rev beside the .pack;
	// only the .pack is the segment.
	var packs []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".pack") {
			packs = append(packs, e.Name())
		}
	}

	switch len(packs) {
	case 0:
		return nil, 0, quarantineWithoutPack(req.Quarantine, entries)
	case 1:
	default:
		// One push is one index-pack, so more than one pack is a shape
		// walden does not understand. Picking one would be a guess.
		return nil, 0, refusal.Refuse(
			"pre-receive refused",
			fmt.Sprintf("quarantine directory %s holds %d packfiles, expected exactly one", packDir, len(packs)),
			"",
		)
	}

	packPath := filepath.Join(packDir, packs[0])
	f, err := os.Open(packPath)
	if err != nil {
		return nil, 0, refusal.RefuseWithCause(
			"pre-receive refused",
			fmt.Sprintf("cannot open the quarantined packfile %s: %s", packPath, err.Error()),
			"",
			err,
		)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, refusal.RefuseWithCause(
			"pre-receive refused",
			fmt.Sprintf("cannot size the quarantined packfile %s: %s", packPath, err.Error()),
			"",
			err,
		)
	}

	// ReadAt, not Read: it leaves the file offset at 0, so the *os.File
	// handed to AppendSegment below is positioned exactly as that method
	// expects to find it. PackfileMinSize bytes rather than
	// PackfileHeaderSize, because ValidatePackfileHeader -- which
	// PackfileObjectCount calls for the validation half -- refuses
	// anything shorter than a whole minimal packfile, and a pack too
	// short to hold its own trailing checksum is a refusal here rather
	// than a segment walden uploads and a reader later chokes on.
	var hdr [journal.PackfileMinSize]byte
	if n, err := f.ReadAt(hdr[:], 0); n < len(hdr) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		f.Close()
		return nil, 0, refusal.RefuseWithCause(
			"pre-receive refused",
			fmt.Sprintf("cannot read the header of the quarantined packfile %s: %s", packPath, err.Error()),
			"",
			err,
		)
	}
	count, err := journal.PackfileObjectCount(hdr[:])
	if err != nil {
		f.Close()
		return nil, 0, refusal.RefuseWithCause(
			"pre-receive refused",
			fmt.Sprintf("quarantined packfile %s: %s", packPath, err.Error()),
			"",
			err,
		)
	}
	if count == 0 {
		// A ref moved to an object the repository already holds: git
		// still writes a pack, but it is the empty one. Journal the ref
		// transaction and no segment.
		f.Close()
		return nil, 0, nil
	}

	return f, info.Size(), nil
}

// quarantineWithoutPack answers the one question captureSegment cannot
// read out of pack/: a quarantine directory with no packfile in it either
// received no objects at all, or received them as loose objects walden
// has no segment to journal. The first is legitimate and journals a ref
// transaction with no segments; the second is walden unable to keep its
// one promise, so it is a one-line refusal and the push does not happen.
// Returning nil for both -- which is what reading "no pack" as "no
// objects" amounts to -- would acknowledge a push whose objects are in no
// journal anywhere, and would do it silently.
//
// The two are told apart by an allowlist, and it has to be one. A
// quarantine that received nothing holds nothing but an empty pack/ and,
// at most, info/ -- that is the whole of the shape git leaves. So this
// asks whether the directory is that shape rather than whether it holds
// one of the things walden knows to look for. Enumerating the evidence would leave the next
// unfamiliar entry reading as "no objects here", which is the one answer
// this function must never give by default, and it is the answer a
// denylist gives to everything it has not met: a pack/ holding an .idx,
// .keep or .rev with no .pack beside it -- index-pack's own footprint
// minus the file that matters -- is exactly the git-changed-under-us case
// this check exists for, and it named no loose object (round 2 finding 2).
// packEntries is what captureSegment already read out of pack/, nil when
// there was no pack/ at all; either way, none of it is a packfile, so any
// entry in it is evidence.
//
// This reads directory names only; it does not open, decompress, or
// otherwise interpret an object, so wrapping git rather than
// reimplementing it (mechanical rule 5) is intact.
//
// A quarantine directory that cannot be read at all -- including one that
// is not there, although git creates it before running this hook -- is a
// refusal too, for the same reason: walden cannot see what it received.
func quarantineWithoutPack(quarantine string, packEntries []os.DirEntry) error {
	entries, err := os.ReadDir(quarantine)
	if err != nil {
		return refusal.RefuseWithCause(
			"pre-receive refused",
			fmt.Sprintf("cannot read the quarantine directory %s: %s", quarantine, err.Error()),
			"",
			err,
		)
	}

	var unexpected, fanout []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() && (name == "pack" || name == "info") {
			continue
		}
		unexpected = append(unexpected, name)
		if e.IsDir() && isFanoutDir(name) {
			fanout = append(fanout, name)
		}
	}

	switch {
	case len(fanout) > 0:
		// The common shape by far, and worth naming as itself: git's
		// default receive.unpackLimit unpacked this push.
		return refuseQuarantineWithoutPack(quarantine,
			fmt.Sprintf("loose objects (%d fan-out directories, including %s)", len(fanout), fanout[0]))
	case len(unexpected) > 0:
		return refuseQuarantineWithoutPack(quarantine,
			fmt.Sprintf("%q, which a quarantine that received nothing never holds (only pack/ and info/)", unexpected[0]))
	case len(packEntries) > 0:
		return refuseQuarantineWithoutPack(quarantine,
			fmt.Sprintf("pack/%s with no packfile beside it", packEntries[0].Name()))
	}
	return nil
}

// refuseQuarantineWithoutPack states the one conclusion quarantineWithoutPack
// draws, with the evidence for it spliced in: whatever walden found, it is
// not a packfile, so this push received objects walden has no segment for.
func refuseQuarantineWithoutPack(quarantine, evidence string) error {
	return refusal.Refuse(
		"pre-receive refused",
		fmt.Sprintf("quarantine directory %s holds %s but no packfile, so this push carries objects walden cannot journal", quarantine, evidence),
		"run receive-pack with -c receive.unpackLimit=0 so git leaves every received push in a packfile",
	)
}

// isFanoutDir reports whether name is one of the two-hex-character
// directories git splits loose objects into -- "3c" holding the objects
// whose id starts with those digits. It no longer decides anything; the
// allowlist above does that, and an entry this rejects is refused anyway.
// What it still decides is what the operator is told, and uppercase is
// accepted as well as the lowercase git writes today so that a git which
// changed its spelling is still reported as the loose objects it left.
func isFanoutDir(name string) bool {
	if len(name) != 2 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// journalPush appends this push to the journal: the quarantined packfile
// as one segment, then the ref transaction naming it (WALD-44).
//
// The order of the four steps is deliberate and is the whole of this
// function's design:
//
//  1. captureSegment is local-only and cheapest, so a malformed quarantine
//     refuses having made no network call at all.
//  2. LoadSigner and Leases.Open run before AppendSegment, so a journal
//     with no genesis record, a local signing key that is not the chain's
//     active one, or an already-fenced stream refuses without first
//     leaving an orphan segment in the bucket.
//  3. AppendSegment runs before AppendRefTx, because spec/journal/v1
//     section 5 requires a segment to be acknowledged before the record
//     that names it -- AppendRefTx's own doc comment says it neither
//     writes segments nor checks that they exist. An orphan segment left
//     by a crash between the two is explicitly harmless (section 6.4 and
//     ARCHITECTURE.md's failure table): the client retries, and
//     AppendSegment's unconditional PUT of identical bytes is a no-op
//     success.
//
// Nothing here hands a closure to (*journal.Lease).Append: the journal is
// reached through (*store.Client).AppendSegment, which is an unconditional
// PUT that never touches a lease, and (*store.Client).AppendRefTx, whose
// own prepare closure only builds, signs, and marshals bytes. WALD-118's
// contract -- that a caller panic inside prepare must not permanently
// fence a healthy stream -- is therefore inherited unchanged and needs no
// code here.
//
// now is a parameter so a test can hold the clock still; runPreReceive
// passes time.Now.
//
// What this does not own: making exit 0 mean "storage acknowledged both
// records". A failure here is returned as an ordinary one-line refusal
// and main() already turns that into a non-zero exit, but proving that is
// always enough -- across every injected failure point -- is WALD-46.
func journalPush(ctx context.Context, req *hookRequest, now func() time.Time) error {
	stream := journal.StreamID(req.Repo)
	client := store.NewClient(req.Journal)

	seg, size, err := captureSegment(req)
	if err != nil {
		return err
	}
	if seg != nil {
		defer seg.Close()
	}

	signer, err := client.LoadSigner(ctx, req.DataDir)
	if err != nil {
		return err
	}

	lease, err := journal.NewLeases(client).Open(ctx, stream)
	if err != nil {
		return err
	}

	var segments []string
	if seg != nil {
		hash, err := client.AppendSegment(ctx, stream, seg, size)
		if err != nil {
			return err
		}
		segments = []string{hash}
	}

	_, err = client.AppendRefTx(ctx, lease, signer, segments, req.Updates, now)
	return err
}

// refusePreReceiveEnv refuses a pre-receive invocation missing one of the
// environment variables internal/githttp/receivepack.go always sets before
// exec'ing git receive-pack: seeing this refusal means something other
// than walden's own receive-pack handler invoked this binary as the hook.
func refusePreReceiveEnv(name string) error {
	return refusal.Refuse(
		"pre-receive refused",
		fmt.Sprintf("%s is not set", name),
		"run this binary only as git's pre-receive hook, invoked by walden's own receive-pack handler",
	)
}
