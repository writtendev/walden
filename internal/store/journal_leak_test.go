package store_test

import (
	"math/rand"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/config"
	"github.com/writtendev/walden/internal/store"
)

// This file holds one test: the guarantee that a journal URL's secret never
// reaches an operator-facing line, whatever the URL looks like.
//
// It imports internal/config, which internal/store does not and must not. The
// guarantee is about the boot path, and the boot path is config.Load, then
// config.Validate, then store.ResolveJournal, then --print-config's
// Journal.String(). A test that covered only this package's half would be the
// same mistake the first version of the leak test made: proving the safe half.

// The sentinel credentials. The secret is built in three-character groups that
// each end in a digit, so that every three-character window of it contains a
// digit and cannot collide with ordinary refusal prose.
const (
	leakKeyID  = "PUBLICKEYIDEXAMPLE"
	leakSecret = "Zq7Xv2Kw9Bm4Tn6Rp8Lc"
)

// leakIterations is the number of URLs the generator builds. It is small
// enough to disappear into a CI run; set WALDEN_LEAK_ITERATIONS to run the
// same generator, from the same seed, much harder locally.
const leakIterations = 3000

// leakSeed is fixed, so a failure is reproducible from the reported URL and a
// green run means the same thing on every machine.
const leakSeed = 18

// leakManglers are the ways a secret gets away from net/url: a delimiter that
// ends the authority early, a broken percent escape, a byte no URL may carry.
// The empty string is in the list because a correctly written URL has to pass
// through the same assertions.
var leakManglers = []string{
	"", "/", "?", "#", "@", "%", ":", "//", "..",
	"%zz", "%2", "%", "%40", "%3A", "%2F",
	"012/", "9000/", "80x/", ":/", ":012/",
	" ", "\t", "\n", "\r", "\x00", "\x01", "\x7f",
	"é", "🔥", "\\", "[", "]", "<", ">", "\"",
	strings.Repeat("x", 300),
}

// leakHosts are the authority shapes the parser reads differently.
var leakHosts = []string{
	"bucket",
	"my-bucket",
	"my.dotted.bucket",
	"s3.eu-west-1.amazonaws.com",
	"s3-fips.us-east-1.amazonaws.com",
	"s3-accelerate.amazonaws.com",
	"my-bucket.s3.amazonaws.com",
	"s3.wasabisys.com",
	"a1b2c3.r2.cloudflarestorage.com",
	"storage.googleapis.com",
	"minio.internal:9000",
	"[::1]:9000",
	"minio.local:",
	"amazonaws.com",
}

var (
	leakSchemes = []string{"s3", "https", "http", "ftp", ""}
	leakPaths   = []string{"", "/", "/walden", "/my-bucket/walden", "/backups/walden/", "/../escape"}
	leakQueries = []string{
		"", "?region=eu-west-1", "?style=path", "?style=virtual",
		"?REGION=EU-WEST-1", "?region=eu-west-1&style=path", "?acl=public",
		"?region=eu-west-1&region=ap-south-1",
	}
	leakPads = []string{"", " ", "\n", "\t ", " \r\n"}
)

// TestJournalRefusalsHideTheSecretRandomized is the standing guarantee behind
// guardCredentials: across every mangling of a journal URL this generator can
// build, nothing walden prints — no refusal, no --print-config line, and no
// field of the resolved Journal other than the credentials themselves — holds
// the secret or any three characters of it.
//
// The generator exists because the leak was never in one refusal. Five of them
// echoed a URL-derived value, and patching those five would have left the sixth
// one somebody adds next year. This test does not know which refusals exist.
func TestJournalRefusalsHideTheSecretRandomized(t *testing.T) {
	iterations := leakIterations
	if v := os.Getenv("WALDEN_LEAK_ITERATIONS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			t.Fatalf("WALDEN_LEAK_ITERATIONS = %q, want a positive integer", v)
		}
		iterations = n
	}

	// Every three-character window of the secret, plus the whole secret.
	// Comparison is case-insensitive: walden folds hosts and regions to
	// lower case, so a leak can arrive in a different case from the one the
	// operator wrote.
	forbidden := []string{strings.ToLower(leakSecret)}
	lower := strings.ToLower(leakSecret)
	for i := 0; i+3 <= len(lower); i++ {
		forbidden = append(forbidden, lower[i:i+3])
	}

	r := rand.New(rand.NewSource(leakSeed))
	seen := make(map[string]bool, iterations)
	for i := 0; i < iterations; i++ {
		raw := buildLeakURL(r)
		if seen[raw] {
			continue
		}
		seen[raw] = true
		for _, out := range journalOutputs(t, raw) {
			leaks := forbidden
			if !out.publicKeyID {
				// The access key ID is a public identifier, and
				// --print-config prints it on purpose. A refusal
				// still has no business naming it.
				leaks = append(leaks, strings.ToLower(leakKeyID))
			}
			for _, leak := range leaks {
				if strings.Contains(strings.ToLower(out.text), leak) {
					t.Fatalf("%s leaked %q for URL %q:\n%s", out.origin, leak, raw, out.text)
				}
			}
		}
	}
	t.Logf("%d distinct journal URLs, none leaked", len(seen))
}

// buildLeakURL composes one journal URL carrying the sentinel credentials,
// mangled somewhere: in the secret or in the access key ID, at its start, its
// middle, or its end.
func buildLeakURL(r *rand.Rand) string {
	mangler := leakManglers[r.Intn(len(leakManglers))]
	key, secret := leakKeyID, leakSecret
	if r.Intn(4) == 0 {
		key = mangleAt(key, mangler, r.Intn(3))
	} else {
		secret = mangleAt(secret, mangler, r.Intn(3))
	}

	var b strings.Builder
	b.WriteString(leakPads[r.Intn(len(leakPads))])
	if scheme := leakSchemes[r.Intn(len(leakSchemes))]; scheme != "" {
		b.WriteString(scheme)
		b.WriteString("://")
	}
	b.WriteString(key)
	if r.Intn(8) != 0 {
		// Nearly always a full "id:secret" pair; sometimes an id alone,
		// which is its own refusal.
		b.WriteString(":")
		b.WriteString(secret)
	}
	b.WriteString("@")
	b.WriteString(leakHosts[r.Intn(len(leakHosts))])
	b.WriteString(leakPaths[r.Intn(len(leakPaths))])
	b.WriteString(leakQueries[r.Intn(len(leakQueries))])
	b.WriteString(leakPads[r.Intn(len(leakPads))])
	return b.String()
}

// mangleAt inserts mangler at the start (0), the middle (1), or the end (2).
func mangleAt(s, mangler string, position int) string {
	switch position {
	case 0:
		return mangler + s
	case 1:
		return s[:len(s)/2] + mangler + s[len(s)/2:]
	default:
		return s + mangler
	}
}

// output is one thing walden would show an operator, and where it came from.
// publicKeyID marks the outputs that print the access key ID by design.
type output struct {
	origin      string
	text        string
	publicKeyID bool
}

// journalOutputs drives one URL through every path that can put a
// URL-derived value in front of an operator: the two entry points in this
// package, the resolved Journal that --print-config prints, and the shallow
// check in internal/config.
func journalOutputs(t *testing.T, raw string) []output {
	t.Helper()

	env := envLookup(creds)
	outs := []output{}

	for _, entry := range []struct {
		name string
		fn   func(string, func(string) (string, bool)) (*store.Journal, error)
	}{
		{"store.ParseJournalURL", store.ParseJournalURL},
		{"store.ResolveJournal", store.ResolveJournal},
	} {
		j, err := entry.fn(raw, env)
		if err != nil {
			assertOneLineRefusal(t, err)
			outs = append(outs, output{origin: entry.name + " refusal", text: err.Error()})
			continue
		}
		// A URL that resolves must not have moved the secret into a
		// location. Credentials.SecretAccessKey is where the secret
		// belongs and is the one field not checked.
		outs = append(outs,
			output{origin: entry.name + " String()", text: j.String()},
			output{origin: entry.name + " Provider", text: j.Provider},
			output{origin: entry.name + " Endpoint", text: j.Endpoint},
			output{origin: entry.name + " Region", text: j.Region},
			output{origin: entry.name + " Bucket", text: j.Bucket},
			output{origin: entry.name + " Prefix", text: j.Prefix},
			output{origin: entry.name + " Credentials.Source", text: j.Credentials.Source},
			output{origin: entry.name + " Credentials.AccessKeyID", text: j.Credentials.AccessKeyID, publicKeyID: true},
		)
	}

	// Only the refusals from internal/config are checked. Config.String() no
	// longer renders the journal URL at all — it prints "(configured)" or
	// "(disabled)" — so asserting that it does not leak would be asserting a
	// property of a constant, which is worse than no assertion: it reads like
	// coverage and is not. The rendered journal location is store.Journal's,
	// and it is checked above, field by field.
	if _, _, err := config.LoadWithEnv([]string{"--journal", raw}, envLookup(nil)); err != nil {
		outs = append(outs, output{origin: "config.LoadWithEnv refusal", text: err.Error()})
	}

	// Validate on a hand-built Config too, so the check does not depend on
	// Load having trimmed the value first.
	direct := &config.Config{
		DataDir:    config.DefaultDataDir,
		JournalURL: raw,
		ListenAddr: config.DefaultListenAddr,
	}
	if err := direct.Validate(); err != nil {
		outs = append(outs, output{origin: "config.Validate refusal", text: err.Error()})
	}

	return outs
}
