// WALD-26: (*store.Client).AppendSegment, the write path for pack segments
// (spec/journal/v1 section 6). Test 1 pins key derivation against the
// published golden fixtures under spec/journal/v1/fixtures - a conformance
// check, not a restatement of journal.SegmentKey. Test 2 uses a bespoke
// httptest.Server (the TestPutIfAbsentHeaderAndSignature pattern in
// client_test.go) to assert the exact wire headers and that they are
// signed. Tests 3 through 6 drive AppendSegment against storetest.Fake -
// the same stateful in-memory S3 fake with fault injection
// storetest_client_test.go and probe_test.go use - to exercise
// idempotence, crash-and-retry, refusals, and the aws-chunked path against
// something that actually behaves like object storage rather than a mock
// that only knows what a test author remembered to assert.
//
// This file reuses newFakeServer, testJournal, fixedClock, verifySignature
// (client_test.go), newFakeClient, fullKey, testPrefix
// (storetest_client_test.go), and assertSingleLine (probe_test.go): all are
// package-level in store_test, shared the same way list_test.go and
// probe_test.go already share them.
package store_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/store"
	"github.com/writtendev/walden/internal/store/storetest"
)

// fixtureRepoAlphaSegmentsDir returns the published golden segments for
// stream "repo-alpha", under spec/journal/v1/fixtures - the same tree
// journal_test.go's journalFixturesDir reads, addressed independently here
// since that helper is unexported in package journal_test.
func fixtureRepoAlphaSegmentsDir() string {
	return filepath.Join("..", "..", "spec", "journal", "v1", "fixtures", "v1", "streams", "repo-alpha", "segments")
}

// validPackfile returns a syntactically valid Git packfile - PACK magic,
// version 2, an arbitrary object count - of exactly size bytes (size must
// be >= journal.PackfileMinSize). Section 6.6's validation never inspects
// anything past the 12-byte header for length or magic/version, and
// AppendSegment's SHA-256 is over whatever bytes are actually here, not a
// real git checksum, so deterministic filler (not a real object stream)
// is enough. The filler is not all-zero so a bug that only distinguishes
// "zeroed" from "not zeroed" still gets caught.
func validPackfile(t *testing.T, size int) []byte {
	t.Helper()
	if size < journal.PackfileMinSize {
		t.Fatalf("validPackfile: size %d is below PackfileMinSize %d", size, journal.PackfileMinSize)
	}
	buf := make([]byte, size)
	copy(buf, journal.PackfileMagic)
	binary.BigEndian.PutUint32(buf[4:8], 2)
	binary.BigEndian.PutUint32(buf[8:12], 1)
	for i := journal.PackfileHeaderSize; i < size; i++ {
		buf[i] = byte(i)
	}
	return buf
}

// 1. Key derivation against the published fixtures: appending each
// committed repo-alpha pack reproduces that fixture's own filename (the
// hash) and, through journal.SegmentKey, its own path - verbatim. The
// fixture tree is the spec's key layout byte for byte, so this is a
// conformance check against section 6.3, not a restatement of SegmentKey.
func TestAppendSegmentMatchesFixtureKeys(t *testing.T) {
	dir := fixtureRepoAlphaSegmentsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}
	if len(entries) == 0 {
		t.Fatalf("no fixture segments found under %q", dir)
	}

	var exercised int
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pack") {
			continue
		}
		exercised++
		wantHash := strings.TrimSuffix(entry.Name(), ".pack")
		t.Run(wantHash, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}

			c, fake := newFakeClient(t)
			hash, err := c.AppendSegment(context.Background(), "repo-alpha", bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatalf("AppendSegment: %v", err)
			}
			if hash != wantHash {
				t.Errorf("hash = %q, want %q (fixture filename)", hash, wantHash)
			}

			wantKey := journal.SegmentKey("repo-alpha", wantHash)
			gotStored, ok := fake.Object(fullKey(wantKey))
			if !ok {
				t.Fatalf("Object(%q) not found - AppendSegment did not PUT to the fixture's own key", fullKey(wantKey))
			}
			if !bytes.Equal(gotStored, data) {
				t.Errorf("stored bytes for %q do not match the fixture verbatim", wantKey)
			}
		})
	}
	if exercised == 0 {
		t.Fatalf("no .pack fixtures under %q were exercised - directory is non-empty but nothing matched the filter (reshaped fixture tree or renamed extension?)", dir)
	}
}

// 2. Headers and signature: Content-Type, both x-amz-meta-walden-* sidecar
// headers, both metadata headers present in the signed set, and no
// If-None-Match - section 6.4's "unconditional write" - on both the plain
// http (aws-chunked) and https (unsigned-payload) send paths.
func TestAppendSegmentHeadersAndSignature(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		name := "http-aws-chunked"
		if useTLS {
			name = "https-unsigned"
		}
		t.Run(name, func(t *testing.T) {
			var gotContentType, gotStream, gotHash, gotIfNoneMatch, gotSignedHeaders string
			var sigErr error
			var reqCount int32
			handler := func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&reqCount, 1)
				gotContentType = r.Header.Get("Content-Type")
				gotStream = r.Header.Get(journal.MetaHeaderStream)
				gotHash = r.Header.Get(journal.MetaHeaderHash)
				gotIfNoneMatch = r.Header.Get("If-None-Match")
				gotSignedHeaders = authSignedHeaders(r)
				io.Copy(io.Discard, r.Body)
				sigErr = verifySignature(t, r)
				w.WriteHeader(http.StatusOK)
			}
			client := newFakeServer(t, useTLS, handler)
			scheme := "http"
			if useTLS {
				scheme = "https"
			}
			j := testJournal(scheme+"://s3.fake.test", "test-bucket", "v1", true)
			c := store.NewClientForTest(j, client, fixedClock(time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)))

			pack := validPackfile(t, 64)
			wantHash := journal.ComputeSegmentHash(pack)

			hash, err := c.AppendSegment(context.Background(), "repo-alpha", bytes.NewReader(pack), int64(len(pack)))
			if err != nil {
				t.Fatalf("AppendSegment: %v", err)
			}
			if hash != wantHash {
				t.Fatalf("hash = %q, want %q", hash, wantHash)
			}
			if atomic.LoadInt32(&reqCount) != 1 {
				t.Fatalf("server saw %d requests, want 1", atomic.LoadInt32(&reqCount))
			}
			if gotContentType != journal.ContentTypeGitPackedObjects {
				t.Errorf("Content-Type = %q, want %q", gotContentType, journal.ContentTypeGitPackedObjects)
			}
			if gotStream != "repo-alpha" {
				t.Errorf("%s = %q, want %q", journal.MetaHeaderStream, gotStream, "repo-alpha")
			}
			if gotHash != wantHash {
				t.Errorf("%s = %q, want %q", journal.MetaHeaderHash, gotHash, wantHash)
			}
			if gotIfNoneMatch != "" {
				t.Errorf("If-None-Match = %q, want unset (section 6.4: unconditional write)", gotIfNoneMatch)
			}
			for _, want := range []string{"content-type", strings.ToLower(journal.MetaHeaderStream), strings.ToLower(journal.MetaHeaderHash)} {
				if !containsSignedHeader(gotSignedHeaders, want) {
					t.Errorf("SignedHeaders = %q, want it to include %q", gotSignedHeaders, want)
				}
			}
			if sigErr != nil {
				t.Errorf("signature verification failed: %v", sigErr)
			}
		})
	}
}

// authSignedHeaders returns the SignedHeaders field of r's Authorization
// header, or "" if absent or malformed.
func authSignedHeaders(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	const prefix = "AWS4-HMAC-SHA256 "
	if !strings.HasPrefix(auth, prefix) {
		return ""
	}
	for _, kv := range strings.Split(strings.TrimPrefix(auth, prefix), ", ") {
		if strings.HasPrefix(kv, "SignedHeaders=") {
			return strings.TrimPrefix(kv, "SignedHeaders=")
		}
	}
	return ""
}

// containsSignedHeader reports whether name appears as one of the
// semicolon-separated entries in signedHeaders.
func containsSignedHeader(signedHeaders, name string) bool {
	for _, h := range strings.Split(signedHeaders, ";") {
		if h == name {
			return true
		}
	}
	return false
}

// 3. Idempotence - "errs never": appending the same bytes twice succeeds
// both times with the identical hash, the fake logs two full OpPut calls
// (never a skip, never a conditional write), and the stored object is
// byte-equal to the input. Repeating against a key pre-seeded with the
// identical bytes (SetObject, modelling a crash after the first PUT
// landed but before the caller learned about it) is still nil.
func TestAppendSegmentIdempotent(t *testing.T) {
	c, fake := newFakeClient(t)
	pack := validPackfile(t, 128)
	stream := journal.StreamID("repo-alpha")

	hash1, err := c.AppendSegment(context.Background(), stream, bytes.NewReader(pack), int64(len(pack)))
	if err != nil {
		t.Fatalf("first AppendSegment: %v", err)
	}
	hash2, err := c.AppendSegment(context.Background(), stream, bytes.NewReader(pack), int64(len(pack)))
	if err != nil {
		t.Fatalf("second AppendSegment: %v", err)
	}
	if hash1 != hash2 {
		t.Fatalf("hash1 = %q, hash2 = %q, want equal", hash1, hash2)
	}

	key := fullKey(journal.SegmentKey(stream, hash1))
	var puts int
	for _, call := range fake.Calls() {
		if call.Op == storetest.OpPut && call.Key == key {
			puts++
			if !call.Landed {
				t.Errorf("call %d: Landed = false, want true (each PUT should be a full write, never skipped)", call.N)
			}
			if call.Status != http.StatusOK {
				t.Errorf("call %d: Status = %d, want %d (unconditional write, no 412 possible)", call.N, call.Status, http.StatusOK)
			}
		}
		if call.Op == storetest.OpPutIfAbsent {
			t.Errorf("call %d: Op = OpPutIfAbsent, want AppendSegment to never send a conditional write", call.N)
		}
	}
	if puts != 2 {
		t.Fatalf("fake logged %d OpPut calls at %q, want 2", puts, key)
	}
	if stored, ok := fake.Object(key); !ok || !bytes.Equal(stored, pack) {
		t.Errorf("Object(%q) = %q, %v, want the input bytes verbatim", key, stored, ok)
	}

	// Pre-seed the identical bytes directly (as if an earlier crashed
	// attempt already landed the write) and append again: still nil.
	fake.SetObject(key, pack)
	if _, err := c.AppendSegment(context.Background(), stream, bytes.NewReader(pack), int64(len(pack))); err != nil {
		t.Fatalf("AppendSegment against a pre-seeded identical object: %v", err)
	}
}

// 4. Crash-and-retry: a burst of one 503 is retried and succeeds (section
// 6.4 licenses retrying an unconditional PUT exactly like Put), and a
// dropped connection whose write actually landed (Land: true) is retried
// and still succeeds with the correct final bytes - and never surfaces
// ErrOutcomeUnknown, which is a rule for conditional appends only
// (PutIfAbsent), not this unconditional one.
func TestAppendSegmentCrashAndRetry(t *testing.T) {
	stream := journal.StreamID("repo-alpha")
	pack := validPackfile(t, 96)
	hash := journal.ComputeSegmentHash(pack)
	key := fullKey(journal.SegmentKey(stream, hash))

	t.Run("503-not-landed", func(t *testing.T) {
		c, fake := newFakeClient(t)
		fake.Inject(storetest.Rule{
			Op: storetest.OpPut, Key: key, Call: 1,
			Fault: storetest.Fault{Status: http.StatusServiceUnavailable, Code: "SlowDown"},
		})

		got, err := c.AppendSegment(context.Background(), stream, bytes.NewReader(pack), int64(len(pack)))
		if err != nil {
			t.Fatalf("AppendSegment: %v", err)
		}
		if got != hash {
			t.Fatalf("hash = %q, want %q", got, hash)
		}
		if stored, ok := fake.Object(key); !ok || !bytes.Equal(stored, pack) {
			t.Errorf("Object(%q) = %q, %v, want the input bytes verbatim", key, stored, ok)
		}
	})

	t.Run("dropped-but-landed", func(t *testing.T) {
		c, fake := newFakeClient(t)
		fake.Inject(storetest.Rule{
			Op: storetest.OpPut, Key: key, Call: 1,
			Fault: storetest.Fault{Land: true, Drop: true},
		})

		got, err := c.AppendSegment(context.Background(), stream, bytes.NewReader(pack), int64(len(pack)))
		if err != nil {
			t.Fatalf("AppendSegment: %v", err)
		}
		if errors.Is(err, store.ErrOutcomeUnknown) {
			t.Fatalf("AppendSegment returned ErrOutcomeUnknown - that rule belongs to conditional appends only")
		}
		if got != hash {
			t.Fatalf("hash = %q, want %q", got, hash)
		}
		if stored, ok := fake.Object(key); !ok || !bytes.Equal(stored, pack) {
			t.Errorf("Object(%q) = %q, %v, want the input bytes verbatim", key, stored, ok)
		}
	})
}

// 5. Refused before the wire: bad magic, an unsupported version, a body
// under the minimum size, a size longer than the ReaderAt actually holds,
// and an invalid stream ID each produce a single-line refusal matching the
// right sentinel, and never reach storage.
func TestAppendSegmentRefusedBeforeWire(t *testing.T) {
	validSize := 64

	cases := []struct {
		name   string
		stream journal.StreamID
		body   func(t *testing.T) []byte
		size   func(bodyLen int) int64
		wantIs error
	}{
		{
			name:   "bad-magic",
			stream: "repo-alpha",
			body: func(t *testing.T) []byte {
				b := validPackfile(t, validSize)
				copy(b[:4], "NOPE")
				return b
			},
			size:   func(n int) int64 { return int64(n) },
			wantIs: journal.ErrInvalidPackfile,
		},
		{
			name:   "unsupported-version",
			stream: "repo-alpha",
			body: func(t *testing.T) []byte {
				b := validPackfile(t, validSize)
				binary.BigEndian.PutUint32(b[4:8], 1)
				return b
			},
			size:   func(n int) int64 { return int64(n) },
			wantIs: journal.ErrInvalidPackfile,
		},
		{
			name:   "too-short",
			stream: "repo-alpha",
			body: func(t *testing.T) []byte {
				return validPackfile(t, journal.PackfileMinSize)[:journal.PackfileMinSize-1]
			},
			size:   func(n int) int64 { return int64(n) },
			wantIs: journal.ErrInvalidPackfile,
		},
		{
			name:   "size-exceeds-reader",
			stream: "repo-alpha",
			body: func(t *testing.T) []byte {
				return validPackfile(t, validSize)
			},
			size:   func(n int) int64 { return int64(n) + 1000 },
			wantIs: journal.ErrInvalidPackfile,
		},
		{
			name:   "invalid-stream-id",
			stream: "",
			body: func(t *testing.T) []byte {
				return validPackfile(t, validSize)
			},
			size:   func(n int) int64 { return int64(n) },
			wantIs: journal.ErrInvalidStream,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, fake := newFakeClient(t)
			body := tc.body(t)
			_, err := c.AppendSegment(context.Background(), tc.stream, bytes.NewReader(body), tc.size(len(body)))
			if err == nil {
				t.Fatalf("AppendSegment: err = nil, want a refusal")
			}
			assertSingleLine(t, err)
			if !errors.Is(err, tc.wantIs) {
				t.Errorf("errors.Is(err, %v) = false, err = %v", tc.wantIs, err)
			}
			if calls := fake.Calls(); len(calls) != 0 {
				t.Errorf("fake logged %d calls, want 0 (refused before the wire): %+v", len(calls), calls)
			}
		})
	}
}

// 6. Verbatim storage on the signed-chunked path: storetest.Fake dials
// over plain http (newFakeClient's Journal.Endpoint), so every call above
// already goes through aws-chunked signing (sigv4.go's newChunkedBody) -
// this test just sizes the pack so it straddles several 64 KiB chunk
// frames without dividing evenly, and checks the round trip is exact:
// zero transformation, section 6.1.
func TestAppendSegmentVerbatimAcrossChunkBoundaries(t *testing.T) {
	c, fake := newFakeClient(t)
	stream := journal.StreamID("repo-alpha")

	// 64 KiB is client.go's chunkSize (unexported; restated here as a
	// plain int the same way sigv4_test.go's own chunkSize const does).
	const awsChunkSize = 64 << 10
	pack := validPackfile(t, awsChunkSize*3+12345)

	hash, err := c.AppendSegment(context.Background(), stream, bytes.NewReader(pack), int64(len(pack)))
	if err != nil {
		t.Fatalf("AppendSegment: %v", err)
	}
	if want := journal.ComputeSegmentHash(pack); hash != want {
		t.Fatalf("hash = %q, want %q", hash, want)
	}

	key := fullKey(journal.SegmentKey(stream, hash))
	stored, ok := fake.Object(key)
	if !ok {
		t.Fatalf("Object(%q) not found", key)
	}
	if !bytes.Equal(stored, pack) {
		t.Fatalf("stored bytes are not byte-for-byte identical to the input (len(stored)=%d, len(pack)=%d)", len(stored), len(pack))
	}
	if got := journal.ComputeSegmentHash(stored); got != hash {
		t.Fatalf("ComputeSegmentHash(stored) = %q, want %q (returned hash)", got, hash)
	}
}
