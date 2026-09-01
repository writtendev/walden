package journal_test

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
)

func TestFencingConstants(t *testing.T) {
	if journal.HeaderIfNoneMatch != "If-None-Match" {
		t.Errorf("HeaderIfNoneMatch = %q, want %q", journal.HeaderIfNoneMatch, "If-None-Match")
	}
	if journal.IfNoneMatchWildcard != "*" {
		t.Errorf("IfNoneMatchWildcard = %q, want %q", journal.IfNoneMatchWildcard, "*")
	}
	if journal.StatusPreconditionFailed != http.StatusPreconditionFailed {
		t.Errorf("StatusPreconditionFailed = %d, want %d", journal.StatusPreconditionFailed, http.StatusPreconditionFailed)
	}
}

func TestRefusalMessagesSingleLineAndFormat(t *testing.T) {
	// 1. RefuseStreamFenced on repository stream
	err := journal.RefuseStreamFenced("repo-alpha", 5)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	var ref *refusal.Refusal
	if !errors.As(err, &ref) {
		t.Fatalf("expected *refusal.Refusal, got %T", err)
	}
	msg := err.Error()
	if strings.Contains(msg, "\n") || strings.Contains(msg, "\r") {
		t.Errorf("refusal message contains newline: %q", msg)
	}
	expected := "refusal: push failed: stream repo-alpha fenced by concurrent writer at seq 5 (instance is fenced for this stream; restart or check active writer)"
	if msg != expected {
		t.Errorf("refusal mismatch:\ngot:  %q\nwant: %q", msg, expected)
	}

	// 2. RefuseStreamFenced on meta stream
	errMeta := journal.RefuseStreamFenced(journal.MetaStreamID, 2)
	msgMeta := errMeta.Error()
	if strings.Contains(msgMeta, "\n") {
		t.Errorf("refusal message contains newline: %q", msgMeta)
	}
	expectedMeta := "refusal: meta operation failed: stream _meta fenced by concurrent writer at seq 2 (instance is fenced for this stream; restart or check active writer)"
	if msgMeta != expectedMeta {
		t.Errorf("refusal mismatch:\ngot:  %q\nwant: %q", msgMeta, expectedMeta)
	}

	// 3. RefusePermanentlyFenced on repository stream
	errPerm := journal.RefusePermanentlyFenced("repo-alpha")
	msgPerm := errPerm.Error()
	if strings.Contains(msgPerm, "\n") {
		t.Errorf("refusal message contains newline: %q", msgPerm)
	}
	expectedPerm := "refusal: push failed: stream repo-alpha is permanently fenced on this instance (restart walden process to re-materialize from journal)"
	if msgPerm != expectedPerm {
		t.Errorf("refusal mismatch:\ngot:  %q\nwant: %q", msgPerm, expectedPerm)
	}

	// 4. RefusePermanentlyFenced on meta stream
	errPermMeta := journal.RefusePermanentlyFenced(journal.MetaStreamID)
	msgPermMeta := errPermMeta.Error()
	if strings.Contains(msgPermMeta, "\n") {
		t.Errorf("refusal message contains newline: %q", msgPermMeta)
	}
	expectedPermMeta := "refusal: meta operation failed: stream _meta is permanently fenced on this instance (restart walden process to re-materialize from journal)"
	if msgPermMeta != expectedPermMeta {
		t.Errorf("refusal mismatch:\ngot:  %q\nwant: %q", msgPermMeta, expectedPermMeta)
	}

	// 5. RefuseCASNotSupported
	errCAS := journal.RefuseCASNotSupported()
	msgCAS := errCAS.Error()
	if strings.Contains(msgCAS, "\n") {
		t.Errorf("refusal message contains newline: %q", msgCAS)
	}
	expectedCAS := "refusal: journal append failed: storage provider does not support compare-and-swap (CAS) conditional writes (verify bucket provider compatibility in spec)"
	if msgCAS != expectedCAS {
		t.Errorf("refusal mismatch:\ngot:  %q\nwant: %q", msgCAS, expectedCAS)
	}
}

func TestFencerLifecycleAndStreamIsolation(t *testing.T) {
	f := journal.NewFencer()

	// Initially, no streams are fenced
	if f.IsFenced("repo-1") {
		t.Errorf("expected repo-1 to not be fenced initially")
	}
	if f.IsFenced("repo-2") {
		t.Errorf("expected repo-2 to not be fenced initially")
	}
	if f.IsFenced(journal.MetaStreamID) {
		t.Errorf("expected _meta to not be fenced initially")
	}
	if len(f.FencedStreams()) != 0 {
		t.Errorf("expected 0 fenced streams, got %d", len(f.FencedStreams()))
	}

	// CheckWritable on unfenced streams succeeds
	if err := f.CheckWritable("repo-1"); err != nil {
		t.Errorf("expected CheckWritable(repo-1) to succeed, got %v", err)
	}
	if err := f.CheckWritable("repo-2"); err != nil {
		t.Errorf("expected CheckWritable(repo-2) to succeed, got %v", err)
	}
	if err := f.CheckWritable(journal.MetaStreamID); err != nil {
		t.Errorf("expected CheckWritable(_meta) to succeed, got %v", err)
	}

	// Fence repo-1 at seq 10 via HandleConflict
	errConflict := f.HandleConflict("repo-1", 10)
	if errConflict == nil {
		t.Fatalf("expected error from HandleConflict, got nil")
	}
	if !strings.Contains(errConflict.Error(), "stream repo-1 fenced by concurrent writer at seq 10") {
		t.Errorf("unexpected HandleConflict error format: %v", errConflict)
	}

	// Verify repo-1 is now fenced
	if !f.IsFenced("repo-1") {
		t.Errorf("expected repo-1 to be fenced")
	}
	seq, ok := f.FencedSeq("repo-1")
	if !ok || seq != 10 {
		t.Errorf("expected FencedSeq(repo-1) = (10, true), got (%d, %v)", seq, ok)
	}

	// Idempotency of FenceStream: fencing repo-1 again at seq 11 retains initial seq 10
	f.FenceStream("repo-1", 11)
	seq, _ = f.FencedSeq("repo-1")
	if seq != 10 {
		t.Errorf("expected FencedSeq(repo-1) to retain initial seq 10, got %d", seq)
	}

	// Verify stream isolation: repo-2 and _meta MUST NOT be fenced
	if f.IsFenced("repo-2") {
		t.Errorf("stream isolation violated: repo-2 is fenced when only repo-1 was fenced")
	}
	if f.IsFenced(journal.MetaStreamID) {
		t.Errorf("stream isolation violated: _meta is fenced when only repo-1 was fenced")
	}
	if err := f.CheckWritable("repo-2"); err != nil {
		t.Errorf("expected repo-2 to remain writable, got %v", err)
	}
	if err := f.CheckWritable(journal.MetaStreamID); err != nil {
		t.Errorf("expected _meta to remain writable, got %v", err)
	}

	// CheckWritable on fenced repo-1 MUST return refusal
	errWritable := f.CheckWritable("repo-1")
	if errWritable == nil {
		t.Fatalf("expected CheckWritable(repo-1) to fail, got nil")
	}
	if !strings.Contains(errWritable.Error(), "stream repo-1 is permanently fenced on this instance") {
		t.Errorf("unexpected CheckWritable refusal message: %v", errWritable)
	}

	// Fence _meta at seq 3
	f.FenceStream(journal.MetaStreamID, 3)
	if !f.IsFenced(journal.MetaStreamID) {
		t.Errorf("expected _meta to be fenced")
	}
	// repo-2 must still remain writable
	if err := f.CheckWritable("repo-2"); err != nil {
		t.Errorf("expected repo-2 to remain writable after fencing _meta, got %v", err)
	}

	// Check FencedStreams returns sorted list
	fenced := f.FencedStreams()
	if len(fenced) != 2 {
		t.Fatalf("expected 2 fenced streams, got %d (%v)", len(fenced), fenced)
	}
	if fenced[0] != journal.MetaStreamID || fenced[1] != "repo-1" {
		t.Errorf("expected sorted [_meta, repo-1], got %v", fenced)
	}

	// Reset clears state
	f.Reset()
	if f.IsFenced("repo-1") || f.IsFenced(journal.MetaStreamID) {
		t.Errorf("expected all streams to be unfenced after Reset")
	}
	if len(f.FencedStreams()) != 0 {
		t.Errorf("expected 0 fenced streams after Reset, got %d", len(f.FencedStreams()))
	}
}

func TestNilFencerSafety(t *testing.T) {
	var f *journal.Fencer

	if f.IsFenced("repo-alpha") {
		t.Errorf("expected nil Fencer.IsFenced to return false")
	}
	if _, ok := f.FencedSeq("repo-alpha"); ok {
		t.Errorf("expected nil Fencer.FencedSeq to return false")
	}
	if streams := f.FencedStreams(); streams != nil {
		t.Errorf("expected nil Fencer.FencedStreams to return nil, got %v", streams)
	}
	if err := f.CheckWritable("repo-alpha"); err != nil {
		t.Errorf("expected nil Fencer.CheckWritable to return nil, got %v", err)
	}
	// Calling methods that mutate nil should not panic
	f.FenceStream("repo-alpha", 0)
	f.Reset()
}

func TestFencerConcurrentAccess(t *testing.T) {
	f := journal.NewFencer()
	var wg sync.WaitGroup

	numGoroutines := 50
	streams := []journal.StreamID{"repo-a", "repo-b", "repo-c", "repo-d", "_meta"}

	for i := 0; i < numGoroutines; i++ {
		wg.Add(3)

		// 1. Reader goroutine
		go func(id int) {
			defer wg.Done()
			s := streams[id%len(streams)]
			_ = f.IsFenced(s)
			_, _ = f.FencedSeq(s)
			_ = f.CheckWritable(s)
			_ = f.FencedStreams()
		}(i)

		// 2. Writer goroutine fencing streams
		go func(id int) {
			defer wg.Done()
			s := streams[id%len(streams)]
			if id%3 == 0 {
				f.FenceStream(s, uint64(id))
			}
		}(i)

		// 3. Conflict handler goroutine
		go func(id int) {
			defer wg.Done()
			s := streams[(id+1)%len(streams)]
			if id%5 == 0 {
				_ = f.HandleConflict(s, uint64(id))
			}
		}(i)
	}

	wg.Wait()
}

func TestProviderSupportMatrix(t *testing.T) {
	expectedProviders := map[string]struct {
		status         journal.ProviderStatus
		conflictStatus int
	}{
		"AWS S3":               {journal.ProviderSupported, http.StatusPreconditionFailed},
		"Cloudflare R2":        {journal.ProviderSupported, http.StatusPreconditionFailed},
		"Google Cloud Storage": {journal.ProviderSupported, http.StatusPreconditionFailed},
		"MinIO":                {journal.ProviderSupported, http.StatusPreconditionFailed},
		"Ceph RGW":             {journal.ProviderSupported, http.StatusPreconditionFailed},
		"Backblaze B2":         {journal.ProviderSupported, http.StatusPreconditionFailed},
		"Garage S3":            {journal.ProviderSupported, http.StatusPreconditionFailed},
		"Wasabi":               {journal.ProviderUnsupported, 0},
		"Azure Blob Storage":   {journal.ProviderConditional, http.StatusPreconditionFailed},
	}

	if len(journal.ProviderSupportMatrix) < len(expectedProviders) {
		t.Errorf("expected at least %d providers in matrix, got %d", len(expectedProviders), len(journal.ProviderSupportMatrix))
	}

	for name, exp := range expectedProviders {
		info, ok := journal.LookupProvider(name)
		if !ok {
			t.Errorf("provider %q missing in ProviderSupportMatrix", name)
			continue
		}
		if info.Status != exp.status {
			t.Errorf("provider %q status = %q, want %q", name, info.Status, exp.status)
		}
		if info.ConflictStatus != exp.conflictStatus {
			t.Errorf("provider %q conflict status = %d, want %d", name, info.ConflictStatus, exp.conflictStatus)
		}
		if info.Header != "If-None-Match: *" {
			t.Errorf("provider %q header = %q, want 'If-None-Match: *'", name, info.Header)
		}
		if info.Notes == "" {
			t.Errorf("provider %q missing notes", name)
		}
	}
}

func TestLookupProviderVariants(t *testing.T) {
	tests := []struct {
		query    string
		expected string
		found    bool
	}{
		{"AWS S3", "AWS S3", true},
		{"aws s3", "AWS S3", true},
		{"  cloudflare r2  ", "Cloudflare R2", true},
		{"minio", "MinIO", true},
		{"ceph", "Ceph RGW", true},
		{"google", "Google Cloud Storage", true},
		{"wasabi", "Wasabi", true},
		{"azure", "Azure Blob Storage", true},
		{"garage", "Garage S3", true},
		{"backblaze", "Backblaze B2", true},
		{"unknown-cloud-storage", "", false},
		{"", "", false},
		{"   ", "", false},
	}

	for _, tc := range tests {
		info, ok := journal.LookupProvider(tc.query)
		if ok != tc.found {
			t.Errorf("LookupProvider(%q) found = %v, want %v", tc.query, ok, tc.found)
			continue
		}
		if tc.found && info.Name != tc.expected {
			t.Errorf("LookupProvider(%q) = %q, want %q", tc.query, info.Name, tc.expected)
		}
	}
}

func TestValidateProviderCAS(t *testing.T) {
	// Supported providers must validate with no error
	supported := []string{
		"AWS S3", "aws", "Amazon S3", "amazonaws.com", "s3.us-east-1.amazonaws.com",
		"Cloudflare R2", "R2", "Cloudflare", "account.r2.cloudflarestorage.com",
		"GCS", "Google Cloud Storage", "googleapis.com", "storage.googleapis.com",
		"MinIO", "minio",
		"Ceph RGW", "Ceph", "ceph-rgw",
		"Backblaze B2", "Backblaze", "backblazeb2.com",
		"Garage S3", "Garage", "garage-s3",
		"Azure Blob Storage", "Azure Blob", "azure-blob", "blob.core.windows.net",
	}
	for _, p := range supported {
		if err := journal.ValidateProviderCAS(p); err != nil {
			t.Errorf("ValidateProviderCAS(%q) failed unexpectedly: %v", p, err)
		}
	}

	// Unsupported provider (Wasabi, wasabi endpoints) must return CAS refusal
	unsupported := []string{
		"Wasabi", "wasabi", "wasabi-cloud", "wasabisys.com", "s3.wasabisys.com", "https://s3.wasabisys.com/mybucket",
	}
	for _, p := range unsupported {
		errWasabi := journal.ValidateProviderCAS(p)
		if errWasabi == nil {
			t.Fatalf("expected ValidateProviderCAS(%q) to fail, got nil", p)
		}
		if !strings.Contains(errWasabi.Error(), "storage provider does not support compare-and-swap") {
			t.Errorf("unexpected refusal message for %q: %v", p, errWasabi)
		}
		if !errors.Is(errWasabi, journal.ErrCASNotSupported) {
			t.Errorf("expected errors.Is(err, ErrCASNotSupported) for %q", p)
		}
	}

	// Unknown provider must return CAS refusal
	errUnknown := journal.ValidateProviderCAS("NonExistentProviderS3")
	if errUnknown == nil {
		t.Fatalf("expected ValidateProviderCAS(NonExistentProviderS3) to fail, got nil")
	}
	if !strings.Contains(errUnknown.Error(), "storage provider does not support compare-and-swap") {
		t.Errorf("unexpected refusal message for unknown provider: %v", errUnknown)
	}
	if !errors.Is(errUnknown, journal.ErrCASNotSupported) {
		t.Errorf("expected errors.Is(err, ErrCASNotSupported) for unknown provider")
	}
}

func TestSentinelErrorsUnificationAndErrorsIs(t *testing.T) {
	// 1. ErrStreamFenced and ErrFenced are unified
	if !errors.Is(journal.ErrStreamFenced, journal.ErrFenced) {
		t.Errorf("expected ErrStreamFenced to match ErrFenced with errors.Is")
	}
	if !errors.Is(journal.ErrFenced, journal.ErrStreamFenced) {
		t.Errorf("expected ErrFenced to match ErrStreamFenced with errors.Is")
	}

	// 2. RefuseStreamFenced matches ErrFenced and ErrStreamFenced
	errFenced := journal.RefuseStreamFenced("repo-alpha", 5)
	if !errors.Is(errFenced, journal.ErrFenced) {
		t.Errorf("expected RefuseStreamFenced to match ErrFenced")
	}
	if !errors.Is(errFenced, journal.ErrStreamFenced) {
		t.Errorf("expected RefuseStreamFenced to match ErrStreamFenced")
	}

	// 3. RefusePermanentlyFenced matches ErrFenced and ErrStreamFenced
	errPerm := journal.RefusePermanentlyFenced("repo-alpha")
	if !errors.Is(errPerm, journal.ErrFenced) {
		t.Errorf("expected RefusePermanentlyFenced to match ErrFenced")
	}
	if !errors.Is(errPerm, journal.ErrStreamFenced) {
		t.Errorf("expected RefusePermanentlyFenced to match ErrStreamFenced")
	}

	// 4. RefuseCASNotSupported matches ErrCASNotSupported
	errCAS := journal.RefuseCASNotSupported()
	if !errors.Is(errCAS, journal.ErrCASNotSupported) {
		t.Errorf("expected RefuseCASNotSupported to match ErrCASNotSupported")
	}

	// 5. Check Fencer methods return errors matching ErrFenced
	f := journal.NewFencer()
	f.FenceStream("repo-x", 1)
	errCheck := f.CheckWritable("repo-x")
	if !errors.Is(errCheck, journal.ErrFenced) {
		t.Errorf("expected CheckWritable on fenced stream to match ErrFenced")
	}
	errConflict := f.HandleConflict("repo-y", 2)
	if !errors.Is(errConflict, journal.ErrFenced) {
		t.Errorf("expected HandleConflict to match ErrFenced")
	}
}

func TestFencerEmptyStreamHandling(t *testing.T) {
	f := journal.NewFencer()

	if f.IsFenced("") {
		t.Errorf("expected empty stream to not be fenced initially")
	}
	if err := f.CheckWritable(""); err != nil {
		t.Errorf("expected CheckWritable(\"\") to succeed initially, got %v", err)
	}

	f.FenceStream("", 42)
	if !f.IsFenced("") {
		t.Errorf("expected empty stream to be fenced after FenceStream")
	}
	seq, ok := f.FencedSeq("")
	if !ok || seq != 42 {
		t.Errorf("expected FencedSeq(\"\") = (42, true), got (%d, %v)", seq, ok)
	}
	if err := f.CheckWritable(""); err == nil {
		t.Errorf("expected CheckWritable(\"\") on fenced stream to return refusal")
	}
}
