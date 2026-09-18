// WALD-34: internal/journal.Reader's ObjectSource port, driven against a
// real *store.Client rather than the in-package fake internal/journal's
// own reader_test.go uses. A pass here is evidence of two things
// reader_test.go cannot show on its own: that *store.Client satisfies
// journal.ObjectSource exactly as it stands (Get and List already match
// the interface; no adapter is written or needed), and that PlanStream's
// start-after resume works against the fake's own paginated LIST — a
// multi-request round trip through real HTTP framing — not just an
// in-memory map that hands back every key from one call.
//
// This file loads the same published golden journal
// (spec/journal/v1/fixtures) internal/journal's fixtures_test.go and
// reader_test.go read, into a storetest.Fake, addressed independently
// here since those helpers are unexported in package journal_test
// (mirrors fixtureRepoAlphaSegmentsDir in segment_test.go).
package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/store"
	"github.com/writtendev/walden/internal/store/storetest"
)

const (
	fixtureRepoStream  = journal.StreamID("repo-alpha")
	fixtureMetaHeadSeq = journal.Seq(4)
)

// journalFixturesDir returns the published golden journal.
func journalFixturesDir() string {
	return filepath.Join("..", "..", "spec", "journal", "v1", "fixtures")
}

// loadFixtureTreeIntoFake walks the golden journal and seeds every object
// into fake under its own key, unprefixed. skip, when non-nil, excludes
// any key it reports true for (used to drop marker.json and exercise the
// no-marker replay path against a real, paginated LIST).
func loadFixtureTreeIntoFake(t *testing.T, fake *storetest.Fake, skip func(key string) bool) {
	t.Helper()
	root := journalFixturesDir()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		if skip != nil && skip(key) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fake.SetObject(key, data)
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk fixture tree %s: %v", root, err)
	}
}

// newFixtureStoreClient starts a Fake, seeds it with the golden journal
// (skip applies as in loadFixtureTreeIntoFake), and returns a *store.Client
// pointed at it with no operator key prefix: journal.TxKey/MarkerKey/etc.
// already embed the "v1/" format version themselves, so an operator
// Prefix would double it. This is why this file does not reuse
// storetest_client_test.go's newFakeClient/testPrefix, which model an
// operator prefix deliberately.
func newFixtureStoreClient(t *testing.T, skip func(key string) bool) (*store.Client, *storetest.Fake) {
	t.Helper()
	restore := store.SetBackoffForTest(time.Millisecond, 5*time.Millisecond)
	t.Cleanup(restore)

	fake := storetest.New(t)
	loadFixtureTreeIntoFake(t, fake, skip)

	j := &store.Journal{
		Endpoint:    fake.URL(),
		Region:      "us-east-1",
		Bucket:      fake.Bucket(),
		Prefix:      "",
		PathStyle:   true,
		Credentials: store.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
	}
	return store.NewClient(j), fake
}

// loadFixtureChainViaClient replays the _meta stream up to and including
// maxSeq through c itself, not local file reads, so this file's tests
// exercise the same *store.Client for both halves of a real boot: reading
// _meta to build the chain (WALD-31's half of spec section 8), and reading
// a repository stream to plan it (this ticket's half). It mirrors
// internal/journal's own, unexported loadFixtureChain.
func loadFixtureChainViaClient(t *testing.T, c *store.Client, maxSeq journal.Seq) *journal.SigningChain {
	t.Helper()
	chain := journal.NewSigningChain()
	ctx := context.Background()

	for seq := journal.Seq(0); seq <= maxSeq; seq++ {
		key := journal.TxKey(journal.MetaStreamID, seq)
		body, err := c.Get(ctx, key)
		if err != nil {
			t.Fatalf("Get(%s) failed: %v", key, err)
		}
		data, err := io.ReadAll(body)
		closeErr := body.Close()
		if err != nil {
			t.Fatalf("failed to read %s: %v", key, err)
		}
		if closeErr != nil {
			t.Fatalf("failed to close %s: %v", key, closeErr)
		}

		var header struct {
			Type string      `json:"type"`
			Seq  journal.Seq `json:"seq"`
		}
		if err := json.Unmarshal(data, &header); err != nil {
			t.Fatalf("failed to parse meta fixture %s: %v", key, err)
		}

		switch header.Type {
		case journal.RecordTypeGenesis:
			var genesis journal.GenesisRecord
			if err := json.Unmarshal(data, &genesis); err != nil {
				t.Fatalf("failed to parse genesis fixture %s: %v", key, err)
			}
			if err := chain.ApplyGenesis(&genesis); err != nil {
				t.Fatalf("ApplyGenesis failed on %s: %v", key, err)
			}
		case journal.RecordTypeKeyRotation:
			var rotation journal.KeyRotationRecord
			if err := json.Unmarshal(data, &rotation); err != nil {
				t.Fatalf("failed to parse rotation fixture %s: %v", key, err)
			}
			if err := chain.ApplyRotation(&rotation); err != nil {
				t.Fatalf("ApplyRotation failed on %s: %v", key, err)
			}
		case journal.RecordTypeTokenCreate:
			create, err := journal.ParseTokenCreate(data)
			if err != nil {
				t.Fatalf("ParseTokenCreate failed on %s: %v", key, err)
			}
			if err := chain.VerifyTokenCreate(create); err != nil {
				t.Fatalf("VerifyTokenCreate failed on %s: %v", key, err)
			}
			if err := chain.AdvanceMetaSeq(header.Seq); err != nil {
				t.Fatalf("AdvanceMetaSeq failed on %s: %v", key, err)
			}
		case journal.RecordTypeTokenRevoke:
			revoke, err := journal.ParseTokenRevoke(data)
			if err != nil {
				t.Fatalf("ParseTokenRevoke failed on %s: %v", key, err)
			}
			if err := chain.VerifyTokenRevoke(revoke); err != nil {
				t.Fatalf("VerifyTokenRevoke failed on %s: %v", key, err)
			}
			if err := chain.AdvanceMetaSeq(header.Seq); err != nil {
				t.Fatalf("AdvanceMetaSeq failed on %s: %v", key, err)
			}
		default:
			if err := chain.AdvanceMetaSeq(header.Seq); err != nil {
				t.Fatalf("AdvanceMetaSeq failed on %s: %v", key, err)
			}
		}
	}
	return chain
}

// TestStoreClientSatisfiesObjectSource is a compile-time check that
// *store.Client needs no adapter to serve as journal.ObjectSource: List
// (declared for WALD-29's TxLister) plus Get already match the interface
// exactly.
func TestStoreClientSatisfiesObjectSource(t *testing.T) {
	var _ journal.ObjectSource = (*store.Client)(nil)
}

// TestPlanStreamEndToEnd plans repo-alpha's marker path through a real
// *store.Client against storetest.Fake, end to end: HTTP framing, XML
// listing, SigV4 signing, all of it, for both the _meta replay this test
// builds the chain from and the repository stream PlanStream reads.
func TestPlanStreamEndToEnd(t *testing.T) {
	c, _ := newFixtureStoreClient(t, nil)
	chain := loadFixtureChainViaClient(t, c, fixtureMetaHeadSeq)

	markerData, err := os.ReadFile(filepath.Join(journalFixturesDir(), filepath.FromSlash(string(journal.MarkerKey(fixtureRepoStream)))))
	if err != nil {
		t.Fatalf("failed to read marker fixture: %v", err)
	}
	marker, err := journal.ParseMarker(markerData)
	if err != nil {
		t.Fatalf("ParseMarker failed on the golden marker: %v", err)
	}

	plan, err := journal.NewReader(c).PlanStream(context.Background(), chain, fixtureRepoStream)
	if err != nil {
		t.Fatalf("PlanStream failed: %v", err)
	}
	if plan.Baseline == nil || *plan.Baseline != marker.Sequence {
		t.Fatalf("Baseline = %v, want %d", plan.Baseline, marker.Sequence)
	}
	if plan.Snapshot == nil || plan.Snapshot.SHA256 != marker.Snapshot {
		t.Fatalf("Snapshot = %+v, want SHA256 %s", plan.Snapshot, marker.Snapshot)
	}
	if len(plan.Refs) != len(marker.Refs) {
		t.Errorf("Refs has %d entries, want %d (the marker's own ref set)", len(plan.Refs), len(marker.Refs))
	}
	if len(plan.Transactions) != 1 {
		t.Fatalf("Transactions has %d entries, want 1", len(plan.Transactions))
	}
	if plan.Transactions[0].Record.Seq != marker.Sequence+1 {
		t.Errorf("Transactions[0].Record.Seq = %d, want %d", plan.Transactions[0].Record.Seq, marker.Sequence+1)
	}
}

// TestPlanStreamGenesisPathResumesAcrossPagination drops marker.json from
// the fake and shrinks its page size to 1, forcing every tx/ listing
// through several real ListObjectsV2 round trips joined by
// continuation-token, plus PlanStream's own start-after — proving the
// resume logic works against genuine pagination, not just a single page
// an in-memory fake could return in one shot.
func TestPlanStreamGenesisPathResumesAcrossPagination(t *testing.T) {
	c, fake := newFixtureStoreClient(t, func(key string) bool {
		return key == string(journal.MarkerKey(fixtureRepoStream))
	})
	fake.PageSize = 1

	chain := loadFixtureChainViaClient(t, c, fixtureMetaHeadSeq)

	plan, err := journal.NewReader(c).PlanStream(context.Background(), chain, fixtureRepoStream)
	if err != nil {
		t.Fatalf("PlanStream failed: %v", err)
	}
	if plan.Baseline != nil {
		t.Fatalf("Baseline = %v, want nil now that marker.json is absent", *plan.Baseline)
	}
	if len(plan.Transactions) != 5 {
		t.Fatalf("Transactions has %d entries, want 5 (all of repo-alpha's history)", len(plan.Transactions))
	}
	for i, tx := range plan.Transactions {
		if want := journal.Seq(i); tx.Record.Seq != want {
			t.Errorf("Transactions[%d].Record.Seq = %d, want %d", i, tx.Record.Seq, want)
		}
	}
}

// TestPlanStream500OnTxGetRefusesRatherThanShortPlan covers the one
// fault-injection case this file owns: a persistent 500 on a tx/ GET must
// surface as a refusal from PlanStream, with a nil plan — never a plan
// that silently stops short of the stream's real length.
func TestPlanStream500OnTxGetRefusesRatherThanShortPlan(t *testing.T) {
	c, fake := newFixtureStoreClient(t, nil)
	fake.Inject(storetest.Rule{
		Op:    storetest.OpGet,
		Key:   string(journal.TxKey(fixtureRepoStream, 4)),
		Call:  1,
		Count: store.MaxAttemptsForTest,
		Fault: storetest.Fault{Status: 500, Code: "InternalError"},
	})

	chain := loadFixtureChainViaClient(t, c, fixtureMetaHeadSeq)

	plan, err := journal.NewReader(c).PlanStream(context.Background(), chain, fixtureRepoStream)
	if plan != nil {
		t.Errorf("plan = %+v, want nil", plan)
	}
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !errors.Is(err, store.ErrStorageUnavailable) {
		t.Errorf("errors.Is(_, store.ErrStorageUnavailable) = false, err = %v", err)
	}
}
