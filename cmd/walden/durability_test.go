// Tests for the durability handshake (WALD-46): the two-directional
// contract that is the product itself, expressed as an exit code:
//
//  1. Exit 0 happens strictly after object storage has acknowledged both
//     the segment and the ref transaction. A failed append at ANY injected
//     failure point blocks the ref update and exits non-zero with a
//     one-line refusal.
//  2. The journal knows about no ref move that did not happen. A push
//     refused on the git side (D/F conflict, stale old_oid, lock contention)
//     leaves no ref transaction in the journal claiming it happened.
package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
	"github.com/writtendev/walden/internal/store/storetest"
)

// TestDurabilityMatrixStorageFaultsBlockRefUpdate is WALD-46's headline
// test: an injected fault at every storage failure point in journalPush
// ensures the hook refuses the push in one line and leaves the repository's
// refs untouched.
func TestDurabilityMatrixStorageFaultsBlockRefUpdate(t *testing.T) {
	pack, sha := realCommit(t)
	segHash := journal.ComputeSegmentHash(pack)

	tests := []struct {
		name       string
		targetRule func(stream journal.StreamID) storetest.Rule
	}{
		// 1. LoadSigner failure points (reading the _meta genesis record)
		{
			name: "LoadSigner: genesis GET 500 InternalError",
			targetRule: func(stream journal.StreamID) storetest.Rule {
				return storetest.Rule{
					Op:    storetest.OpGet,
					Key:   "prefix/" + journal.TxKey(journal.MetaStreamID, 0),
					Count: 10,
					Fault: storetest.Fault{Status: 500, Code: "InternalError"},
				}
			},
		},
		{
			name: "LoadSigner: genesis GET 503 SlowDown",
			targetRule: func(stream journal.StreamID) storetest.Rule {
				return storetest.Rule{
					Op:    storetest.OpGet,
					Key:   "prefix/" + journal.TxKey(journal.MetaStreamID, 0),
					Count: 10,
					Fault: storetest.Fault{Status: 503, Code: "SlowDown"},
				}
			},
		},
		{
			name: "LoadSigner: genesis GET connection drop",
			targetRule: func(stream journal.StreamID) storetest.Rule {
				return storetest.Rule{
					Op:    storetest.OpGet,
					Key:   "prefix/" + journal.TxKey(journal.MetaStreamID, 0),
					Count: 10,
					Fault: storetest.Fault{Drop: true},
				}
			},
		},
		{
			name: "LoadSigner: genesis GET truncated body",
			targetRule: func(stream journal.StreamID) storetest.Rule {
				return storetest.Rule{
					Op:    storetest.OpGet,
					Key:   "prefix/" + journal.TxKey(journal.MetaStreamID, 0),
					Count: 10,
					Fault: storetest.Fault{TruncateBody: 5},
				}
			},
		},
		{
			name: "LoadSigner: genesis GET 404 absent journal",
			targetRule: func(stream journal.StreamID) storetest.Rule {
				return storetest.Rule{
					Op:    storetest.OpGet,
					Key:   "prefix/" + journal.TxKey(journal.MetaStreamID, 0),
					Count: 10,
					Fault: storetest.Fault{Status: 404, Code: "NoSuchKey"},
				}
			},
		},

		// 2. Leases.Open failure points (listing existing transactions)
		{
			name: "Leases.Open: tx LIST 500 InternalError",
			targetRule: func(stream journal.StreamID) storetest.Rule {
				return storetest.Rule{
					Op:    storetest.OpList,
					Key:   "prefix/" + journal.TxPrefix(stream),
					Count: 10,
					Fault: storetest.Fault{Status: 500, Code: "InternalError"},
				}
			},
		},
		{
			name: "Leases.Open: tx LIST 503 SlowDown",
			targetRule: func(stream journal.StreamID) storetest.Rule {
				return storetest.Rule{
					Op:    storetest.OpList,
					Key:   "prefix/" + journal.TxPrefix(stream),
					Count: 10,
					Fault: storetest.Fault{Status: 503, Code: "SlowDown"},
				}
			},
		},
		{
			name: "Leases.Open: tx LIST connection drop",
			targetRule: func(stream journal.StreamID) storetest.Rule {
				return storetest.Rule{
					Op:    storetest.OpList,
					Key:   "prefix/" + journal.TxPrefix(stream),
					Count: 10,
					Fault: storetest.Fault{Drop: true},
				}
			},
		},

		// 3. AppendSegment failure points (unconditional PUT of segment pack)
		{
			name: "AppendSegment: segment PUT 500 InternalError",
			targetRule: func(stream journal.StreamID) storetest.Rule {
				return storetest.Rule{
					Op:    storetest.OpPut,
					Key:   "prefix/" + journal.SegmentKey(stream, segHash),
					Count: 10,
					Fault: storetest.Fault{Status: 500, Code: "InternalError"},
				}
			},
		},
		{
			name: "AppendSegment: segment PUT 503 SlowDown",
			targetRule: func(stream journal.StreamID) storetest.Rule {
				return storetest.Rule{
					Op:    storetest.OpPut,
					Key:   "prefix/" + journal.SegmentKey(stream, segHash),
					Count: 10,
					Fault: storetest.Fault{Status: 503, Code: "SlowDown"},
				}
			},
		},
		{
			name: "AppendSegment: segment PUT connection drop",
			targetRule: func(stream journal.StreamID) storetest.Rule {
				return storetest.Rule{
					Op:    storetest.OpPut,
					Key:   "prefix/" + journal.SegmentKey(stream, segHash),
					Count: 10,
					Fault: storetest.Fault{Drop: true},
				}
			},
		},
		{
			name: "AppendSegment: segment PUT truncated body",
			targetRule: func(stream journal.StreamID) storetest.Rule {
				return storetest.Rule{
					Op:    storetest.OpPut,
					Key:   "prefix/" + journal.SegmentKey(stream, segHash),
					Count: 10,
					Fault: storetest.Fault{TruncateBody: 10},
				}
			},
		},

		// 4. AppendRefTx failure points (conditional PUT of ref transaction)
		{
			name: "AppendRefTx: tx PUT 500 InternalError",
			targetRule: func(stream journal.StreamID) storetest.Rule {
				return storetest.Rule{
					Op:    storetest.OpPutIfAbsent,
					Key:   "prefix/" + journal.TxKey(stream, 0),
					Count: 10,
					Fault: storetest.Fault{Status: 500, Code: "InternalError"},
				}
			},
		},
		{
			name: "AppendRefTx: tx PUT 503 SlowDown",
			targetRule: func(stream journal.StreamID) storetest.Rule {
				return storetest.Rule{
					Op:    storetest.OpPutIfAbsent,
					Key:   "prefix/" + journal.TxKey(stream, 0),
					Count: 10,
					Fault: storetest.Fault{Status: 503, Code: "SlowDown"},
				}
			},
		},
		{
			name: "AppendRefTx: tx PUT connection drop",
			targetRule: func(stream journal.StreamID) storetest.Rule {
				return storetest.Rule{
					Op:    storetest.OpPutIfAbsent,
					Key:   "prefix/" + journal.TxKey(stream, 0),
					Count: 10,
					Fault: storetest.Fault{Drop: true},
				}
			},
		},
		{
			name: "AppendRefTx: tx PUT truncated body",
			targetRule: func(stream journal.StreamID) storetest.Rule {
				return storetest.Rule{
					Op:    storetest.OpPutIfAbsent,
					Key:   "prefix/" + journal.TxKey(stream, 0),
					Count: 10,
					Fault: storetest.Fault{TruncateBody: 10},
				}
			},
		},
		{
			name: "AppendRefTx: tx PUT 412 PreconditionFailed (rival write / CAS collision)",
			targetRule: func(stream journal.StreamID) storetest.Rule {
				return storetest.Rule{
					Op:    storetest.OpPutIfAbsent,
					Key:   "prefix/" + journal.TxKey(stream, 0),
					Fault: storetest.Fault{Rival: []byte("rival-fencing-record")},
				}
			},
		},
		{
			name: "AppendRefTx: tx PUT ambiguous write (Land=true, 500)",
			targetRule: func(stream journal.StreamID) storetest.Rule {
				return storetest.Rule{
					Op:    storetest.OpPutIfAbsent,
					Key:   "prefix/" + journal.TxKey(stream, 0),
					Fault: storetest.Fault{Land: true, Status: 500, Code: "InternalError"},
				}
			},
		},
		{
			name: "AppendRefTx: tx PUT ambiguous write (Land=true, Drop=true)",
			targetRule: func(stream journal.StreamID) storetest.Rule {
				return storetest.Rule{
					Op:    storetest.OpPutIfAbsent,
					Key:   "prefix/" + journal.TxKey(stream, 0),
					Fault: storetest.Fault{Land: true, Drop: true},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newHookJournalFixture(t, "repo")
			f.quarantineIndexed(t, "push", pack)

			stream := journal.StreamID(f.repo)
			rule := tt.targetRule(stream)
			rule.Call = 1
			f.fake.Inject(rule)

			updates := []journal.RefUpdate{
				{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: sha},
			}
			err := runHook(t, updates)
			if err == nil {
				t.Fatalf("runHook succeeded despite injected fault, want refusal")
			}

			// Invariant: every refusal is an operator-facing *refusal.Refusal and exactly one line.
			if strings.ContainsAny(err.Error(), "\r\n") {
				t.Errorf("refusal contains newlines: %q", err.Error())
			}
			var ref *refusal.Refusal
			if !errors.As(err, &ref) {
				t.Errorf("expected *refusal.Refusal, got: %T (%v)", err, err)
			}

			// Invariant: no locks left behind.
			assertNoLocks(t, f.repoPath)

			// Invariant: the ref was NOT moved in the repository.
			if got := readRef(t, f.repoPath, "refs/heads/main"); got != "" {
				t.Errorf("refs/heads/main = %q after failed hook, want empty", got)
			}
		})
	}
}

// TestDurabilityMatrixGitSideRefFailuresLeaveNoJournalRecord verifies the
// second direction of WALD-46's amended invariant: every git-side ref
// failure must leave no ref-transaction record claiming it happened.
func TestDurabilityMatrixGitSideRefFailuresLeaveNoJournalRecord(t *testing.T) {
	pack, sha := realCommitMsg(t, "base-commit")

	t.Run("D/F conflict in single-ref push", func(t *testing.T) {
		f := newHookJournalFixture(t, "repo")
		// refs/heads/feature already exists on disk
		realizeObjects(t, f.repoPath, pack)
		setRef(t, f.repoPath, "refs/heads/feature", sha)

		// Push refs/heads/feature/x with new objects
		pack2, sha2 := realCommitMsg(t, "df-commit")
		f.quarantineIndexed(t, "df", pack2)

		updates := []journal.RefUpdate{
			{Ref: "refs/heads/feature/x", OldOID: journal.ZeroOID40, NewOID: sha2},
		}
		// A single-ref D/F conflict: git will refuse feature/x.
		// WALD-128 Done-when 9: journals segment only, NO ref transaction.
		if err := runHook(t, updates); err != nil {
			t.Fatalf("runHook: %v", err)
		}

		// Segment was journaled because objects are real
		if keys := f.segmentKeys(); len(keys) != 1 {
			t.Errorf("got %d segments, want 1", len(keys))
		}

		// BUT no ref transaction was written claiming feature/x moved
		txKey := "prefix/" + journal.TxKey(journal.StreamID(f.repo), 0)
		if _, ok := f.fake.Object(txKey); ok {
			t.Errorf("ref transaction at %s exists, want NO ref transaction for refused D/F ref", txKey)
		}
		assertNoLocks(t, f.repoPath)
	})

	t.Run("D/F conflict within batch (both orders) refused whole", func(t *testing.T) {
		for _, order := range []string{"parent-first", "child-first"} {
			t.Run(order, func(t *testing.T) {
				f := newHookJournalFixture(t, "repo")
				f.quarantineIndexed(t, "batch-df", pack)

				var updates []journal.RefUpdate
				if order == "parent-first" {
					updates = []journal.RefUpdate{
						{Ref: "refs/heads/feature", OldOID: journal.ZeroOID40, NewOID: sha},
						{Ref: "refs/heads/feature/x", OldOID: journal.ZeroOID40, NewOID: sha},
					}
				} else {
					updates = []journal.RefUpdate{
						{Ref: "refs/heads/feature/x", OldOID: journal.ZeroOID40, NewOID: sha},
						{Ref: "refs/heads/feature", OldOID: journal.ZeroOID40, NewOID: sha},
					}
				}

				err := runHook(t, updates)
				if err == nil {
					t.Fatalf("runHook accepted D/F collision batch, want refusal")
				}
				if !strings.Contains(err.Error(), "one ref name is a directory prefix of the other") {
					t.Errorf("expected D/F refusal, got: %q", err.Error())
				}

				// Nothing journaled for this repo
				for _, k := range f.fake.Keys() {
					if strings.HasPrefix(k, "prefix/v1/streams/"+f.repo+"/") {
						t.Errorf("key %q was journaled for %s, want nothing", k, f.repo)
					}
				}
				assertNoLocks(t, f.repoPath)
			})
		}
	})

	t.Run("Stale old_oid in single-ref push", func(t *testing.T) {
		f := newHookJournalFixture(t, "repo")
		realizeObjects(t, f.repoPath, pack)
		setRef(t, f.repoPath, "refs/heads/main", sha)

		// Push claiming main is at zero OID
		pack2, sha2 := realCommitMsg(t, "stale-commit")
		f.quarantineIndexed(t, "stale", pack2)

		updates := []journal.RefUpdate{
			{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: sha2},
		}
		if err := runHook(t, updates); err != nil {
			t.Fatalf("runHook: %v", err)
		}

		// No ref transaction claiming stale update applied
		txKey := "prefix/" + journal.TxKey(journal.StreamID(f.repo), 0)
		if _, ok := f.fake.Object(txKey); ok {
			t.Errorf("ref transaction at %s exists, want none", txKey)
		}
		assertNoLocks(t, f.repoPath)
	})

	t.Run("Lock contention refuses whole push", func(t *testing.T) {
		f := newHookJournalFixture(t, "repo")
		realizeObjects(t, f.repoPath, pack)
		setRef(t, f.repoPath, "refs/heads/main", sha)

		// Create a contention lock file directly
		lockPath := filepath.Join(f.repoPath, "refs", "heads", "main.lock")
		writeFile(t, lockPath, []byte("foreign-lock"))

		pack2, sha2 := realCommitMsg(t, "contending-lock-commit")
		f.quarantineIndexed(t, "lock", pack2)

		updates := []journal.RefUpdate{
			{Ref: "refs/heads/main", OldOID: sha, NewOID: sha2},
		}
		err := runHook(t, updates)
		if err == nil {
			t.Fatalf("runHook succeeded with lock held, want refusal")
		}
		if !strings.Contains(err.Error(), "could not determine whether git will accept this push") {
			t.Errorf("expected lock collision refusal, got: %q", err.Error())
		}

		// Nothing journaled for this repo
		for _, k := range f.fake.Keys() {
			if strings.HasPrefix(k, "prefix/v1/streams/"+f.repo+"/") {
				t.Errorf("key %q was journaled for %s, want nothing", k, f.repo)
			}
		}

		os.Remove(lockPath)
		assertNoLocks(t, f.repoPath)
	})

	t.Run("Nonexistent object without alternates refuses whole push", func(t *testing.T) {
		f := newHookJournalFixture(t, "repo")
		f.noQuarantine(t)
		updates := []journal.RefUpdate{
			{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "0123456789abcdef0123456789abcdef01234567"},
		}
		err := runHook(t, updates)
		if err == nil {
			t.Fatalf("runHook accepted nonexistent object, want refusal")
		}
		for _, k := range f.fake.Keys() {
			if strings.HasPrefix(k, "prefix/v1/streams/"+f.repo+"/") {
				t.Errorf("key %q was journaled for %s, want nothing", k, f.repo)
			}
		}
		assertNoLocks(t, f.repoPath)
	})
}
