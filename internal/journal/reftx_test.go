package journal_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/writtendev/walden/internal/journal"
)

func TestValidateOID(t *testing.T) {
	valid := []string{
		"0000000000000000000000000000000000000000",
		"4b825dc642cb6eb9a060e54bf8d69288fbee4904",
		"4B825DC642CB6EB9A060E54BF8D69288FBEE4904",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	for _, oid := range valid {
		if err := journal.ValidateOID(oid); err != nil {
			t.Errorf("expected valid OID %q, got error: %v", oid, err)
		}
	}

	invalid := []struct {
		oid string
		err string
	}{
		{"", "oid must be 40 or 64 hex characters"},
		{"4b825dc6", "oid must be 40 or 64 hex characters"},
		{strings.Repeat("0", 39), "oid must be 40 or 64 hex characters"},
		{strings.Repeat("0", 41), "oid must be 40 or 64 hex characters"},
		{strings.Repeat("0", 63), "oid must be 40 or 64 hex characters"},
		{strings.Repeat("0", 65), "oid must be 40 or 64 hex characters"},
		{strings.Repeat("g", 40), "sha1 oid must be 40 hexadecimal characters"},
		{strings.Repeat("z", 64), "sha256 oid must be 64 hexadecimal characters"},
	}
	for _, tc := range invalid {
		err := journal.ValidateOID(tc.oid)
		if err == nil {
			t.Errorf("expected error for OID %q, got nil", tc.oid)
			continue
		}
		if !errors.Is(err, journal.ErrInvalidOID) {
			t.Errorf("expected ErrInvalidOID for %q, got %v", tc.oid, err)
		}
		if !strings.Contains(err.Error(), tc.err) {
			t.Errorf("expected error containing %q, got %q", tc.err, err.Error())
		}
	}
}

func TestValidateRefName(t *testing.T) {
	valid := []string{
		"HEAD",
		"refs/heads/main",
		"refs/heads/feature/branch-1",
		"refs/tags/v1.0.0",
		"refs/tags/v2.0-rc.1",
		"refs/remotes/origin/main",
		"refs/changes/01/123/1",
		"refs/heads/föö-bär", // Non-ASCII UTF-8 bytes
		"refs/heads/日本語",     // Multi-byte UTF-8
	}
	for _, ref := range valid {
		if err := journal.ValidateRefName(ref); err != nil {
			t.Errorf("expected valid ref name %q, got error: %v", ref, err)
		}
	}

	invalid := []struct {
		ref string
		err string
	}{
		{"", "cannot be empty"},
		{"@", "cannot be '@'"},
		{strings.Repeat("a", 4097), "ref name exceeds 4096 bytes"},
		{"/refs/heads/main", "leading or trailing slashes"},
		{"refs/heads/main/", "leading or trailing slashes"},
		{"refs/heads//main", "consecutive slashes"},
		{"refs/heads/../main", "'..' sequences are not allowed"},
		{"refs/heads/main@{1}", "'@{' sequences are not allowed"},
		{"refs/heads/main.lock", "cannot end with '.lock'"},
		{"refs/heads/foo.lock/bar", "cannot end with '.lock'"},
		{"refs/heads/.main", "cannot begin or end with dot"},
		{"refs/heads/main.", "cannot begin or end with dot"},
		{"refs/heads/branch name", "contains control character or whitespace"},
		{"refs/heads/branch\nname", "contains control character or whitespace"},
		{"refs/heads/branch\tname", "contains control character or whitespace"},
		{"refs/heads/branch~1", "contains illegal character"},
		{"refs/heads/branch^1", "contains illegal character"},
		{"refs/heads/branch:1", "contains illegal character"},
		{"refs/heads/branch?1", "contains illegal character"},
		{"refs/heads/branch*1", "contains illegal character"},
		{"refs/heads/branch[1", "contains illegal character"},
		{"refs/heads/branch\\1", "contains illegal character"},
	}
	for _, tc := range invalid {
		err := journal.ValidateRefName(tc.ref)
		if err == nil {
			t.Errorf("expected error for ref %q, got nil", tc.ref)
			continue
		}
		if !errors.Is(err, journal.ErrInvalidRef) {
			t.Errorf("expected ErrInvalidRef for %q, got %v", tc.ref, err)
		}
		if !strings.Contains(err.Error(), tc.err) {
			t.Errorf("expected error containing %q, got %q", tc.err, err.Error())
		}
	}
}

func TestValidateRefUpdate(t *testing.T) {
	valid := []journal.RefUpdate{
		{
			Ref:    "refs/heads/main",
			OldOID: journal.ZeroOID40,
			NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
		},
		{
			Ref:    "refs/heads/main",
			OldOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
			NewOID: "8a65c6d3715c0e1e92d6e3e5362e49c7198cfb60",
		},
		{
			Ref:    "refs/heads/feature",
			OldOID: "8a65c6d3715c0e1e92d6e3e5362e49c7198cfb60",
			NewOID: journal.ZeroOID40,
		},
		{
			Ref:    "refs/heads/sha256-branch",
			OldOID: journal.ZeroOID64,
			NewOID: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
	}
	for _, u := range valid {
		if err := journal.ValidateRefUpdate(u); err != nil {
			t.Errorf("expected valid ref update %+v, got error: %v", u, err)
		}
	}

	invalid := []struct {
		u   journal.RefUpdate
		err string
	}{
		{
			journal.RefUpdate{Ref: "", OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
			"cannot be empty",
		},
		{
			journal.RefUpdate{Ref: "refs/heads/main", OldOID: "bad-oid", NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
			"invalid old_oid",
		},
		{
			journal.RefUpdate{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "bad-oid"},
			"invalid new_oid",
		},
		{
			// Mismatched OID lengths (SHA-1 to SHA-256)
			journal.RefUpdate{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
			"mismatched lengths",
		},
		{
			// No-op ref update (old_oid == new_oid)
			journal.RefUpdate{Ref: "refs/heads/main", OldOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904", NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
			"no-op ref update",
		},
		{
			// Zero to zero transition
			journal.RefUpdate{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: journal.ZeroOID40},
			"cannot transition from zero oid to zero oid",
		},
	}
	for _, tc := range invalid {
		err := journal.ValidateRefUpdate(tc.u)
		if err == nil {
			t.Errorf("expected error for ref update %+v, got nil", tc.u)
			continue
		}
		if !strings.Contains(err.Error(), tc.err) {
			t.Errorf("expected error containing %q, got %q", tc.err, err.Error())
		}
	}
}

func TestCanonicalRefUpdatePayload(t *testing.T) {
	stream := journal.StreamID("repo-alpha")
	seq := journal.Seq(0)
	timestamp := "2026-08-31T00:02:00Z"
	segments := []string{
		"4a49646b96dbca4f1eb8699ef7cefdcae68fefc6ee7ae6305a3f25c7e1ef5638",
	}
	updates := []journal.RefUpdate{
		{
			Ref:    "refs/heads/main",
			OldOID: "0000000000000000000000000000000000000000",
			NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
		},
	}

	payload := journal.CanonicalRefUpdatePayload(stream, seq, 0, timestamp, segments, updates)
	expected := "walden-ref-update:v1\n" +
		"stream:repo-alpha\n" +
		"seq:0\n" +
		"key_epoch:0\n" +
		"timestamp:2026-08-31T00:02:00Z\n" +
		"segment:4a49646b96dbca4f1eb8699ef7cefdcae68fefc6ee7ae6305a3f25c7e1ef5638\n" +
		"update:refs/heads/main 0000000000000000000000000000000000000000 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n"

	if string(payload) != expected {
		t.Errorf("payload mismatch:\ngot:\n%s\nwant:\n%s", string(payload), expected)
	}

	// Test zero segments (e.g. branch deletion)
	updatesDel := []journal.RefUpdate{
		{
			Ref:    "refs/heads/feature",
			OldOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
			NewOID: "0000000000000000000000000000000000000000",
		},
	}
	payloadDel := journal.CanonicalRefUpdatePayload(stream, 1, 1, timestamp, nil, updatesDel)
	expectedDel := "walden-ref-update:v1\n" +
		"stream:repo-alpha\n" +
		"seq:1\n" +
		"key_epoch:1\n" +
		"timestamp:2026-08-31T00:02:00Z\n" +
		"update:refs/heads/feature 4b825dc642cb6eb9a060e54bf8d69288fbee4904 0000000000000000000000000000000000000000\n"

	if string(payloadDel) != expectedDel {
		t.Errorf("payload mismatch on zero segments:\ngot:\n%s\nwant:\n%s", string(payloadDel), expectedDel)
	}
}

func TestSignAndVerifyRefTx(t *testing.T) {
	priv, pub := deterministicKeypair(0x01)
	formattedPub := journal.FormatPublicKey(pub)

	rec := &journal.RefTransactionRecord{
		Version: "v1",
		Stream:  "repo-alpha",
		Seq:     0,
		Type:    "ref_update",
		Segments: []string{
			"4a49646b96dbca4f1eb8699ef7cefdcae68fefc6ee7ae6305a3f25c7e1ef5638",
		},
		Updates: []journal.RefUpdate{
			{
				Ref:    "refs/heads/main",
				OldOID: "0000000000000000000000000000000000000000",
				NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
			},
		},
		Timestamp: "2026-08-31T00:02:00Z",
	}

	if err := journal.SignRefTx(priv, rec); err != nil {
		t.Fatalf("SignRefTx failed: %v", err)
	}

	if !strings.HasPrefix(rec.Signature, "ed25519:") {
		t.Fatalf("expected signature prefix 'ed25519:', got %q", rec.Signature)
	}

	// Successful verification
	if err := journal.VerifyRefTx(rec, formattedPub); err != nil {
		t.Fatalf("VerifyRefTx failed: %v", err)
	}

	// Verify with wrong public key
	_, wrongPub := deterministicKeypair(0x02)
	if err := journal.VerifyRefTx(rec, journal.FormatPublicKey(wrongPub)); !errors.Is(err, journal.ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch with wrong key, got %v", err)
	}

	// Verify tampering detection
	// 1. Tamper stream
	recTamperedStream := *rec
	recTamperedStream.Stream = "repo-beta"
	if err := journal.VerifyRefTx(&recTamperedStream, formattedPub); !errors.Is(err, journal.ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch when tampering stream, got %v", err)
	}

	// 2. Tamper sequence
	recTamperedSeq := *rec
	recTamperedSeq.Seq = 1
	if err := journal.VerifyRefTx(&recTamperedSeq, formattedPub); !errors.Is(err, journal.ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch when tampering seq, got %v", err)
	}

	// 3. Tamper timestamp
	recTamperedTime := *rec
	recTamperedTime.Timestamp = "2026-08-31T00:03:00Z"
	if err := journal.VerifyRefTx(&recTamperedTime, formattedPub); !errors.Is(err, journal.ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch when tampering timestamp, got %v", err)
	}

	// 4. Tamper segments
	recTamperedSeg := *rec
	recTamperedSeg.Segments = []string{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
	if err := journal.VerifyRefTx(&recTamperedSeg, formattedPub); !errors.Is(err, journal.ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch when tampering segments, got %v", err)
	}

	// 5. Tamper ref update OID
	recTamperedUpdate := *rec
	recTamperedUpdate.Updates = []journal.RefUpdate{
		{
			Ref:    "refs/heads/main",
			OldOID: "0000000000000000000000000000000000000000",
			NewOID: "8a65c6d3715c0e1e92d6e3e5362e49c7198cfb60",
		},
	}
	if err := journal.VerifyRefTx(&recTamperedUpdate, formattedPub); !errors.Is(err, journal.ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch when tampering update OID, got %v", err)
	}

	// 6. Tamper ref name
	recTamperedRefName := *rec
	recTamperedRefName.Updates = []journal.RefUpdate{
		{
			Ref:    "refs/heads/master",
			OldOID: "0000000000000000000000000000000000000000",
			NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
		},
	}
	if err := journal.VerifyRefTx(&recTamperedRefName, formattedPub); !errors.Is(err, journal.ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch when tampering ref name, got %v", err)
	}

	// 7. Tamper key_epoch: it is covered by the signature (WALD-96) exactly like every
	// other field here, so changing it invalidates the signature rather than silently
	// picking a different verification key.
	recTamperedEpoch := *rec
	recTamperedEpoch.KeyEpoch = rec.KeyEpoch + 1
	if err := journal.VerifyRefTx(&recTamperedEpoch, formattedPub); !errors.Is(err, journal.ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch when tampering key_epoch, got %v", err)
	}
}

func TestSigningChainRefTxVerification(t *testing.T) {
	priv1, pub1 := deterministicKeypair(0x01)
	priv2, pub2 := deterministicKeypair(0x02)

	chain := journal.NewSigningChain()

	// 1. Genesis record at _meta seq 0
	genesis := &journal.GenesisRecord{
		Version:   "v1",
		Stream:    journal.MetaStreamID,
		Seq:       0,
		Type:      "genesis",
		PublicKey: journal.FormatPublicKey(pub1),
		Timestamp: "2026-08-31T00:00:00Z",
	}
	if err := chain.ApplyGenesis(genesis); err != nil {
		t.Fatalf("ApplyGenesis failed: %v", err)
	}

	// 2. Ref tx signed with key 1
	tx0 := &journal.RefTransactionRecord{
		Version: "v1",
		Stream:  "repo-alpha",
		Seq:     0,
		Type:    "ref_update",
		Segments: []string{
			"4a49646b96dbca4f1eb8699ef7cefdcae68fefc6ee7ae6305a3f25c7e1ef5638",
		},
		Updates: []journal.RefUpdate{
			{
				Ref:    "refs/heads/main",
				OldOID: "0000000000000000000000000000000000000000",
				NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
			},
		},
		Timestamp: "2026-08-31T00:01:00Z",
	}
	if err := journal.SignRefTx(priv1, tx0); err != nil {
		t.Fatalf("SignRefTx(1) failed: %v", err)
	}
	if err := chain.VerifyRefTx(tx0); err != nil {
		t.Fatalf("chain.VerifyRefTx(tx0) failed: %v", err)
	}

	// 3. Key rotation record at _meta seq 1 (key1 -> key2)
	rot := &journal.KeyRotationRecord{
		Version:      "v1",
		Stream:       journal.MetaStreamID,
		Seq:          1,
		Type:         "key_rotation",
		OldPublicKey: journal.FormatPublicKey(pub1),
		NewPublicKey: journal.FormatPublicKey(pub2),
		Timestamp:    "2026-08-31T00:02:00Z",
	}
	if err := journal.SignRotation(priv1, rot); err != nil {
		t.Fatalf("SignRotation failed: %v", err)
	}
	if err := chain.ApplyRotation(rot); err != nil {
		t.Fatalf("ApplyRotation failed: %v", err)
	}

	// 4. Ref tx signed with new key 2
	tx1 := &journal.RefTransactionRecord{
		Version:  "v1",
		Stream:   "repo-alpha",
		Seq:      1,
		Type:     "ref_update",
		KeyEpoch: 1,
		Updates: []journal.RefUpdate{
			{
				Ref:    "refs/heads/main",
				OldOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
				NewOID: "8a65c6d3715c0e1e92d6e3e5362e49c7198cfb60",
			},
		},
		Timestamp: "2026-08-31T00:03:00Z",
	}
	if err := journal.SignRefTx(priv2, tx1); err != nil {
		t.Fatalf("SignRefTx(2) failed: %v", err)
	}
	if err := chain.VerifyRefTx(tx1); err != nil {
		t.Fatalf("chain.VerifyRefTx(tx1) failed with new key: %v", err)
	}

	// 5. Ref tx signed with old key 1 after rotation MUST fail verification against chain
	tx1OldKey := *tx1
	if err := journal.SignRefTx(priv1, &tx1OldKey); err != nil {
		t.Fatalf("SignRefTx with old key failed: %v", err)
	}
	if err := chain.VerifyRefTx(&tx1OldKey); !errors.Is(err, journal.ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch for old key after rotation, got %v", err)
	}
}

// TestSigningChainKeyEpochEnforcement covers WALD-96: a ref-transaction record is
// verified against the key its own key_epoch names, an epoch outside the verified
// chain is refused rather than a reason to fall back to the active key, and an epoch
// lower than one already seen on the same stream is refused too, so a retired key
// cannot go on validating records forever.
func TestSigningChainKeyEpochEnforcement(t *testing.T) {
	priv1, pub1 := deterministicKeypair(0x01)
	priv2, pub2 := deterministicKeypair(0x02)

	chain := journal.NewSigningChain()
	genesis := &journal.GenesisRecord{
		Version:   "v1",
		Stream:    journal.MetaStreamID,
		Seq:       0,
		Type:      "genesis",
		PublicKey: journal.FormatPublicKey(pub1),
		Timestamp: "2026-08-31T00:00:00Z",
	}
	if err := chain.ApplyGenesis(genesis); err != nil {
		t.Fatalf("ApplyGenesis failed: %v", err)
	}
	if chain.CurrentEpoch() != 0 {
		t.Errorf("CurrentEpoch after genesis = %d, want 0", chain.CurrentEpoch())
	}

	rot := &journal.KeyRotationRecord{
		Version:      "v1",
		Stream:       journal.MetaStreamID,
		Seq:          1,
		Type:         "key_rotation",
		OldPublicKey: journal.FormatPublicKey(pub1),
		NewPublicKey: journal.FormatPublicKey(pub2),
		Timestamp:    "2026-08-31T00:02:00Z",
	}
	if err := journal.SignRotation(priv1, rot); err != nil {
		t.Fatalf("SignRotation failed: %v", err)
	}
	if err := chain.ApplyRotation(rot); err != nil {
		t.Fatalf("ApplyRotation failed: %v", err)
	}
	if chain.CurrentEpoch() != 1 {
		t.Errorf("CurrentEpoch after rotation = %d, want 1", chain.CurrentEpoch())
	}

	newRec := func(seq journal.Seq, epoch journal.Epoch) *journal.RefTransactionRecord {
		return &journal.RefTransactionRecord{
			Version:  "v1",
			Stream:   "repo-x",
			Seq:      seq,
			Type:     "ref_update",
			KeyEpoch: epoch,
			Updates: []journal.RefUpdate{
				{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
			},
			Timestamp: "2026-08-31T00:03:00Z",
		}
	}

	// An epoch naming a key that has never existed in the chain is refused outright,
	// not treated as a request to fall back to the active key.
	unknown := newRec(0, 2)
	if err := journal.SignRefTx(priv2, unknown); err != nil {
		t.Fatalf("SignRefTx failed: %v", err)
	}
	err := chain.VerifyRefTx(unknown)
	if !errors.Is(err, journal.ErrUnknownKeyEpoch) {
		t.Errorf("expected ErrUnknownKeyEpoch for out-of-range epoch, got %v", err)
	}
	wantMsg := "refusal: replay failed: ref update on stream repo-x at seq 0 names unknown key epoch 2"
	if err == nil || err.Error() != wantMsg {
		t.Errorf("unknown key epoch refusal = %q, want %q", err, wantMsg)
	}

	// seq 0 at epoch 0, signed by the genesis key: establishes the floor for repo-x.
	rec0 := newRec(0, 0)
	if err := journal.SignRefTx(priv1, rec0); err != nil {
		t.Fatalf("SignRefTx failed: %v", err)
	}
	if err := chain.VerifyRefTx(rec0); err != nil {
		t.Fatalf("chain.VerifyRefTx(rec0) failed: %v", err)
	}

	// A record naming epoch 1 but signed by the epoch-0 key fails signature
	// verification: the epoch names which key to check against, and does not by
	// itself make a record valid.
	wrongKey := newRec(1, 1)
	if err := journal.SignRefTx(priv1, wrongKey); err != nil {
		t.Fatalf("SignRefTx failed: %v", err)
	}
	if err := chain.VerifyRefTx(wrongKey); !errors.Is(err, journal.ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch for epoch/key mismatch, got %v", err)
	}

	// seq 1 at epoch 1, correctly signed by the rotated key: advances the floor.
	rec1 := newRec(1, 1)
	if err := journal.SignRefTx(priv2, rec1); err != nil {
		t.Fatalf("SignRefTx failed: %v", err)
	}
	if err := chain.VerifyRefTx(rec1); err != nil {
		t.Fatalf("chain.VerifyRefTx(rec1) failed: %v", err)
	}

	// seq 2 naming epoch 0 again — the retired key correctly signs it, but the floor
	// this stream already reached (epoch 1) refuses it anyway. Without this check a
	// retired key would go on validating records forever, which defeats rotation.
	regressed := newRec(2, 0)
	if err := journal.SignRefTx(priv1, regressed); err != nil {
		t.Fatalf("SignRefTx failed: %v", err)
	}
	err = chain.VerifyRefTx(regressed)
	if !errors.Is(err, journal.ErrKeyEpochRegression) {
		t.Errorf("expected ErrKeyEpochRegression, got %v", err)
	}
	wantRegressionMsg := "refusal: replay failed: ref update on stream repo-x at seq 2 names key epoch 0 below epoch 1 already seen on this stream"
	if err == nil || err.Error() != wantRegressionMsg {
		t.Errorf("key epoch regression refusal = %q, want %q", err, wantRegressionMsg)
	}
}

func TestUnknownFieldsToleranceAndForwardCompatibility(t *testing.T) {
	priv, pub := deterministicKeypair(0x01)
	formattedPub := journal.FormatPublicKey(pub)

	baseRec := &journal.RefTransactionRecord{
		Version: "v1",
		Stream:  "repo-alpha",
		Seq:     0,
		Type:    "ref_update",
		Segments: []string{
			"4a49646b96dbca4f1eb8699ef7cefdcae68fefc6ee7ae6305a3f25c7e1ef5638",
		},
		Updates: []journal.RefUpdate{
			{
				Ref:    "refs/heads/main",
				OldOID: "0000000000000000000000000000000000000000",
				NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
			},
		},
		Timestamp: "2026-08-31T00:02:00Z",
	}

	if err := journal.SignRefTx(priv, baseRec); err != nil {
		t.Fatalf("SignRefTx failed: %v", err)
	}

	// Construct JSON string with additional unknown fields (simulating v2 extensions or client metadata)
	jsonWithExtraFields := `{
		"version": "v1",
		"stream": "repo-alpha",
		"seq": "0",
		"type": "ref_update",
		"segments": [
			"4a49646b96dbca4f1eb8699ef7cefdcae68fefc6ee7ae6305a3f25c7e1ef5638"
		],
		"updates": [
			{
				"ref": "refs/heads/main",
				"old_oid": "0000000000000000000000000000000000000000",
				"new_oid": "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
				"extra_ref_metadata": "ignored"
			}
		],
		"timestamp": "2026-08-31T00:02:00Z",
		"signature": "` + baseRec.Signature + `",
		"v2_future_field": "some future capability",
		"client_ip": "192.168.1.1",
		"metadata": {"custom_tag": 42}
	}`

	var parsedRec journal.RefTransactionRecord
	if err := json.Unmarshal([]byte(jsonWithExtraFields), &parsedRec); err != nil {
		t.Fatalf("json.Unmarshal with extra fields failed: %v", err)
	}

	// Verification MUST succeed because unknown fields are ignored and do not alter the canonical v1 payload
	if err := journal.VerifyRefTx(&parsedRec, formattedPub); err != nil {
		t.Fatalf("VerifyRefTx failed on record with unknown fields: %v", err)
	}
}

// TestRefTxSeqEncoding covers spec section 1.1 at the record: `seq` is written as a JSON
// string holding its exact decimal form, and a record encoding it any other way is refused
// on parse rather than coerced into a sequence that is not the one its key names.
func TestRefTxSeqEncoding(t *testing.T) {
	rec := &journal.RefTransactionRecord{
		Version: "v1",
		Stream:  "repo-alpha",
		Seq:     journal.Seq(^uint64(0)),
		Type:    "ref_update",
		Segments: []string{
			"4a49646b96dbca4f1eb8699ef7cefdcae68fefc6ee7ae6305a3f25c7e1ef5638",
		},
		Updates: []journal.RefUpdate{
			{
				Ref:    "refs/heads/main",
				OldOID: "0000000000000000000000000000000000000000",
				NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
			},
		},
		Timestamp: "2026-08-31T00:02:00Z",
	}

	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if !strings.Contains(string(data), `"seq":"18446744073709551615"`) {
		t.Errorf("record does not carry seq as a decimal string: %s", data)
	}

	var parsed journal.RefTransactionRecord
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if parsed.Seq != rec.Seq {
		t.Errorf("seq round-tripped to %d, want %d", uint64(parsed.Seq), uint64(rec.Seq))
	}

	// The two encodings a reader must refuse: a JSON number, which loses precision at this
	// end of the range, and the rounded value such a reader produces from one.
	for _, encoded := range []string{`18446744073709551615`, `"18446744073709552000"`} {
		var refused journal.RefTransactionRecord
		body := strings.Replace(string(data), `"18446744073709551615"`, encoded, 1)
		err := json.Unmarshal([]byte(body), &refused)
		if err == nil {
			t.Errorf("expected seq %s to be refused, got %d", encoded, uint64(refused.Seq))
			continue
		}
		if !errors.Is(err, journal.ErrInvalidSeq) {
			t.Errorf("expected ErrInvalidSeq for seq %s, got %v", encoded, err)
		}
	}
}

func TestRefNameBytePreservation(t *testing.T) {
	priv, pub := deterministicKeypair(0x01)
	formattedPub := journal.FormatPublicKey(pub)

	// UTF-8 ref name with multi-byte characters
	utf8Ref := "refs/heads/releases/v1.0-π-テスト"

	rec := &journal.RefTransactionRecord{
		Version: "v1",
		Stream:  "repo-alpha",
		Seq:     0,
		Type:    "ref_update",
		Segments: []string{
			"4a49646b96dbca4f1eb8699ef7cefdcae68fefc6ee7ae6305a3f25c7e1ef5638",
		},
		Updates: []journal.RefUpdate{
			{
				Ref:    utf8Ref,
				OldOID: "0000000000000000000000000000000000000000",
				NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
			},
		},
		Timestamp: "2026-08-31T00:02:00Z",
	}

	if err := journal.SignRefTx(priv, rec); err != nil {
		t.Fatalf("SignRefTx with UTF-8 ref failed: %v", err)
	}

	// Marshal to JSON and unmarshal back
	jsonData, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var roundTripped journal.RefTransactionRecord
	if err := json.Unmarshal(jsonData, &roundTripped); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if roundTripped.Updates[0].Ref != utf8Ref {
		t.Errorf("ref name mismatch: got %q, want %q", roundTripped.Updates[0].Ref, utf8Ref)
	}

	if err := journal.VerifyRefTx(&roundTripped, formattedPub); err != nil {
		t.Fatalf("VerifyRefTx on round-tripped UTF-8 ref failed: %v", err)
	}
}

func TestRefTransactionRecordValidateErrors(t *testing.T) {
	// 1. Nil record
	var nilRec *journal.RefTransactionRecord
	if err := nilRec.Validate(); err == nil || !errors.Is(err, journal.ErrInvalidRefTx) {
		t.Errorf("expected ErrInvalidRefTx for nil record, got %v", err)
	}

	// 2. Unsupported version
	recBadVersion := &journal.RefTransactionRecord{
		Version:   "v2",
		Stream:    "repo-alpha",
		Seq:       0,
		Type:      journal.RecordTypeRefUpdate,
		Updates:   []journal.RefUpdate{{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"}},
		Timestamp: "2026-08-31T00:00:00Z",
	}
	if err := recBadVersion.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported version") {
		t.Errorf("expected unsupported version error, got %v", err)
	}

	// 3. Meta stream rejected
	recMetaStream := &journal.RefTransactionRecord{
		Version:   "v1",
		Stream:    journal.MetaStreamID,
		Seq:       0,
		Type:      journal.RecordTypeRefUpdate,
		Updates:   []journal.RefUpdate{{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"}},
		Timestamp: "2026-08-31T00:00:00Z",
	}
	if err := recMetaStream.Validate(); err == nil || !strings.Contains(err.Error(), "meta stream") {
		t.Errorf("expected meta stream rejection, got %v", err)
	}

	// 4. Invalid stream ID
	recBadStream := &journal.RefTransactionRecord{
		Version:   "v1",
		Stream:    "repo/invalid",
		Seq:       0,
		Type:      journal.RecordTypeRefUpdate,
		Updates:   []journal.RefUpdate{{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"}},
		Timestamp: "2026-08-31T00:00:00Z",
	}
	if err := recBadStream.Validate(); err == nil || !strings.Contains(err.Error(), "invalid stream") {
		t.Errorf("expected invalid stream error, got %v", err)
	}

	// 5. Wrong type
	recBadType := &journal.RefTransactionRecord{
		Version:   "v1",
		Stream:    "repo-alpha",
		Seq:       0,
		Type:      "genesis",
		Updates:   []journal.RefUpdate{{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"}},
		Timestamp: "2026-08-31T00:00:00Z",
	}
	if err := recBadType.Validate(); err == nil || !strings.Contains(err.Error(), "expected type") {
		t.Errorf("expected wrong type error, got %v", err)
	}

	// 6. Invalid segment hash
	recBadSeg := &journal.RefTransactionRecord{
		Version:   "v1",
		Stream:    "repo-alpha",
		Seq:       0,
		Type:      journal.RecordTypeRefUpdate,
		Segments:  []string{"not-a-hash"},
		Updates:   []journal.RefUpdate{{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"}},
		Timestamp: "2026-08-31T00:00:00Z",
	}
	if err := recBadSeg.Validate(); err == nil || !strings.Contains(err.Error(), "segment[0]") {
		t.Errorf("expected invalid segment error, got %v", err)
	}

	// 7. Duplicate segment hash
	dupHash := "4a49646b96dbca4f1eb8699ef7cefdcae68fefc6ee7ae6305a3f25c7e1ef5638"
	recDupSeg := &journal.RefTransactionRecord{
		Version:   "v1",
		Stream:    "repo-alpha",
		Seq:       0,
		Type:      journal.RecordTypeRefUpdate,
		Segments:  []string{dupHash, strings.ToUpper(dupHash)},
		Updates:   []journal.RefUpdate{{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"}},
		Timestamp: "2026-08-31T00:00:00Z",
	}
	if err := recDupSeg.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate segment") {
		t.Errorf("expected duplicate segment error, got %v", err)
	}

	// 8. Empty updates array
	recEmptyUpdates := &journal.RefTransactionRecord{
		Version:   "v1",
		Stream:    "repo-alpha",
		Seq:       0,
		Type:      journal.RecordTypeRefUpdate,
		Updates:   []journal.RefUpdate{},
		Timestamp: "2026-08-31T00:00:00Z",
	}
	if err := recEmptyUpdates.Validate(); err == nil || !strings.Contains(err.Error(), "updates array must contain at least one") {
		t.Errorf("expected empty updates error, got %v", err)
	}

	// 9. Duplicate ref in same transaction
	recDupRef := &journal.RefTransactionRecord{
		Version: "v1",
		Stream:  "repo-alpha",
		Seq:     0,
		Type:    journal.RecordTypeRefUpdate,
		Updates: []journal.RefUpdate{
			{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
			{Ref: "refs/heads/main", OldOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904", NewOID: "8a65c6d3715c0e1e92d6e3e5362e49c7198cfb60"},
		},
		Timestamp: "2026-08-31T00:00:00Z",
	}
	if err := recDupRef.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate ref update") {
		t.Errorf("expected duplicate ref update error, got %v", err)
	}

	// 10. Empty timestamp
	recEmptyTime := &journal.RefTransactionRecord{
		Version:   "v1",
		Stream:    "repo-alpha",
		Seq:       0,
		Type:      journal.RecordTypeRefUpdate,
		Updates:   []journal.RefUpdate{{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"}},
		Timestamp: "",
	}
	if err := recEmptyTime.Validate(); err == nil || !strings.Contains(err.Error(), "timestamp cannot be empty") {
		t.Errorf("expected empty timestamp error, got %v", err)
	}

	// 11. Invalid timestamp format
	recBadTime := &journal.RefTransactionRecord{
		Version:   "v1",
		Stream:    "repo-alpha",
		Seq:       0,
		Type:      journal.RecordTypeRefUpdate,
		Updates:   []journal.RefUpdate{{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"}},
		Timestamp: "not-a-date",
	}
	if err := recBadTime.Validate(); err == nil || !strings.Contains(err.Error(), "invalid timestamp") {
		t.Errorf("expected invalid timestamp error, got %v", err)
	}

	// 12. Non-UTC timestamp
	recNonUTCTime := &journal.RefTransactionRecord{
		Version:   "v1",
		Stream:    "repo-alpha",
		Seq:       0,
		Type:      journal.RecordTypeRefUpdate,
		Updates:   []journal.RefUpdate{{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"}},
		Timestamp: "2026-08-31T00:00:00+05:00",
	}
	if err := recNonUTCTime.Validate(); err == nil || !strings.Contains(err.Error(), "must be in UTC") {
		t.Errorf("expected non-UTC timestamp error, got %v", err)
	}
}

func TestSignAndVerifyRefTxErrors(t *testing.T) {
	priv, pub := deterministicKeypair(0x01)
	formattedPub := journal.FormatPublicKey(pub)

	// 1. Sign nil record
	if err := journal.SignRefTx(priv, nil); err == nil || !errors.Is(err, journal.ErrInvalidRefTx) {
		t.Errorf("expected ErrInvalidRefTx signing nil record, got %v", err)
	}

	// 2. Verify nil record
	if err := journal.VerifyRefTx(nil, formattedPub); err == nil || !errors.Is(err, journal.ErrInvalidRefTx) {
		t.Errorf("expected ErrInvalidRefTx verifying nil record, got %v", err)
	}

	rec := &journal.RefTransactionRecord{
		Version:   "v1",
		Stream:    "repo-alpha",
		Seq:       0,
		Type:      journal.RecordTypeRefUpdate,
		Updates:   []journal.RefUpdate{{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"}},
		Timestamp: "2026-08-31T00:00:00Z",
	}

	// 3. Verify record missing signature
	if err := journal.VerifyRefTx(rec, formattedPub); err == nil || !errors.Is(err, journal.ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature for missing signature, got %v", err)
	}

	// 4. Verify record with malformed public key
	recWithSig := *rec
	recWithSig.Signature = "ed25519:" + strings.Repeat("0", 128)
	if err := journal.VerifyRefTx(&recWithSig, "invalid-key"); err == nil || !errors.Is(err, journal.ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey for bad pubkey, got %v", err)
	}

	// 5. Verify record with malformed signature format
	if err := journal.VerifyRefTx(&recWithSig, formattedPub); err == nil || !errors.Is(err, journal.ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch for all-zero signature, got %v", err)
	}
	recBadSigFormat := *rec
	recBadSigFormat.Signature = "not-ed25519-sig"
	if err := journal.VerifyRefTx(&recBadSigFormat, formattedPub); err == nil || !errors.Is(err, journal.ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature for bad signature format, got %v", err)
	}

	// 6. SigningChain uninitialized / nil
	var nilChain *journal.SigningChain
	if err := nilChain.VerifyRefTx(&recWithSig); err == nil || !errors.Is(err, journal.ErrGenesisMissing) {
		t.Errorf("expected ErrGenesisMissing for nil chain, got %v", err)
	}

	uninitChain := journal.NewSigningChain()
	if err := uninitChain.VerifyRefTx(&recWithSig); err == nil || !errors.Is(err, journal.ErrGenesisMissing) {
		t.Errorf("expected ErrGenesisMissing for uninitialized chain, got %v", err)
	}
}

func TestFutureV2ReaderOwesV1Record(t *testing.T) {
	// A future v2 reader must parse and verify v1 records without requiring v2 metadata or fields.
	priv, pub := deterministicKeypair(0x01)
	formattedPub := journal.FormatPublicKey(pub)

	v1Rec := &journal.RefTransactionRecord{
		Version:   "v1",
		Stream:    "repo-future-compat",
		Seq:       42,
		Type:      "ref_update",
		Segments:  []string{"4a49646b96dbca4f1eb8699ef7cefdcae68fefc6ee7ae6305a3f25c7e1ef5638"},
		Updates:   []journal.RefUpdate{{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"}},
		Timestamp: "2026-08-31T12:00:00Z",
	}

	if err := journal.SignRefTx(priv, v1Rec); err != nil {
		t.Fatalf("SignRefTx failed: %v", err)
	}

	// Serialize and deserialize simulating a future reader reading historical v1 record
	data, err := json.Marshal(v1Rec)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var readerV2 journal.RefTransactionRecord
	if err := json.Unmarshal(data, &readerV2); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Reader confirms version is "v1" and verifies using v1 rules
	if readerV2.Version != "v1" {
		t.Fatalf("expected version v1, got %q", readerV2.Version)
	}
	if err := journal.VerifyRefTx(&readerV2, formattedPub); err != nil {
		t.Fatalf("future reader failed to verify historical v1 record: %v", err)
	}
}

func TestMixedOIDAlgorithmsInTransaction(t *testing.T) {
	// A transaction must not mix SHA-1 and SHA-256 updates across different refs
	rec := &journal.RefTransactionRecord{
		Version:  "v1",
		Stream:   "repo-mixed-oids",
		Seq:      0,
		Type:     journal.RecordTypeRefUpdate,
		Segments: []string{"4a49646b96dbca4f1eb8699ef7cefdcae68fefc6ee7ae6305a3f25c7e1ef5638"},
		Updates: []journal.RefUpdate{
			{
				Ref:    "refs/heads/main",
				OldOID: journal.ZeroOID40,
				NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
			},
			{
				Ref:    "refs/heads/feature",
				OldOID: journal.ZeroOID64,
				NewOID: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
		},
		Timestamp: "2026-08-31T12:00:00Z",
	}

	err := rec.Validate()
	if err == nil {
		t.Fatalf("expected error for mixed OID algorithms in single transaction, got nil")
	}
	if !errors.Is(err, journal.ErrInvalidRefTx) {
		t.Errorf("expected ErrInvalidRefTx, got %v", err)
	}
	if !strings.Contains(err.Error(), "mixed oid algorithms") {
		t.Errorf("expected error to contain 'mixed oid algorithms', got %q", err.Error())
	}
}

func TestSHA256RefTransactions(t *testing.T) {
	priv, pub := deterministicKeypair(0x01)
	formattedPub := journal.FormatPublicKey(pub)

	sha256OID1 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	sha256OID2 := "8a65c6d3715c0e1e92d6e3e5362e49c7198cfb608a65c6d3715c0e1e92d6e3e5"

	// 1. Initial push on SHA-256 repo
	rec0 := &journal.RefTransactionRecord{
		Version:  "v1",
		Stream:   "repo-sha256",
		Seq:      0,
		Type:     "ref_update",
		Segments: []string{"4a49646b96dbca4f1eb8699ef7cefdcae68fefc6ee7ae6305a3f25c7e1ef5638"},
		Updates: []journal.RefUpdate{
			{
				Ref:    "refs/heads/main",
				OldOID: journal.ZeroOID64,
				NewOID: sha256OID1,
			},
		},
		Timestamp: "2026-08-31T01:00:00Z",
	}

	if err := journal.SignRefTx(priv, rec0); err != nil {
		t.Fatalf("SignRefTx(SHA-256 seq 0) failed: %v", err)
	}
	if err := journal.VerifyRefTx(rec0, formattedPub); err != nil {
		t.Fatalf("VerifyRefTx(SHA-256 seq 0) failed: %v", err)
	}

	// 2. Multi-ref update on SHA-256 repo
	rec1 := &journal.RefTransactionRecord{
		Version:  "v1",
		Stream:   "repo-sha256",
		Seq:      1,
		Type:     "ref_update",
		Segments: []string{"4a49646b96dbca4f1eb8699ef7cefdcae68fefc6ee7ae6305a3f25c7e1ef5638"},
		Updates: []journal.RefUpdate{
			{
				Ref:    "refs/heads/main",
				OldOID: sha256OID1,
				NewOID: sha256OID2,
			},
			{
				Ref:    "refs/tags/v1.0",
				OldOID: journal.ZeroOID64,
				NewOID: sha256OID2,
			},
		},
		Timestamp: "2026-08-31T02:00:00Z",
	}

	if err := journal.SignRefTx(priv, rec1); err != nil {
		t.Fatalf("SignRefTx(SHA-256 seq 1) failed: %v", err)
	}
	if err := journal.VerifyRefTx(rec1, formattedPub); err != nil {
		t.Fatalf("VerifyRefTx(SHA-256 seq 1) failed: %v", err)
	}

	// 3. Deletion with zero segments on SHA-256 repo
	rec2 := &journal.RefTransactionRecord{
		Version:  "v1",
		Stream:   "repo-sha256",
		Seq:      2,
		Type:     "ref_update",
		Segments: []string{},
		Updates: []journal.RefUpdate{
			{
				Ref:    "refs/tags/v1.0",
				OldOID: sha256OID2,
				NewOID: journal.ZeroOID64,
			},
		},
		Timestamp: "2026-08-31T03:00:00Z",
	}

	if err := journal.SignRefTx(priv, rec2); err != nil {
		t.Fatalf("SignRefTx(SHA-256 seq 2) failed: %v", err)
	}
	if err := journal.VerifyRefTx(rec2, formattedPub); err != nil {
		t.Fatalf("VerifyRefTx(SHA-256 seq 2) failed: %v", err)
	}
}

func TestRefNameRawBytePreservationNonUTF8(t *testing.T) {
	// Ref names are arbitrary raw byte sequences (non-zero bytes not containing restricted chars)
	priv, pub := deterministicKeypair(0x01)
	formattedPub := journal.FormatPublicKey(pub)

	// High bytes (0x80..0xFF) that are valid raw bytes in git ref names
	rawBytesRef := "refs/heads/branch-\x80\x90\xa0\xb0\xc0\xd0\xe0\xf0"

	rec := &journal.RefTransactionRecord{
		Version:  "v1",
		Stream:   "repo-raw-bytes",
		Seq:      0,
		Type:     "ref_update",
		Segments: []string{"4a49646b96dbca4f1eb8699ef7cefdcae68fefc6ee7ae6305a3f25c7e1ef5638"},
		Updates: []journal.RefUpdate{
			{
				Ref:    rawBytesRef,
				OldOID: journal.ZeroOID40,
				NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
			},
		},
		Timestamp: "2026-08-31T12:00:00Z",
	}

	if err := journal.SignRefTx(priv, rec); err != nil {
		t.Fatalf("SignRefTx with raw bytes failed: %v", err)
	}
	if err := journal.VerifyRefTx(rec, formattedPub); err != nil {
		t.Fatalf("VerifyRefTx with raw bytes failed: %v", err)
	}

	// Verify CanonicalRefUpdatePayload contains the exact raw byte sequence
	payload := journal.CanonicalRefUpdatePayload(rec.Stream, rec.Seq, rec.KeyEpoch, rec.Timestamp, rec.Segments, rec.Updates)
	expectedSub := "update:" + rawBytesRef + " " + journal.ZeroOID40 + " 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n"
	if !strings.Contains(string(payload), expectedSub) {
		t.Fatalf("canonical payload did not preserve exact raw bytes:\npayload:\n%s\nexpected substring:\n%s", string(payload), expectedSub)
	}
}

// TestZeroValueSigningChainVerifyRefTx pins a regression: SigningChain was
// zero-value-safe before WALD-96, and the epoch-floor map it added
// (lastEpoch) must not break that. A chain built as `var c journal.SigningChain`
// and initialized by ApplyGenesis directly (bypassing NewSigningChain, the
// only place that used to allocate the map) must still verify a well-signed
// record instead of panicking with "assignment to entry in nil map".
func TestZeroValueSigningChainVerifyRefTx(t *testing.T) {
	priv, pub := deterministicKeypair(0x01)

	var chain journal.SigningChain
	genesis := &journal.GenesisRecord{
		Version:   "v1",
		Stream:    journal.MetaStreamID,
		Seq:       0,
		Type:      "genesis",
		PublicKey: journal.FormatPublicKey(pub),
		Timestamp: "2026-08-31T00:00:00Z",
	}
	if err := chain.ApplyGenesis(genesis); err != nil {
		t.Fatalf("ApplyGenesis failed: %v", err)
	}

	tx := &journal.RefTransactionRecord{
		Version: "v1",
		Stream:  "repo-alpha",
		Seq:     0,
		Type:    "ref_update",
		Updates: []journal.RefUpdate{
			{
				Ref:    "refs/heads/main",
				OldOID: journal.ZeroOID40,
				NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
			},
		},
		Timestamp: "2026-08-31T00:01:00Z",
	}
	if err := journal.SignRefTx(priv, tx); err != nil {
		t.Fatalf("SignRefTx failed: %v", err)
	}

	// Must not panic (previously: "assignment to entry in nil map").
	if err := chain.VerifyRefTx(tx); err != nil {
		t.Fatalf("zero-value SigningChain.VerifyRefTx failed: %v", err)
	}

	// A second record on the same stream exercises the read side of the
	// lazily-allocated map too.
	tx2 := *tx
	tx2.Seq = 1
	tx2.Timestamp = "2026-08-31T00:02:00Z"
	if err := journal.SignRefTx(priv, &tx2); err != nil {
		t.Fatalf("SignRefTx(tx2) failed: %v", err)
	}
	if err := chain.VerifyRefTx(&tx2); err != nil {
		t.Fatalf("zero-value SigningChain.VerifyRefTx(tx2) failed: %v", err)
	}
}

// TestNewRefTransactionRecordFixedFields pins that NewRefTransactionRecord
// sets version and type (spec section 5.1) in one place, exactly as
// NewGenesisRecord does for the genesis record, and threads every other
// field straight through unmodified.
func TestNewRefTransactionRecordFixedFields(t *testing.T) {
	segments := []string{"db89aeed94af475ae97ce5fe75618d404f017d23e0aa61ce1c7abd11707dbbab"}
	updates := []journal.RefUpdate{
		{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
	}

	rec := journal.NewRefTransactionRecord("repo-alpha", 3, 1, "2026-08-31T00:02:00Z", segments, updates)

	if rec.Version != journal.VersionPrefix {
		t.Errorf("Version = %q, want %q", rec.Version, journal.VersionPrefix)
	}
	if rec.Type != journal.RecordTypeRefUpdate {
		t.Errorf("Type = %q, want %q", rec.Type, journal.RecordTypeRefUpdate)
	}
	if rec.Stream != "repo-alpha" {
		t.Errorf("Stream = %q, want %q", rec.Stream, "repo-alpha")
	}
	if rec.Seq != 3 {
		t.Errorf("Seq = %d, want 3", rec.Seq)
	}
	if rec.KeyEpoch != 1 {
		t.Errorf("KeyEpoch = %d, want 1", rec.KeyEpoch)
	}
	if rec.Timestamp != "2026-08-31T00:02:00Z" {
		t.Errorf("Timestamp = %q, want %q", rec.Timestamp, "2026-08-31T00:02:00Z")
	}
	if !reflect.DeepEqual(rec.Segments, segments) {
		t.Errorf("Segments = %v, want %v", rec.Segments, segments)
	}
	if !reflect.DeepEqual(rec.Updates, updates) {
		t.Errorf("Updates = %v, want %v", rec.Updates, updates)
	}
	if rec.Signature != "" {
		t.Errorf("Signature = %q, want empty (unsigned)", rec.Signature)
	}
}

// TestMarshalRefTxFixtureByteEquality is change 4's "real proof" for
// internal/journal/reftx.go: every ref-transaction record in the golden
// journal (spec/journal/v1/fixtures), on both repo-alpha and the opaque
// stream, is rebuilt through NewRefTransactionRecord from the fixture's own
// decoded field values and signature, and MarshalRefTx's output is asserted
// byte-for-byte equal to the committed fixture file. A pass here means
// production code — not just the fixture generator's own writeJSON — can
// reproduce the published golden records exactly.
func TestMarshalRefTxFixtureByteEquality(t *testing.T) {
	for _, stream := range []journal.StreamID{fixtureRepoStream, fixtureOpaqueStream} {
		for _, rec := range fixtureStreamRecords(t, stream) {
			rebuilt := journal.NewRefTransactionRecord(rec.Stream, rec.Seq, rec.KeyEpoch, rec.Timestamp, rec.Segments, rec.Updates)
			rebuilt.Signature = rec.Signature

			got, err := journal.MarshalRefTx(rebuilt)
			if err != nil {
				t.Fatalf("MarshalRefTx(%s seq %d): %v", stream, rec.Seq, err)
			}

			want, err := os.ReadFile(fixtureKeyPath(journal.TxKey(stream, rec.Seq)))
			if err != nil {
				t.Fatalf("reading golden fixture for %s seq %d: %v", stream, rec.Seq, err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("MarshalRefTx(%s seq %d) does not reproduce the golden fixture byte-for-byte\ngot:\n%s\nwant:\n%s", stream, rec.Seq, got, want)
			}
		}
	}
}

// TestMarshalRefTxEmptySegmentsMarshalAsEmptyArray pins that a record with
// no segments marshals "segments": [] rather than omitting the field or
// emitting null — Validate already normalizes a nil Segments to []string{}
// (reftx.go), and MarshalRefTx must not add omitempty and undo that. This
// is also exercised end to end by repo-alpha seq 2 in the byte-equality
// test above; this test isolates the claim against a record built fresh,
// with nil Segments, rather than one read back off disk.
func TestMarshalRefTxEmptySegmentsMarshalAsEmptyArray(t *testing.T) {
	priv, _ := deterministicKeypair(0x01)
	rec := journal.NewRefTransactionRecord("repo-alpha", 0, 0, "2026-08-31T00:00:00Z", nil, []journal.RefUpdate{
		{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
	})
	if err := journal.SignRefTx(priv, rec); err != nil {
		t.Fatalf("SignRefTx: %v", err)
	}

	data, err := journal.MarshalRefTx(rec)
	if err != nil {
		t.Fatalf("MarshalRefTx: %v", err)
	}
	if !strings.Contains(string(data), `"segments": []`) {
		t.Errorf("MarshalRefTx with nil segments = %s, want it to contain \"segments\": []", data)
	}
}

// TestMarshalRefTxLowercasesWithoutMutatingCaller pins the two halves of
// change 1's lowercasing requirement together: uppercase-hex segments and
// OIDs marshal lowercase (spec section 5.1), and MarshalRefTx does this in
// a copy, never touching the caller's own Segments/Updates slices in
// place. NewRefTransactionRecord assigns the caller's slices straight
// through with no copy of its own, so this is the one place the mutation
// could leak from if MarshalRefTx got the copy wrong.
func TestMarshalRefTxLowercasesWithoutMutatingCaller(t *testing.T) {
	priv, _ := deterministicKeypair(0x01)

	segments := []string{"DB89AEED94AF475AE97CE5FE75618D404F017D23E0AA61CE1C7ABD11707DBBAB"}
	updates := []journal.RefUpdate{
		{Ref: "refs/heads/main", OldOID: strings.ToUpper(journal.ZeroOID40), NewOID: "4B825DC642CB6EB9A060E54BF8D69288FBEE4904"},
	}
	wantSegments := append([]string(nil), segments...)
	wantUpdates := append([]journal.RefUpdate(nil), updates...)

	rec := journal.NewRefTransactionRecord("repo-alpha", 0, 0, "2026-08-31T00:00:00Z", segments, updates)
	if err := journal.SignRefTx(priv, rec); err != nil {
		t.Fatalf("SignRefTx: %v", err)
	}

	data, err := journal.MarshalRefTx(rec)
	if err != nil {
		t.Fatalf("MarshalRefTx: %v", err)
	}
	if strings.Contains(string(data), "DB89AEED") || strings.Contains(string(data), "4B825DC6") {
		t.Errorf("MarshalRefTx did not lowercase hex: %s", data)
	}
	if !strings.Contains(string(data), "db89aeed") || !strings.Contains(string(data), "4b825dc6") {
		t.Errorf("MarshalRefTx did not emit the expected lowercase hex: %s", data)
	}

	if !reflect.DeepEqual(segments, wantSegments) {
		t.Errorf("MarshalRefTx mutated the caller's segments slice: got %v, want %v", segments, wantSegments)
	}
	if !reflect.DeepEqual(updates, wantUpdates) {
		t.Errorf("MarshalRefTx mutated the caller's updates slice: got %v, want %v", updates, wantUpdates)
	}
}

// TestMarshalRefTxRefusals covers MarshalRefTx's refusals: a nil record, an
// invalid one (Validate fails), an unsigned one (empty signature), and one
// carrying a signature ParseSignature rejects. Every refusal is asserted to
// be exactly one line, per AGENTS.md's mechanical review rule that every
// operator-facing refusal is one line.
func TestMarshalRefTxRefusals(t *testing.T) {
	validRec := func() *journal.RefTransactionRecord {
		return journal.NewRefTransactionRecord("repo-alpha", 0, 0, "2026-08-31T00:00:00Z",
			[]string{"db89aeed94af475ae97ce5fe75618d404f017d23e0aa61ce1c7abd11707dbbab"},
			[]journal.RefUpdate{{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"}},
		)
	}

	assertOneLine := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if strings.Count(err.Error(), "\n") != 0 {
			t.Errorf("refusal is not one line: %q", err.Error())
		}
	}

	t.Run("nil record", func(t *testing.T) {
		_, err := journal.MarshalRefTx(nil)
		if !errors.Is(err, journal.ErrInvalidRefTx) {
			t.Fatalf("expected ErrInvalidRefTx, got %v", err)
		}
		assertOneLine(t, err)
	})

	t.Run("invalid record", func(t *testing.T) {
		rec := validRec()
		rec.Type = "not-ref-update"
		_, err := journal.MarshalRefTx(rec)
		if !errors.Is(err, journal.ErrInvalidRefTx) {
			t.Fatalf("expected ErrInvalidRefTx, got %v", err)
		}
		assertOneLine(t, err)
	})

	t.Run("empty signature", func(t *testing.T) {
		rec := validRec()
		_, err := journal.MarshalRefTx(rec)
		if !errors.Is(err, journal.ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature, got %v", err)
		}
		assertOneLine(t, err)
	})

	t.Run("malformed signature", func(t *testing.T) {
		rec := validRec()
		rec.Signature = "not-a-signature"
		_, err := journal.MarshalRefTx(rec)
		if !errors.Is(err, journal.ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature, got %v", err)
		}
		assertOneLine(t, err)
	})
}

// TestMarshalRefTxRefusesNonUTF8RefName is WALD-27 round 3's finding, made
// permanent: a ref name git and journal.ValidateRefName both accept but
// that is not valid UTF-8 (Latin-1 "café", the reviewer's own example) must
// never reach json.MarshalIndent, which silently replaces such bytes with
// U+FFFD rather than erroring — producing a record whose signature, computed
// over the raw bytes via CanonicalRefUpdatePayload, can never verify again
// (spec section 5.2; spec section 8.1 rule 3 aborts replay of the whole
// stream on exactly that).
//
// ValidateRefName and SignRefTx still accept this ref name — they operate
// on raw bytes, never JSON, and TestRefNameRawBytePreservationNonUTF8 above
// pins that this is deliberate, not an oversight this test contradicts.
// v1's on-disk record format is JSON (section 5.1), so that is where the
// two representations diverge, and MarshalRefTx is where this refuses.
func TestMarshalRefTxRefusesNonUTF8RefName(t *testing.T) {
	priv, _ := deterministicKeypair(0x01)

	// "café" encoded as Latin-1 rather than UTF-8: 'c', 'a', 'f', 0xE9. Legal
	// per git-check-ref-format (no control character, no reserved byte), so
	// ValidateRefName accepts it — but a lone 0xE9 is not a valid UTF-8 byte
	// sequence.
	nonUTF8Ref := "refs/heads/caf\xe9"
	if utf8.ValidString(nonUTF8Ref) {
		t.Fatalf("test fixture %q is valid UTF-8; this test needs a byte sequence that genuinely is not", nonUTF8Ref)
	}
	if err := journal.ValidateRefName(nonUTF8Ref); err != nil {
		t.Fatalf("ValidateRefName(%q) = %v, want nil: this ref name is legal per git-check-ref-format", nonUTF8Ref, err)
	}

	rec := journal.NewRefTransactionRecord("repo-alpha", 0, 0, "2026-08-31T00:00:00Z", nil, []journal.RefUpdate{
		{Ref: nonUTF8Ref, OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
	})
	if err := journal.SignRefTx(priv, rec); err != nil {
		t.Fatalf("SignRefTx(%q) = %v, want nil: CanonicalRefUpdatePayload is a raw byte stream, not JSON, so it preserves this ref name exactly", nonUTF8Ref, err)
	}

	_, err := journal.MarshalRefTx(rec)
	if err == nil {
		t.Fatal("MarshalRefTx succeeded on a non-UTF-8 ref name; it must refuse rather than silently write a record that can never verify again")
	}
	if !errors.Is(err, journal.ErrInvalidRefTx) {
		t.Errorf("errors.Is(_, journal.ErrInvalidRefTx) = false, err = %v", err)
	}
	if !errors.Is(err, journal.ErrInvalidRef) {
		t.Errorf("errors.Is(_, journal.ErrInvalidRef) = false, err = %v", err)
	}
	if strings.Count(err.Error(), "\n") != 0 {
		t.Errorf("refusal is not one line: %q", err.Error())
	}
}

// WALD-34: ParseRefTx and RefuseRefTxSignatureMismatch — the read side of
// the ref-transaction record, in the style of ParseMarker/ParseTokenCreate.

// TestParseRefTx covers the round trip: a record built, signed, and
// marshaled through MarshalRefTx parses back through ParseRefTx to an
// identical record.
func TestParseRefTx(t *testing.T) {
	priv, _ := deterministicKeypair(0x05)

	rec := journal.NewRefTransactionRecord("repo-alpha", 3, 1, "2026-08-31T00:02:00Z",
		[]string{"4a49646b96dbca4f1eb8699ef7cefdcae68fefc6ee7ae6305a3f25c7e1ef5638"},
		[]journal.RefUpdate{
			{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
		},
	)
	if err := journal.SignRefTx(priv, rec); err != nil {
		t.Fatalf("SignRefTx failed: %v", err)
	}
	data, err := journal.MarshalRefTx(rec)
	if err != nil {
		t.Fatalf("MarshalRefTx failed: %v", err)
	}

	parsed, err := journal.ParseRefTx(data)
	if err != nil {
		t.Fatalf("ParseRefTx failed: %v", err)
	}
	if !reflect.DeepEqual(*parsed, *rec) {
		t.Errorf("ParseRefTx round trip mismatch:\ngot:  %+v\nwant: %+v", *parsed, *rec)
	}
}

// TestParseRefTxEmptyData covers the same "nothing to parse" guard
// ParseMarker and ParseGenesis apply to their own empty-input case.
func TestParseRefTxEmptyData(t *testing.T) {
	_, err := journal.ParseRefTx(nil)
	if err == nil {
		t.Fatal("expected an error for empty ref transaction data, got nil")
	}
	if !errors.Is(err, journal.ErrInvalidRefTx) {
		t.Errorf("errors.Is(_, journal.ErrInvalidRefTx) = false, err = %v", err)
	}
}

// TestParseRefTxCorruptJSON covers malformed JSON bytes, distinct from a
// well-formed document missing a required field.
func TestParseRefTxCorruptJSON(t *testing.T) {
	_, err := journal.ParseRefTx([]byte("{not json"))
	if err == nil {
		t.Fatal("expected an error for corrupt JSON, got nil")
	}
	if !errors.Is(err, journal.ErrInvalidRefTx) {
		t.Errorf("errors.Is(_, journal.ErrInvalidRefTx) = false, err = %v", err)
	}
}

// TestParseRefTxMissingFields covers every field ParseRefTx requires to be
// present, styled on TestParseMarkerMissingFields: each one, removed alone
// from an otherwise-complete document, is refused by name; the complete
// document is the control that proves each failure comes from the field
// actually being absent.
func TestParseRefTxMissingFields(t *testing.T) {
	priv, _ := deterministicKeypair(0x06)
	rec := journal.NewRefTransactionRecord("repo-alpha", 0, 0, "2026-08-31T00:02:00Z", nil,
		[]journal.RefUpdate{
			{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
		},
	)
	if err := journal.SignRefTx(priv, rec); err != nil {
		t.Fatalf("SignRefTx failed: %v", err)
	}
	data, err := journal.MarshalRefTx(rec)
	if err != nil {
		t.Fatalf("MarshalRefTx failed: %v", err)
	}

	var complete map[string]any
	if err := json.Unmarshal(data, &complete); err != nil {
		t.Fatalf("failed to unmarshal the marshaled record into a map: %v", err)
	}

	for _, field := range []string{"version", "stream", "seq", "type", "timestamp", "signature"} {
		t.Run("missing "+field, func(t *testing.T) {
			doc := make(map[string]any, len(complete))
			for k, v := range complete {
				if k == field {
					continue
				}
				doc[k] = v
			}
			docData, err := json.Marshal(doc)
			if err != nil {
				t.Fatalf("failed to marshal test document: %v", err)
			}
			_, err = journal.ParseRefTx(docData)
			if err == nil {
				t.Fatalf("expected error for a ref transaction missing %q, got nil", field)
			}
			if !errors.Is(err, journal.ErrInvalidRefTx) {
				t.Errorf("expected ErrInvalidRefTx for missing %q, got %v", field, err)
			}
			if !strings.Contains(err.Error(), field) {
				t.Errorf("expected error naming the missing field %q, got %q", field, err.Error())
			}
		})
	}

	// The complete document, unmodified, must parse.
	if _, err := journal.ParseRefTx(data); err != nil {
		t.Fatalf("ParseRefTx failed on a complete document: %v", err)
	}
}

// TestParseRefTxKeyEpochAbsentDefaultsToZero pins spec section 5.1's own
// words: "A record with no key_epoch at all is read as epoch 0,
// identically to an explicit 'key_epoch': '0'." Unlike every other field
// ParseRefTx requires, an absent key_epoch is not a parse failure —
// segments and updates default the same way TestParseRefTxSegmentsAndUpdatesOptional
// below pins.
func TestParseRefTxKeyEpochAbsentDefaultsToZero(t *testing.T) {
	raw := `{
		"version": "v1",
		"stream": "repo-alpha",
		"seq": "0",
		"type": "ref_update",
		"segments": [],
		"updates": [{"ref": "refs/heads/main", "old_oid": "` + journal.ZeroOID40 + `", "new_oid": "4b825dc642cb6eb9a060e54bf8d69288fbee4904"}],
		"timestamp": "2026-08-31T00:02:00Z",
		"signature": "ed25519:e3663b676f671095e4b8653ddc1419b2349d39a8adab7f28b1cb6574bc62963ec2f03996af92d34d6e2fab685c365a180d411053af476d4b319fe6a9359a8805"
	}`

	rec, err := journal.ParseRefTx([]byte(raw))
	if err != nil {
		t.Fatalf("ParseRefTx failed on a record with no key_epoch field: %v", err)
	}
	if rec.KeyEpoch != 0 {
		t.Errorf("KeyEpoch = %d, want 0 for an absent key_epoch field", rec.KeyEpoch)
	}
}

// TestParseRefTxSegmentsAndUpdatesOptional covers the two fields whose
// absence Validate() already turns into either the empty slice (Segments)
// or a refusal with its own established wording (Updates) — ParseRefTx
// adds no separate presence check for either, since doing so would only
// duplicate what Validate does.
func TestParseRefTxSegmentsAndUpdatesOptional(t *testing.T) {
	t.Run("segments absent defaults to empty", func(t *testing.T) {
		raw := `{
			"version": "v1",
			"stream": "repo-alpha",
			"seq": "0",
			"type": "ref_update",
			"key_epoch": "0",
			"updates": [{"ref": "refs/heads/main", "old_oid": "` + journal.ZeroOID40 + `", "new_oid": "4b825dc642cb6eb9a060e54bf8d69288fbee4904"}],
			"timestamp": "2026-08-31T00:02:00Z",
			"signature": "ed25519:e3663b676f671095e4b8653ddc1419b2349d39a8adab7f28b1cb6574bc62963ec2f03996af92d34d6e2fab685c365a180d411053af476d4b319fe6a9359a8805"
		}`
		rec, err := journal.ParseRefTx([]byte(raw))
		if err != nil {
			t.Fatalf("ParseRefTx failed on a record with no segments field: %v", err)
		}
		if rec.Segments == nil || len(rec.Segments) != 0 {
			t.Errorf("Segments = %+v, want a non-nil empty slice", rec.Segments)
		}
	})

	t.Run("updates absent is refused, not defaulted", func(t *testing.T) {
		raw := `{
			"version": "v1",
			"stream": "repo-alpha",
			"seq": "0",
			"type": "ref_update",
			"key_epoch": "0",
			"segments": [],
			"timestamp": "2026-08-31T00:02:00Z",
			"signature": "ed25519:e3663b676f671095e4b8653ddc1419b2349d39a8adab7f28b1cb6574bc62963ec2f03996af92d34d6e2fab685c365a180d411053af476d4b319fe6a9359a8805"
		}`
		_, err := journal.ParseRefTx([]byte(raw))
		if !errors.Is(err, journal.ErrInvalidRefTx) {
			t.Errorf("errors.Is(_, journal.ErrInvalidRefTx) = false, err = %v", err)
		}
	})
}

// TestParseRefTxUnknownFieldsIgnored covers spec section 5.4: readers
// ignore unrecognized JSON object keys.
func TestParseRefTxUnknownFieldsIgnored(t *testing.T) {
	priv, pub := deterministicKeypair(0x07)
	formattedPub := journal.FormatPublicKey(pub)
	rec := journal.NewRefTransactionRecord("repo-alpha", 0, 0, "2026-08-31T00:02:00Z", nil,
		[]journal.RefUpdate{
			{Ref: "refs/heads/main", OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
		},
	)
	if err := journal.SignRefTx(priv, rec); err != nil {
		t.Fatalf("SignRefTx failed: %v", err)
	}

	raw := `{
		"version": "v1",
		"stream": "repo-alpha",
		"seq": "0",
		"type": "ref_update",
		"key_epoch": "0",
		"segments": [],
		"updates": [{"ref": "refs/heads/main", "old_oid": "` + journal.ZeroOID40 + `", "new_oid": "4b825dc642cb6eb9a060e54bf8d69288fbee4904", "extra": "ignored"}],
		"timestamp": "2026-08-31T00:02:00Z",
		"signature": "` + rec.Signature + `",
		"future_field": "ignored too"
	}`

	parsed, err := journal.ParseRefTx([]byte(raw))
	if err != nil {
		t.Fatalf("ParseRefTx failed on a record with unknown fields: %v", err)
	}
	if err := journal.VerifyRefTx(parsed, formattedPub); err != nil {
		t.Errorf("VerifyRefTx failed on a record round-tripped through unknown fields: %v", err)
	}
}

// TestParseRefTxNonUTF8RefNameFailsClosedOnVerify answers the question
// WALD-27 left open for this ticket: what should ParseRefTx do with a ref
// name that is not valid UTF-8?
//
// MarshalRefTx already refuses to write one (TestMarshalRefTxRefusesNonUTF8RefName),
// because JSON cannot carry arbitrary bytes losslessly — encoding/json
// substitutes U+FFFD for an invalid byte sequence instead of erroring, on
// both encode and decode. That guard is the only thing keeping such a
// record out of the journal in the first place, so a record like this can
// only exist if something other than this package's own writer put it
// there. When it does, ParseRefTx has no way to recover the original
// bytes either: it decodes through the same encoding/json, which performs
// the identical substitution going in. The record does not come back
// looking valid with a corrupted ref name — the substitution changes the
// bytes CanonicalRefUpdatePayload is computed over, so the signature that
// was computed over the real bytes no longer matches, and
// chain.VerifyRefTx refuses it as an ordinary signature mismatch (rule
// 3). No separate check is added to ParseRefTx for this case: the
// existing signature check already closes it. See WALD-119 for the
// analogous, still-open gap in MarshalMarker.
func TestParseRefTxNonUTF8RefNameFailsClosedOnVerify(t *testing.T) {
	priv, pub := deterministicKeypair(0x08)
	formattedPub := journal.FormatPublicKey(pub)

	// "café" encoded as Latin-1 rather than UTF-8, as in
	// TestMarshalRefTxRefusesNonUTF8RefName: legal per
	// git-check-ref-format, but not valid UTF-8.
	nonUTF8Ref := "refs/heads/caf\xe9"
	if utf8.ValidString(nonUTF8Ref) {
		t.Fatalf("test fixture %q is valid UTF-8; this test needs a byte sequence that genuinely is not", nonUTF8Ref)
	}

	rec := journal.NewRefTransactionRecord("repo-alpha", 0, 0, "2026-08-31T00:00:00Z", nil,
		[]journal.RefUpdate{
			{Ref: nonUTF8Ref, OldOID: journal.ZeroOID40, NewOID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
		},
	)
	if err := journal.SignRefTx(priv, rec); err != nil {
		t.Fatalf("SignRefTx failed: %v", err)
	}

	// Hand-built JSON carrying the exact raw bytes, standing in for a
	// record written by something other than MarshalRefTx: string
	// concatenation, not json.Marshal, which would perform the same
	// U+FFFD substitution on the way out that this test needs ParseRefTx
	// to perform on the way in.
	raw := []byte(`{
		"version": "v1",
		"stream": "repo-alpha",
		"seq": "0",
		"type": "ref_update",
		"key_epoch": "0",
		"segments": [],
		"updates": [{"ref": "` + nonUTF8Ref + `", "old_oid": "` + journal.ZeroOID40 + `", "new_oid": "4b825dc642cb6eb9a060e54bf8d69288fbee4904"}],
		"timestamp": "2026-08-31T00:00:00Z",
		"signature": "` + rec.Signature + `"
	}`)

	parsed, err := journal.ParseRefTx(raw)
	if err != nil {
		t.Fatalf("ParseRefTx failed: %v", err)
	}
	if parsed.Updates[0].Ref == nonUTF8Ref {
		t.Fatalf("test fixture did not exercise JSON's own U+FFFD substitution; got back the exact non-UTF-8 bytes")
	}

	err = journal.VerifyRefTx(parsed, formattedPub)
	if !errors.Is(err, journal.ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch once JSON has mangled the non-UTF-8 ref name, got %v", err)
	}
}

// TestRefuseRefTxSignatureMismatch pins section 8.1 rule 3's exact wording.
func TestRefuseRefTxSignatureMismatch(t *testing.T) {
	err := journal.RefuseRefTxSignatureMismatch("repo-alpha", 4)
	if !errors.Is(err, journal.ErrSignatureMismatch) {
		t.Errorf("errors.Is(_, journal.ErrSignatureMismatch) = false, err = %v", err)
	}
	want := "refusal: replay failed: signature mismatch for ref update on stream repo-alpha at seq 4"
	if err.Error() != want {
		t.Errorf("RefuseRefTxSignatureMismatch = %q, want %q", err.Error(), want)
	}
	if strings.Count(err.Error(), "\n") != 0 {
		t.Errorf("refusal is not one line: %q", err.Error())
	}
}
