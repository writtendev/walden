package journal_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/journal"
)

func deterministicKeypair(seedByte byte) (ed25519.PrivateKey, ed25519.PublicKey) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = seedByte
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub
}

func TestGenerateAndFormatKeypair(t *testing.T) {
	priv, pub, err := journal.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	formattedPub := journal.FormatPublicKey(pub)
	if !strings.HasPrefix(formattedPub, "ed25519:") {
		t.Errorf("expected ed25519: prefix, got %q", formattedPub)
	}
	if len(formattedPub) != len("ed25519:")+64 {
		t.Errorf("expected 72 chars total, got %d (%q)", len(formattedPub), formattedPub)
	}

	parsedPub, err := journal.ParsePublicKey(formattedPub)
	if err != nil {
		t.Fatalf("ParsePublicKey failed: %v", err)
	}
	if !pub.Equal(parsedPub) {
		t.Errorf("parsed public key does not match generated public key")
	}

	// Test signing with generated key
	msg := []byte("hello walden")
	sig := ed25519.Sign(priv, msg)
	formattedSig := journal.FormatSignature(sig)
	if !strings.HasPrefix(formattedSig, "ed25519:") {
		t.Errorf("expected ed25519: signature prefix, got %q", formattedSig)
	}
	if len(formattedSig) != len("ed25519:")+128 {
		t.Errorf("expected 136 chars total for signature, got %d", len(formattedSig))
	}

	parsedSig, err := journal.ParseSignature(formattedSig)
	if err != nil {
		t.Fatalf("ParseSignature failed: %v", err)
	}
	if !ed25519.Verify(parsedPub, msg, parsedSig) {
		t.Errorf("signature verification failed")
	}
}

func TestParsePublicKeyErrors(t *testing.T) {
	invalid := []struct {
		key string
		err string
	}{
		{"", "missing prefix"},
		{"ssh-rsa:1234", "missing prefix"},
		{"ed25519:", "public key hex must be 64 characters"},
		{"ed25519:1234abcd", "public key hex must be 64 characters"},
		{"ed25519:" + strings.Repeat("0", 63), "public key hex must be 64 characters"},
		{"ed25519:" + strings.Repeat("0", 65), "public key hex must be 64 characters"},
		{"ed25519:" + strings.Repeat("g", 64), "hex decode error"},
	}

	for _, tc := range invalid {
		_, err := journal.ParsePublicKey(tc.key)
		if err == nil {
			t.Errorf("expected error for public key %q, got nil", tc.key)
			continue
		}
		if !errors.Is(err, journal.ErrInvalidKey) {
			t.Errorf("expected ErrInvalidKey for %q, got %v", tc.key, err)
		}
		if !strings.Contains(err.Error(), tc.err) {
			t.Errorf("expected error containing %q, got %q", tc.err, err.Error())
		}
	}
}

func TestParseSignatureErrors(t *testing.T) {
	invalid := []struct {
		sig string
		err string
	}{
		{"", "missing prefix"},
		{"rsa:1234", "missing prefix"},
		{"ed25519:", "signature hex must be 128 characters"},
		{"ed25519:" + strings.Repeat("0", 127), "signature hex must be 128 characters"},
		{"ed25519:" + strings.Repeat("0", 129), "signature hex must be 128 characters"},
		{"ed25519:" + strings.Repeat("z", 128), "hex decode error"},
	}

	for _, tc := range invalid {
		_, err := journal.ParseSignature(tc.sig)
		if err == nil {
			t.Errorf("expected error for signature %q, got nil", tc.sig)
			continue
		}
		if !errors.Is(err, journal.ErrInvalidSignature) {
			t.Errorf("expected ErrInvalidSignature for %q, got %v", tc.sig, err)
		}
		if !strings.Contains(err.Error(), tc.err) {
			t.Errorf("expected error containing %q, got %q", tc.err, err.Error())
		}
	}
}

func TestSigningChainGenesisAndRotation(t *testing.T) {
	priv1, pub1 := deterministicKeypair(0x01)
	priv2, pub2 := deterministicKeypair(0x02)
	_, pub3 := deterministicKeypair(0x03)

	chain := journal.NewSigningChain()
	if chain.IsInitialized() {
		t.Errorf("expected chain to not be initialized initially")
	}

	// Applying rotation before genesis must fail
	rotRecord := &journal.KeyRotationRecord{
		Version:      "v1",
		Stream:       journal.MetaStreamID,
		Seq:          1,
		Type:         "key_rotation",
		OldPublicKey: journal.FormatPublicKey(pub1),
		NewPublicKey: journal.FormatPublicKey(pub2),
		Timestamp:    "2026-08-31T01:00:00Z",
	}
	if err := chain.ApplyRotation(rotRecord); !errors.Is(err, journal.ErrGenesisMissing) {
		t.Errorf("expected ErrGenesisMissing, got %v", err)
	}

	// Apply genesis
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
	if !chain.IsInitialized() {
		t.Errorf("expected chain to be initialized")
	}
	if chain.ActiveKey() != journal.FormatPublicKey(pub1) {
		t.Errorf("expected active key %q, got %q", journal.FormatPublicKey(pub1), chain.ActiveKey())
	}
	if chain.LastMetaSeq() != 0 {
		t.Errorf("expected last meta seq 0, got %d", chain.LastMetaSeq())
	}

	// Applying genesis twice must fail
	if err := chain.ApplyGenesis(genesis); !errors.Is(err, journal.ErrInvalidGenesis) {
		t.Errorf("expected ErrInvalidGenesis on duplicate genesis, got %v", err)
	}

	// Advance meta sequence for an intermediate record (e.g. token_create at seq 1)
	if err := chain.AdvanceMetaSeq(1); err != nil {
		t.Fatalf("AdvanceMetaSeq(1) failed: %v", err)
	}
	if chain.LastMetaSeq() != 1 {
		t.Errorf("expected last meta seq 1, got %d", chain.LastMetaSeq())
	}

	// Rotate from key1 to key2 at seq 2
	rot1 := &journal.KeyRotationRecord{
		Version:      "v1",
		Stream:       journal.MetaStreamID,
		Seq:          2,
		Type:         "key_rotation",
		OldPublicKey: journal.FormatPublicKey(pub1),
		NewPublicKey: journal.FormatPublicKey(pub2),
		Timestamp:    "2026-08-31T02:00:00Z",
	}

	if err := journal.SignRotation(priv1, rot1); err != nil {
		t.Fatalf("SignRotation failed: %v", err)
	}

	if err := chain.ApplyRotation(rot1); err != nil {
		t.Fatalf("ApplyRotation failed: %v", err)
	}
	if chain.ActiveKey() != journal.FormatPublicKey(pub2) {
		t.Errorf("expected active key %q after rotation, got %q", journal.FormatPublicKey(pub2), chain.ActiveKey())
	}
	if chain.LastMetaSeq() != 2 {
		t.Errorf("expected last meta seq 2, got %d", chain.LastMetaSeq())
	}

	// Rotate from key2 to key3 at seq 3
	rot2 := &journal.KeyRotationRecord{
		Version:      "v1",
		Stream:       journal.MetaStreamID,
		Seq:          3,
		Type:         "key_rotation",
		OldPublicKey: journal.FormatPublicKey(pub2),
		NewPublicKey: journal.FormatPublicKey(pub3),
		Timestamp:    "2026-08-31T03:00:00Z",
	}
	if err := journal.SignRotation(priv2, rot2); err != nil {
		t.Fatalf("SignRotation (2->3) failed: %v", err)
	}
	if err := chain.ApplyRotation(rot2); err != nil {
		t.Fatalf("ApplyRotation (2->3) failed: %v", err)
	}
	if chain.ActiveKey() != journal.FormatPublicKey(pub3) {
		t.Errorf("expected active key %q after second rotation, got %q", journal.FormatPublicKey(pub3), chain.ActiveKey())
	}
}

func TestUnchainableRotationErrors(t *testing.T) {
	_, pub1 := deterministicKeypair(0x01)
	priv2, pub2 := deterministicKeypair(0x02)
	_, pub3 := deterministicKeypair(0x03)

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

	// 1. Old public key mismatch (unchainable rotation)
	rotUnchainable := &journal.KeyRotationRecord{
		Version:      "v1",
		Stream:       journal.MetaStreamID,
		Seq:          1,
		Type:         "key_rotation",
		OldPublicKey: journal.FormatPublicKey(pub2), // Should be pub1
		NewPublicKey: journal.FormatPublicKey(pub3),
		Timestamp:    "2026-08-31T01:00:00Z",
	}
	_ = journal.SignRotation(priv2, rotUnchainable)

	err := chain.ApplyRotation(rotUnchainable)
	if !errors.Is(err, journal.ErrUnchainableRotation) {
		t.Errorf("expected ErrUnchainableRotation, got %v", err)
	}

	// 2. Tampered signature on valid chain
	rotBadSig := &journal.KeyRotationRecord{
		Version:      "v1",
		Stream:       journal.MetaStreamID,
		Seq:          1,
		Type:         "key_rotation",
		OldPublicKey: journal.FormatPublicKey(pub1),
		NewPublicKey: journal.FormatPublicKey(pub2),
		Timestamp:    "2026-08-31T01:00:00Z",
		Signature:    "ed25519:" + strings.Repeat("0", 128), // bogus sig
	}
	err = chain.ApplyRotation(rotBadSig)
	if !errors.Is(err, journal.ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch, got %v", err)
	}

	// 3. Sequence gap
	rotSeqGap := &journal.KeyRotationRecord{
		Version:      "v1",
		Stream:       journal.MetaStreamID,
		Seq:          5, // expected 1
		Type:         "key_rotation",
		OldPublicKey: journal.FormatPublicKey(pub1),
		NewPublicKey: journal.FormatPublicKey(pub2),
		Timestamp:    "2026-08-31T01:00:00Z",
	}
	err = chain.ApplyRotation(rotSeqGap)
	if !errors.Is(err, journal.ErrInvalidRotation) {
		t.Errorf("expected ErrInvalidRotation for seq gap, got %v", err)
	}

	// 4. Same key rotation
	rotSameKey := &journal.KeyRotationRecord{
		Version:      "v1",
		Stream:       journal.MetaStreamID,
		Seq:          1,
		Type:         "key_rotation",
		OldPublicKey: journal.FormatPublicKey(pub1),
		NewPublicKey: journal.FormatPublicKey(pub1), // identical
		Timestamp:    "2026-08-31T01:00:00Z",
	}
	err = chain.ApplyRotation(rotSameKey)
	if !errors.Is(err, journal.ErrInvalidRotation) {
		t.Errorf("expected ErrInvalidRotation for same key rotation, got %v", err)
	}
}

func TestCanonicalRotationPayloadDeterministic(t *testing.T) {
	stream := journal.StreamID("_meta")
	seq := uint64(1)
	oldKey := "ed25519:" + hex.EncodeToString(make([]byte, 32))
	newKey := "ed25519:" + hex.EncodeToString(make([]byte, 32))
	timestamp := "2026-08-31T00:00:00Z"

	p1 := journal.CanonicalRotationPayload(stream, seq, oldKey, newKey, timestamp)
	p2 := journal.CanonicalRotationPayload(stream, seq, oldKey, newKey, timestamp)

	if string(p1) != string(p2) {
		t.Errorf("expected deterministic canonical rotation payload")
	}

	expected := "walden-key-rotation:v1\nstream:_meta\nseq:1\nold_public_key:" + oldKey + "\nnew_public_key:" + newKey + "\ntimestamp:2026-08-31T00:00:00Z\n"
	if string(p1) != expected {
		t.Errorf("payload mismatch:\ngot:  %q\nwant: %q", string(p1), expected)
	}
}
