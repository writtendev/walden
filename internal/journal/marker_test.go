package journal_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/writtendev/walden/internal/journal"
	"github.com/writtendev/walden/internal/refusal"
)

func TestParseMarkerValid(t *testing.T) {
	raw := `{
		"version": "v1",
		"stream": "repo-beta",
		"sequence": "42",
		"key_epoch": "2",
		"key_epoch_floor": "1",
		"snapshot": "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db",
		"refs": [
			{"ref": "refs/heads/main", "oid": "4b825dc642cb6eb9a060e54bf8d69288fbee4904"}
		],
		"timestamp": "2026-08-31T01:00:00Z",
		"signature": "ed25519:e3663b676f671095e4b8653ddc1419b2349d39a8adab7f28b1cb6574bc62963ec2f03996af92d34d6e2fab685c365a180d411053af476d4b319fe6a9359a8805"
	}`

	m, err := journal.ParseMarker([]byte(raw))
	if err != nil {
		t.Fatalf("ParseMarker failed: %v", err)
	}

	if m.Version != "v1" {
		t.Errorf("Version = %q, want %q", m.Version, "v1")
	}
	if m.Stream != "repo-beta" {
		t.Errorf("Stream = %q, want %q", m.Stream, "repo-beta")
	}
	if m.Sequence != 42 {
		t.Errorf("Sequence = %d, want 42", m.Sequence)
	}
	if m.KeyEpoch != 2 {
		t.Errorf("KeyEpoch = %d, want 2", m.KeyEpoch)
	}
	if m.KeyEpochFloor != 1 {
		t.Errorf("KeyEpochFloor = %d, want 1", m.KeyEpochFloor)
	}
	if m.Snapshot != "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db" {
		t.Errorf("Snapshot = %q, want %q", m.Snapshot, "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db")
	}
	if len(m.Refs) != 1 || m.Refs[0].Ref != "refs/heads/main" || m.Refs[0].OID != "4b825dc642cb6eb9a060e54bf8d69288fbee4904" {
		t.Errorf("Refs = %+v, want a single refs/heads/main entry", m.Refs)
	}
	if m.Timestamp != "2026-08-31T01:00:00Z" {
		t.Errorf("Timestamp = %q, want %q", m.Timestamp, "2026-08-31T01:00:00Z")
	}
	if !strings.HasPrefix(m.Signature, "ed25519:") {
		t.Errorf("Signature = %q, want ed25519: prefix", m.Signature)
	}
}

func TestMarshalMarkerRoundTrip(t *testing.T) {
	orig := &journal.Marker{
		Version:       "v1",
		Stream:        "repo-gamma",
		Sequence:      100,
		KeyEpoch:      2,
		KeyEpochFloor: 1,
		Snapshot:      "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db",
		Refs: []journal.MarkerRef{
			{Ref: "refs/heads/main", OID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
		},
		Timestamp: "2026-08-31T02:00:00Z",
		Signature: "ed25519:e3663b676f671095e4b8653ddc1419b2349d39a8adab7f28b1cb6574bc62963ec2f03996af92d34d6e2fab685c365a180d411053af476d4b319fe6a9359a8805",
	}

	data, err := journal.MarshalMarker(orig)
	if err != nil {
		t.Fatalf("MarshalMarker failed: %v", err)
	}

	if !strings.HasSuffix(string(data), "\n") {
		t.Errorf("expected trailing newline in marshaled marker JSON")
	}

	parsed, err := journal.ParseMarker(data)
	if err != nil {
		t.Fatalf("ParseMarker failed on marshaled data: %v", err)
	}

	if parsed.Version != orig.Version ||
		parsed.Stream != orig.Stream ||
		parsed.Sequence != orig.Sequence ||
		parsed.KeyEpoch != orig.KeyEpoch ||
		parsed.KeyEpochFloor != orig.KeyEpochFloor ||
		parsed.Snapshot != orig.Snapshot ||
		parsed.Timestamp != orig.Timestamp ||
		parsed.Signature != orig.Signature ||
		len(parsed.Refs) != len(orig.Refs) || parsed.Refs[0] != orig.Refs[0] {
		t.Errorf("round-trip mismatch: got %+v, want %+v", parsed, orig)
	}

	// Uppercase snapshot hash should be normalized to lowercase
	origUpper := *orig
	origUpper.Snapshot = strings.ToUpper(orig.Snapshot)
	dataUpper, err := journal.MarshalMarker(&origUpper)
	if err != nil {
		t.Fatalf("MarshalMarker with uppercase hash failed: %v", err)
	}
	parsedUpper, err := journal.ParseMarker(dataUpper)
	if err != nil {
		t.Fatalf("ParseMarker with uppercase hash failed: %v", err)
	}
	if parsedUpper.Snapshot != strings.ToLower(orig.Snapshot) {
		t.Errorf("expected lowercase snapshot hash, got %q", parsedUpper.Snapshot)
	}
}

// TestParseMarkerMissingFields covers the presence check ParseMarker's shadow struct
// performs: a marker missing any required field is refused outright, rather than
// letting Seq's and Epoch's own absent-vs-zero gap silently hand back a zero value —
// an absent key_epoch_floor decoding to 0 is exactly the hole WALD-97 closes.
func TestParseMarkerMissingFields(t *testing.T) {
	validHash := "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db"
	validSig := "ed25519:e3663b676f671095e4b8653ddc1419b2349d39a8adab7f28b1cb6574bc62963ec2f03996af92d34d6e2fab685c365a180d411053af476d4b319fe6a9359a8805"

	complete := map[string]any{
		"version":         "v1",
		"stream":          "repo-alpha",
		"sequence":        "3",
		"key_epoch":       "1",
		"key_epoch_floor": "1",
		"snapshot":        validHash,
		"refs":            []any{},
		"timestamp":       "2026-08-31T01:00:00Z",
		"signature":       validSig,
	}

	for _, field := range []string{"version", "stream", "sequence", "key_epoch", "key_epoch_floor", "snapshot", "refs", "timestamp", "signature"} {
		t.Run("missing "+field, func(t *testing.T) {
			doc := make(map[string]any, len(complete))
			for k, v := range complete {
				if k == field {
					continue
				}
				doc[k] = v
			}
			data, err := json.Marshal(doc)
			if err != nil {
				t.Fatalf("failed to marshal test document: %v", err)
			}
			_, err = journal.ParseMarker(data)
			if err == nil {
				t.Fatalf("expected error for a marker missing %q, got nil", field)
			}
			if !errors.Is(err, journal.ErrInvalidMarker) {
				t.Errorf("expected ErrInvalidMarker for missing %q, got %v", field, err)
			}
			if !strings.Contains(err.Error(), field) {
				t.Errorf("expected error naming the missing field %q, got %q", field, err.Error())
			}
		})
	}

	// The complete document, unmodified, must parse: this is the control that proves
	// each failure above comes from the field actually being absent.
	data, err := json.Marshal(complete)
	if err != nil {
		t.Fatalf("failed to marshal complete test document: %v", err)
	}
	if _, err := journal.ParseMarker(data); err != nil {
		t.Fatalf("ParseMarker failed on a complete document: %v", err)
	}
}

// TestParseMarkerEmptyRefsAccepted covers section 7.2: refs MAY be [], and that is
// authoritative state (every ref on the stream has been deleted), not a missing field.
func TestParseMarkerEmptyRefsAccepted(t *testing.T) {
	raw := `{
		"version": "v1",
		"stream": "repo-alpha",
		"sequence": "3",
		"key_epoch": "0",
		"key_epoch_floor": "0",
		"snapshot": "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db",
		"refs": [],
		"timestamp": "2026-08-31T01:00:00Z",
		"signature": "ed25519:e3663b676f671095e4b8653ddc1419b2349d39a8adab7f28b1cb6574bc62963ec2f03996af92d34d6e2fab685c365a180d411053af476d4b319fe6a9359a8805"
	}`

	m, err := journal.ParseMarker([]byte(raw))
	if err != nil {
		t.Fatalf("ParseMarker failed on an empty ref set: %v", err)
	}
	if m.Refs == nil || len(m.Refs) != 0 {
		t.Errorf("Refs = %+v, want a non-nil empty slice", m.Refs)
	}
}

// TestCanonicalMarkerPayload pins the exact byte layout of the canonical marker
// signing payload (spec section 7.2's new subsection), styled on
// TestCanonicalRefUpdatePayload.
func TestCanonicalMarkerPayload(t *testing.T) {
	stream := journal.StreamID("repo-alpha")
	refs := []journal.MarkerRef{
		{Ref: "refs/heads/main", OID: "fe75a8a9eea356bbe01fdf92d95d448190ad7942"},
		{Ref: "refs/tags/v0.1", OID: "63ed45846ea17a17cc2c2b3ddc54e37dd402ae96"},
	}
	payload := journal.CanonicalMarkerPayload(stream, 3, 1, 1, "2026-08-31T01:00:00Z", "CD04837137CBCA78F87A66055EB1EC4A598842618FA6CDB126295C6CDA9B6638", refs)
	expected := "walden-marker:v1\n" +
		"stream:repo-alpha\n" +
		"sequence:3\n" +
		"key_epoch:1\n" +
		"key_epoch_floor:1\n" +
		"timestamp:2026-08-31T01:00:00Z\n" +
		"snapshot:cd04837137cbca78f87a66055eb1ec4a598842618fa6cdb126295c6cda9b6638\n" +
		"ref:refs/heads/main fe75a8a9eea356bbe01fdf92d95d448190ad7942\n" +
		"ref:refs/tags/v0.1 63ed45846ea17a17cc2c2b3ddc54e37dd402ae96\n"

	if string(payload) != expected {
		t.Errorf("payload mismatch:\ngot:\n%s\nwant:\n%s", string(payload), expected)
	}

	// Empty ref set: zero ref lines, no trailing artifact.
	empty := journal.CanonicalMarkerPayload(stream, 3, 0, 0, "2026-08-31T01:00:00Z", "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db", nil)
	expectedEmpty := "walden-marker:v1\n" +
		"stream:repo-alpha\n" +
		"sequence:3\n" +
		"key_epoch:0\n" +
		"key_epoch_floor:0\n" +
		"timestamp:2026-08-31T01:00:00Z\n" +
		"snapshot:2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db\n"
	if string(empty) != expectedEmpty {
		t.Errorf("payload mismatch on empty refs:\ngot:\n%s\nwant:\n%s", string(empty), expectedEmpty)
	}
}

// validSignableMarker returns a well-formed, unsigned Marker ready for SignMarker.
func validSignableMarker() *journal.Marker {
	return &journal.Marker{
		Version:       "v1",
		Stream:        "repo-alpha",
		Sequence:      3,
		KeyEpoch:      1,
		KeyEpochFloor: 1,
		Snapshot:      "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db",
		Refs: []journal.MarkerRef{
			{Ref: "refs/heads/main", OID: "fe75a8a9eea356bbe01fdf92d95d448190ad7942"},
			{Ref: "refs/tags/v0.1", OID: "63ed45846ea17a17cc2c2b3ddc54e37dd402ae96"},
		},
		Timestamp: "2026-08-31T01:00:00Z",
	}
}

// TestSignAndVerifyMarker mirrors TestSignAndVerifyRefTx: a marker signs and verifies
// against the right key and fails against the wrong one, and every field the
// canonical payload covers is tamper-evident — flipping one byte of any of them
// invalidates the signature rather than silently verifying against a different
// intent.
func TestSignAndVerifyMarker(t *testing.T) {
	priv, pub := deterministicKeypair(0x01)
	formattedPub := journal.FormatPublicKey(pub)

	m := validSignableMarker()
	if err := journal.SignMarker(priv, m); err != nil {
		t.Fatalf("SignMarker failed: %v", err)
	}
	if !strings.HasPrefix(m.Signature, "ed25519:") {
		t.Fatalf("expected signature prefix 'ed25519:', got %q", m.Signature)
	}

	if err := journal.VerifyMarker(m, formattedPub); err != nil {
		t.Fatalf("VerifyMarker failed: %v", err)
	}

	_, wrongPub := deterministicKeypair(0x02)
	if err := journal.VerifyMarker(m, journal.FormatPublicKey(wrongPub)); !errors.Is(err, journal.ErrSignatureMismatch) {
		t.Errorf("expected ErrSignatureMismatch with wrong key, got %v", err)
	}

	tamper := func(name string, mutate func(*journal.Marker)) {
		t.Run(name, func(t *testing.T) {
			tampered := *m
			tampered.Refs = append([]journal.MarkerRef(nil), m.Refs...)
			mutate(&tampered)
			if err := journal.VerifyMarker(&tampered, formattedPub); !errors.Is(err, journal.ErrSignatureMismatch) {
				t.Errorf("expected ErrSignatureMismatch when tampering %s, got %v", name, err)
			}
		})
	}

	tamper("stream", func(m *journal.Marker) { m.Stream = "repo-beta" })
	tamper("sequence", func(m *journal.Marker) { m.Sequence++ })
	tamper("key_epoch", func(m *journal.Marker) { m.KeyEpoch++ })
	tamper("key_epoch_floor", func(m *journal.Marker) { m.KeyEpochFloor = 0 })
	tamper("timestamp", func(m *journal.Marker) { m.Timestamp = "2026-08-31T02:00:00Z" })
	tamper("snapshot", func(m *journal.Marker) {
		m.Snapshot = "0000000000000000000000000000000000000000000000000000000000000000"[:64]
	})
	tamper("a ref's oid", func(m *journal.Marker) { m.Refs[0].OID = "0000000000000000000000000000000000000001" })
	tamper("dropping a ref", func(m *journal.Marker) { m.Refs = m.Refs[:1] })
	tamper("adding a ref", func(m *journal.Marker) {
		// Inserted in sorted position ("refs/heads/main" < "refs/heads/zzz" <
		// "refs/tags/v0.1") so Validate's ordering rule does not catch this before
		// the signature check gets a chance to: this case is about the signature
		// covering ref set membership, not about the sort-order rule, which
		// TestValidateMarkerErrors already covers on its own.
		m.Refs = []journal.MarkerRef{
			m.Refs[0],
			{Ref: "refs/heads/zzz", OID: "8a65c6d3715c0e1e92d6e3e5362e49c7198cfb60"},
			m.Refs[1],
		}
	})
	// A reordering of an already-sorted, duplicate-free ref set is not a case this
	// path can reach: any permutation other than the sorted one fails Validate's
	// ordering rule before VerifyMarker ever gets to the signature (see
	// TestValidateMarkerErrors/marker_refs_not_sorted_ascending), so the signature's
	// coverage of ref order is enforced structurally rather than tested here.
}

// TestVerifyMarkerRequiresSignature covers the same shape as VerifyRefTx: a marker
// with no signature is refused rather than treated as trivially valid.
func TestVerifyMarkerRequiresSignature(t *testing.T) {
	_, pub := deterministicKeypair(0x01)
	m := validSignableMarker()
	if err := journal.VerifyMarker(m, journal.FormatPublicKey(pub)); !errors.Is(err, journal.ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature for a marker with no signature, got %v", err)
	}
}

// TestSigningChainVerifyMarker covers WALD-97: a marker verifies against the key its
// own key_epoch names in the chain, an epoch outside the chain is refused, and on
// success the chain's per-stream epoch floor for the marker's stream is raised to
// the marker's key_epoch_floor — the seed a resumed replay's rule 15 (key epoch
// regression) checks against.
func TestSigningChainVerifyMarker(t *testing.T) {
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

	// An epoch naming a key that has never existed in the chain is refused outright.
	unknownEpoch := validSignableMarker()
	unknownEpoch.KeyEpoch = 5
	unknownEpoch.KeyEpochFloor = 0
	if err := journal.SignMarker(priv2, unknownEpoch); err != nil {
		t.Fatalf("SignMarker failed: %v", err)
	}
	err := chain.VerifyMarker(unknownEpoch)
	if !errors.Is(err, journal.ErrUnknownKeyEpoch) {
		t.Errorf("expected ErrUnknownKeyEpoch for out-of-range epoch, got %v", err)
	}
	wantMsg := "refusal: replay failed: marker on stream repo-alpha names unknown key epoch 5"
	if err == nil || err.Error() != wantMsg {
		t.Errorf("unknown key epoch refusal = %q, want %q", err, wantMsg)
	}

	// A marker signed by the rotated key, naming its own epoch and a floor of 1
	// (the highest epoch this stream's history carries at the baseline), seeds the
	// chain's per-stream floor once it verifies.
	m := validSignableMarker()
	m.KeyEpoch = 1
	m.KeyEpochFloor = 1
	if err := journal.SignMarker(priv2, m); err != nil {
		t.Fatalf("SignMarker failed: %v", err)
	}
	if err := chain.VerifyMarker(m); err != nil {
		t.Fatalf("chain.VerifyMarker(m) failed: %v", err)
	}

	// A ref transaction on the same stream naming a lower epoch than the
	// marker-seeded floor is refused, exactly as it would be had an ordinary ref
	// transaction raised that floor (WALD-96).
	regressed := &journal.RefTransactionRecord{
		Version:  "v1",
		Stream:   "repo-alpha",
		Seq:      4,
		Type:     "ref_update",
		KeyEpoch: 0,
		Updates: []journal.RefUpdate{
			{Ref: "refs/heads/main", OldOID: "fe75a8a9eea356bbe01fdf92d95d448190ad7942", NewOID: "8a65c6d3715c0e1e92d6e3e5362e49c7198cfb60"},
		},
		Timestamp: "2026-08-31T00:10:00Z",
	}
	if err := journal.SignRefTx(priv1, regressed); err != nil {
		t.Fatalf("SignRefTx failed: %v", err)
	}
	if err := chain.VerifyRefTx(regressed); !errors.Is(err, journal.ErrKeyEpochRegression) {
		t.Errorf("expected ErrKeyEpochRegression for a record below the marker-seeded floor, got %v", err)
	}

	// A record naming the marker's own epoch verifies and raises the floor further,
	// same as any other ref transaction would.
	current := &journal.RefTransactionRecord{
		Version:  "v1",
		Stream:   "repo-alpha",
		Seq:      4,
		Type:     "ref_update",
		KeyEpoch: 1,
		Updates: []journal.RefUpdate{
			{Ref: "refs/heads/main", OldOID: "fe75a8a9eea356bbe01fdf92d95d448190ad7942", NewOID: "8a65c6d3715c0e1e92d6e3e5362e49c7198cfb60"},
		},
		Timestamp: "2026-08-31T00:10:00Z",
	}
	if err := journal.SignRefTx(priv2, current); err != nil {
		t.Fatalf("SignRefTx failed: %v", err)
	}
	if err := chain.VerifyRefTx(current); err != nil {
		t.Errorf("chain.VerifyRefTx(current) failed: %v", err)
	}
}

// TestSigningChainVerifyMarkerFloorNeverLowers is the WALD-97 round-1 finding in
// two assertions: VerifyMarker must raise a stream's epoch floor, never lower one
// (*SigningChain).VerifyRefTx already established. Without the fix, verifying a
// marker with a lower key_epoch_floor after verifying a ref transaction on the
// same stream would silently drop that stream's floor back down, and a record
// naming a retired epoch above the marker's floor but below the floor already
// seen would incorrectly verify.
func TestSigningChainVerifyMarkerFloorNeverLowers(t *testing.T) {
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

	// First, an ordinary ref transaction at the rotated key's epoch (1) raises this
	// stream's floor to 1 through (*SigningChain).VerifyRefTx.
	high := &journal.RefTransactionRecord{
		Version:  "v1",
		Stream:   "repo-alpha",
		Seq:      4,
		Type:     "ref_update",
		KeyEpoch: 1,
		Updates: []journal.RefUpdate{
			{Ref: "refs/heads/main", OldOID: "fe75a8a9eea356bbe01fdf92d95d448190ad7942", NewOID: "8a65c6d3715c0e1e92d6e3e5362e49c7198cfb60"},
		},
		Timestamp: "2026-08-31T00:10:00Z",
	}
	if err := journal.SignRefTx(priv2, high); err != nil {
		t.Fatalf("SignRefTx failed: %v", err)
	}
	if err := chain.VerifyRefTx(high); err != nil {
		t.Fatalf("chain.VerifyRefTx(high) failed: %v", err)
	}

	// Now verify a marker for the same stream carrying a lower key_epoch_floor (0)
	// than the floor VerifyRefTx already established (1) — the shape of a
	// materializer that validates the tail it already has on disk, then consults
	// marker.json, or a compactor verifying the records it just snapshotted before
	// signing and verifying the marker it produces from them.
	m := validSignableMarker()
	m.KeyEpoch = 1
	m.KeyEpochFloor = 0
	if err := journal.SignMarker(priv2, m); err != nil {
		t.Fatalf("SignMarker failed: %v", err)
	}
	if err := chain.VerifyMarker(m); err != nil {
		t.Fatalf("chain.VerifyMarker(m) failed: %v", err)
	}

	// The floor must still be 1, not lowered to the marker's 0: a record forged
	// with the retired epoch-0 key must still be refused, not accepted because the
	// marker silently reset the floor to its own, older baseline.
	forged := &journal.RefTransactionRecord{
		Version:  "v1",
		Stream:   "repo-alpha",
		Seq:      5,
		Type:     "ref_update",
		KeyEpoch: 0,
		Updates: []journal.RefUpdate{
			{Ref: "refs/heads/main", OldOID: "8a65c6d3715c0e1e92d6e3e5362e49c7198cfb60", NewOID: "63ed45846ea17a17cc2c2b3ddc54e37dd402ae96"},
		},
		Timestamp: "2026-08-31T00:11:00Z",
	}
	if err := journal.SignRefTx(priv1, forged); err != nil {
		t.Fatalf("SignRefTx failed: %v", err)
	}
	if err := chain.VerifyRefTx(forged); !errors.Is(err, journal.ErrKeyEpochRegression) {
		t.Errorf("expected ErrKeyEpochRegression for a retired-epoch record after a lower-floor marker verified, got %v", err)
	}
}

func TestParseMarkerInvalidJSON(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"empty data", []byte{}},
		{"nil data", nil},
		{"invalid json syntax", []byte("{not-json}")},
		{"truncated json", []byte(`{"version": "v1", "stream": `)},
		{"non-object json array", []byte(`["v1", "repo-alpha"]`)},
		{"non-object json scalar", []byte(`"v1"`)},
		// Section 1.1: the sequence is a JSON string holding its exact decimal form. A
		// number is refused rather than coerced, and so is a string that has been rounded
		// or reformatted — either one names a baseline that is not the one written.
		{"sequence as a json number", []byte(`{
			"version": "v1",
			"stream": "repo-beta",
			"sequence": 42,
			"snapshot": "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db",
			"timestamp": "2026-08-31T01:00:00Z"
		}`)},
		{"sequence with leading zeros", []byte(`{
			"version": "v1",
			"stream": "repo-beta",
			"sequence": "042",
			"snapshot": "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db",
			"timestamp": "2026-08-31T01:00:00Z"
		}`)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := journal.ParseMarker(tc.data)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
			if !errors.Is(err, journal.ErrCorruptMarker) {
				t.Errorf("expected ErrCorruptMarker, got %v", err)
			}
		})
	}
}

func TestValidateMarkerErrors(t *testing.T) {
	validHash := "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db"
	validTime := "2026-08-31T01:00:00Z"

	// 1. Nil marker
	var nilMarker *journal.Marker
	if err := nilMarker.Validate(); err == nil || !errors.Is(err, journal.ErrInvalidMarker) {
		t.Errorf("expected ErrInvalidMarker for nil marker, got %v", err)
	}
	if err := journal.ValidateMarker(nilMarker); err == nil || !errors.Is(err, journal.ErrInvalidMarker) {
		t.Errorf("expected ErrInvalidMarker from ValidateMarker(nil), got %v", err)
	}
	if _, err := journal.MarshalMarker(nilMarker); err == nil || !errors.Is(err, journal.ErrInvalidMarker) {
		t.Errorf("expected ErrInvalidMarker from MarshalMarker(nil), got %v", err)
	}

	invalidCases := []struct {
		name   string
		marker *journal.Marker
		errSub string
	}{
		{
			name: "unsupported version v2",
			marker: &journal.Marker{
				Version:   "v2",
				Stream:    "repo-alpha",
				Sequence:  0,
				Snapshot:  validHash,
				Timestamp: validTime,
			},
			errSub: "unsupported version",
		},
		{
			name: "meta stream rejected",
			marker: &journal.Marker{
				Version:   "v1",
				Stream:    journal.MetaStreamID,
				Sequence:  0,
				Snapshot:  validHash,
				Timestamp: validTime,
			},
			errSub: "meta stream",
		},
		{
			name: "empty stream",
			marker: &journal.Marker{
				Version:   "v1",
				Stream:    "",
				Sequence:  0,
				Snapshot:  validHash,
				Timestamp: validTime,
			},
			errSub: "invalid stream",
		},
		{
			name: "invalid stream characters",
			marker: &journal.Marker{
				Version:   "v1",
				Stream:    "repo/alpha",
				Sequence:  0,
				Snapshot:  validHash,
				Timestamp: validTime,
			},
			errSub: "invalid stream",
		},
		{
			name: "invalid snapshot hash length",
			marker: &journal.Marker{
				Version:   "v1",
				Stream:    "repo-alpha",
				Sequence:  0,
				Snapshot:  "2fe16ead",
				Timestamp: validTime,
			},
			errSub: "invalid snapshot hash",
		},
		{
			name: "invalid snapshot non-hex characters",
			marker: &journal.Marker{
				Version:   "v1",
				Stream:    "repo-alpha",
				Sequence:  0,
				Snapshot:  strings.Repeat("z", 64),
				Timestamp: validTime,
			},
			errSub: "invalid snapshot hash",
		},
		{
			name: "empty timestamp",
			marker: &journal.Marker{
				Version:   "v1",
				Stream:    "repo-alpha",
				Sequence:  0,
				Snapshot:  validHash,
				Timestamp: "",
			},
			errSub: "timestamp cannot be empty",
		},
		{
			name: "invalid timestamp format",
			marker: &journal.Marker{
				Version:   "v1",
				Stream:    "repo-alpha",
				Sequence:  0,
				Snapshot:  validHash,
				Timestamp: "not-a-date",
			},
			errSub: "invalid timestamp",
		},
		{
			name: "non-UTC timestamp",
			marker: &journal.Marker{
				Version:   "v1",
				Stream:    "repo-alpha",
				Sequence:  0,
				Snapshot:  validHash,
				Timestamp: "2026-08-31T01:00:00+05:00",
			},
			errSub: "timestamp must be in UTC",
		},
		{
			name: "key_epoch_floor exceeds key_epoch",
			marker: &journal.Marker{
				Version:       "v1",
				Stream:        "repo-alpha",
				Sequence:      0,
				KeyEpoch:      0,
				KeyEpochFloor: 1,
				Snapshot:      validHash,
				Timestamp:     validTime,
			},
			errSub: "key_epoch_floor",
		},
		{
			name: "duplicate ref in marker ref set",
			marker: &journal.Marker{
				Version:   "v1",
				Stream:    "repo-alpha",
				Sequence:  0,
				Snapshot:  validHash,
				Timestamp: validTime,
				Refs: []journal.MarkerRef{
					{Ref: "refs/heads/main", OID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
					{Ref: "refs/heads/main", OID: "8a65c6d3715c0e1e92d6e3e5362e49c7198cfb60"},
				},
			},
			errSub: "duplicate ref",
		},
		{
			name: "marker refs not sorted ascending",
			marker: &journal.Marker{
				Version:   "v1",
				Stream:    "repo-alpha",
				Sequence:  0,
				Snapshot:  validHash,
				Timestamp: validTime,
				Refs: []journal.MarkerRef{
					{Ref: "refs/tags/v0.1", OID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
					{Ref: "refs/heads/main", OID: "8a65c6d3715c0e1e92d6e3e5362e49c7198cfb60"},
				},
			},
			errSub: "sorted ascending",
		},
		{
			name: "marker ref names the zero OID",
			marker: &journal.Marker{
				Version:   "v1",
				Stream:    "repo-alpha",
				Sequence:  0,
				Snapshot:  validHash,
				Timestamp: validTime,
				Refs: []journal.MarkerRef{
					{Ref: "refs/heads/main", OID: journal.ZeroOID40},
				},
			},
			errSub: "zero OID",
		},
		{
			name: "marker refs mix oid algorithms",
			marker: &journal.Marker{
				Version:   "v1",
				Stream:    "repo-alpha",
				Sequence:  0,
				Snapshot:  validHash,
				Timestamp: validTime,
				Refs: []journal.MarkerRef{
					{Ref: "refs/heads/main", OID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
					{Ref: "refs/tags/v0.1", OID: strings.Repeat("a", 64)},
				},
			},
			errSub: "mixed oid algorithms",
		},
		{
			name: "marker ref carries an invalid ref name",
			marker: &journal.Marker{
				Version:   "v1",
				Stream:    "repo-alpha",
				Sequence:  0,
				Snapshot:  validHash,
				Timestamp: validTime,
				Refs: []journal.MarkerRef{
					{Ref: "refs/heads/main~1", OID: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
				},
			},
			errSub: "invalid ref name",
		},
		{
			name: "marker ref carries an invalid oid",
			marker: &journal.Marker{
				Version:   "v1",
				Stream:    "repo-alpha",
				Sequence:  0,
				Snapshot:  validHash,
				Timestamp: validTime,
				Refs: []journal.MarkerRef{
					{Ref: "refs/heads/main", OID: "not-an-oid"},
				},
			},
			errSub: "invalid oid",
		},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.marker.Validate()
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
			if !errors.Is(err, journal.ErrInvalidMarker) {
				t.Errorf("expected ErrInvalidMarker, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.errSub) {
				t.Errorf("expected error containing %q, got %q", tc.errSub, err.Error())
			}

			// ValidateMarker should produce identical error
			if err2 := journal.ValidateMarker(tc.marker); err2 == nil || !errors.Is(err2, journal.ErrInvalidMarker) {
				t.Errorf("ValidateMarker failed to match ErrInvalidMarker: %v", err2)
			}

			// MarshalMarker should refuse invalid marker
			if _, err2 := journal.MarshalMarker(tc.marker); err2 == nil || !errors.Is(err2, journal.ErrInvalidMarker) {
				t.Errorf("MarshalMarker failed to refuse invalid marker: %v", err2)
			}

			// ParseMarker on marshaled JSON of invalid struct should fail
			rawBytes, _ := json.Marshal(tc.marker)
			if _, err2 := journal.ParseMarker(rawBytes); err2 == nil || !errors.Is(err2, journal.ErrInvalidMarker) {
				t.Errorf("ParseMarker failed to refuse invalid marker JSON: %v", err2)
			}
		})
	}
}

func TestMarkerUnknownFieldsTolerance(t *testing.T) {
	rawWithUnknownFields := `{
		"version": "v1",
		"stream": "repo-alpha",
		"sequence": "15",
		"key_epoch": "0",
		"key_epoch_floor": "0",
		"snapshot": "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db",
		"refs": [],
		"timestamp": "2026-08-31T01:00:00Z",
		"signature": "ed25519:e3663b676f671095e4b8653ddc1419b2349d39a8adab7f28b1cb6574bc62963ec2f03996af92d34d6e2fab685c365a180d411053af476d4b319fe6a9359a8805",
		"compactor_version": "1.2.0",
		"reachable_objects": 1520,
		"extra_metadata": {
			"duration_ms": 340,
			"pruned_bytes": 1048576
		}
	}`

	m, err := journal.ParseMarker([]byte(rawWithUnknownFields))
	if err != nil {
		t.Fatalf("ParseMarker failed on JSON with unknown fields: %v", err)
	}

	if m.Version != "v1" || m.Stream != "repo-alpha" || m.Sequence != 15 {
		t.Errorf("unexpected parsed marker values: %+v", m)
	}
}

func TestValidateSnapshot(t *testing.T) {
	// 1. Valid SHA-1 packfile snapshot
	sha1Pack := validEmptyPackfile()
	sha1Hash := journal.ComputeSegmentHash(sha1Pack)
	if err := journal.ValidateSnapshot(sha1Pack, sha1Hash); err != nil {
		t.Errorf("ValidateSnapshot failed on valid SHA-1 snapshot: %v", err)
	}

	// 2. Valid SHA-256 packfile snapshot
	sha256Pack := validEmptyPackfileSHA256()
	sha256Hash := journal.ComputeSegmentHash(sha256Pack)
	if err := journal.ValidateSnapshot(sha256Pack, sha256Hash); err != nil {
		t.Errorf("ValidateSnapshot failed on valid SHA-256 snapshot: %v", err)
	}

	// 3. Case-insensitive hash match
	if err := journal.ValidateSnapshot(sha1Pack, strings.ToUpper(sha1Hash)); err != nil {
		t.Errorf("ValidateSnapshot failed on uppercase expected hash: %v", err)
	}

	// 4. Hash mismatch
	wrongHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	err := journal.ValidateSnapshot(sha1Pack, wrongHash)
	if err == nil {
		t.Fatalf("expected error on hash mismatch, got nil")
	}
	if !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt, got %v", err)
	}
	if !errors.Is(err, journal.ErrSnapshotHashMismatch) {
		t.Errorf("expected ErrSnapshotHashMismatch, got %v", err)
	}

	// 5. Invalid expected hash format
	err = journal.ValidateSnapshot(sha1Pack, "invalid-hash")
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for bad hash format, got %v", err)
	}

	// 6. Corrupt packfile header
	corruptPack := make([]byte, 32)
	copy(corruptPack, sha1Pack)
	corruptPack[0] = 'B' // PACK -> BACK
	err = journal.ValidateSnapshot(corruptPack, sha1Hash)
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for corrupt header, got %v", err)
	}
	if !errors.Is(err, journal.ErrInvalidPackfile) {
		t.Errorf("expected ErrInvalidPackfile for corrupt header, got %v", err)
	}

	// 7. Truncated packfile (< 32 bytes)
	truncatedPack := make([]byte, 20)
	err = journal.ValidateSnapshot(truncatedPack, sha1Hash)
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for truncated pack, got %v", err)
	}
}

func TestValidateSnapshotSHA256(t *testing.T) {
	// 1. Valid SHA-256 packfile snapshot (>= 44 bytes)
	sha256Pack := validEmptyPackfileSHA256()
	sha256Hash := journal.ComputeSegmentHash(sha256Pack)
	if err := journal.ValidateSnapshotSHA256(sha256Pack, sha256Hash); err != nil {
		t.Errorf("ValidateSnapshotSHA256 failed on valid SHA-256 snapshot: %v", err)
	}

	// 2. Too short for SHA-256 repo (< 44 bytes, even if valid SHA-1 32 bytes)
	sha1Pack := validEmptyPackfile()
	sha1Hash := journal.ComputeSegmentHash(sha1Pack)
	err := journal.ValidateSnapshotSHA256(sha1Pack, sha1Hash)
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for 32-byte packfile in SHA-256 validation, got %v", err)
	}

	// 3. Invalid expected hash
	err = journal.ValidateSnapshotSHA256(sha256Pack, "invalid-hash")
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for invalid hash, got %v", err)
	}

	// 4. Hash mismatch
	err = journal.ValidateSnapshotSHA256(sha256Pack, sha1Hash)
	if err == nil || !errors.Is(err, journal.ErrSnapshotHashMismatch) {
		t.Errorf("expected ErrSnapshotHashMismatch, got %v", err)
	}
}

func TestSnapshotMetadataAndContentType(t *testing.T) {
	stream := journal.StreamID("repo-delta")
	hash := "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db"

	meta := journal.SnapshotMetadata(stream, strings.ToUpper(hash))
	if meta[journal.MetaHeaderStream] != "repo-delta" {
		t.Errorf("MetaHeaderStream = %q, want %q", meta[journal.MetaHeaderStream], "repo-delta")
	}
	if meta[journal.MetaHeaderHash] != hash {
		t.Errorf("MetaHeaderHash = %q, want %q", meta[journal.MetaHeaderHash], hash)
	}

	if got := journal.SnapshotContentType(); got != "application/x-git-packed-objects" {
		t.Errorf("SnapshotContentType = %q, want %q", got, "application/x-git-packed-objects")
	}
}

func TestMarkerRefusalFormatting(t *testing.T) {
	stream := journal.StreamID("repo-alpha")
	hash := "2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db"

	// 1. Missing snapshot refusal
	err := journal.RefuseMissingSnapshot(stream, hash)
	if err == nil {
		t.Fatalf("expected refusal error, got nil")
	}
	var ref *refusal.Refusal
	if !errors.As(err, &ref) {
		t.Fatalf("expected *refusal.Refusal type, got %T", err)
	}
	if !errors.Is(err, journal.ErrSnapshotNotFound) {
		t.Errorf("expected errors.Is(err, ErrSnapshotNotFound) to be true")
	}
	msg := err.Error()
	if strings.Contains(msg, "\n") {
		t.Errorf("refusal message contains newline: %q", msg)
	}
	expectedPrefix := "refusal: replay failed: missing snapshot pack 2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db on stream repo-alpha"
	if !strings.HasPrefix(msg, expectedPrefix) {
		t.Errorf("unexpected refusal message format: got %q, want prefix %q", msg, expectedPrefix)
	}

	// 2. Snapshot hash mismatch refusal
	computed := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	err = journal.RefuseSnapshotHashMismatch(stream, hash, computed)
	if !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected errors.Is(err, ErrSnapshotCorrupt) to be true")
	}
	if !errors.Is(err, journal.ErrSnapshotHashMismatch) {
		t.Errorf("expected errors.Is(err, ErrSnapshotHashMismatch) to be true")
	}
	msg = err.Error()
	if strings.Contains(msg, "\n") {
		t.Errorf("refusal message contains newline: %q", msg)
	}
	expectedMismatch := "refusal: replay failed: snapshot hash mismatch for 2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db on stream repo-alpha (computed e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)"
	if !strings.HasPrefix(msg, expectedMismatch) {
		t.Errorf("unexpected hash mismatch refusal format: got %q, want prefix %q", msg, expectedMismatch)
	}

	// 3. Corrupt snapshot refusal
	err = journal.RefuseCorruptSnapshot(stream, hash, journal.ErrInvalidPackfile)
	if !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected errors.Is(err, ErrSnapshotCorrupt) to be true")
	}
	if !errors.Is(err, journal.ErrInvalidPackfile) {
		t.Errorf("expected errors.Is(err, ErrInvalidPackfile) to be true")
	}
	msg = err.Error()
	if strings.Contains(msg, "\n") {
		t.Errorf("refusal message contains newline: %q", msg)
	}
	expectedCorrupt := "refusal: replay failed: corrupt snapshot pack 2fe16eadff990410007dcbc1cd25b5f381489e774a22056cecd1fb52989006db on stream repo-alpha"
	if !strings.HasPrefix(msg, expectedCorrupt) {
		t.Errorf("unexpected corrupt snapshot refusal format: got %q, want prefix %q", msg, expectedCorrupt)
	}

	// 4. Corrupt marker refusal
	eofErr := errors.New("unexpected EOF")
	err = journal.RefuseCorruptMarker(stream, eofErr)
	if !errors.Is(err, journal.ErrCorruptMarker) {
		t.Errorf("expected errors.Is(err, ErrCorruptMarker) to be true")
	}
	if !errors.Is(err, eofErr) {
		t.Errorf("expected errors.Is(err, eofErr) to be true")
	}
	msg = err.Error()
	if strings.Contains(msg, "\n") {
		t.Errorf("refusal message contains newline: %q", msg)
	}
	expectedMarkerCorrupt := "refusal: replay failed: corrupt marker on stream repo-alpha (unexpected EOF) (marker.json in object storage is malformed)"
	if msg != expectedMarkerCorrupt {
		t.Errorf("unexpected corrupt marker refusal: got %q, want %q", msg, expectedMarkerCorrupt)
	}

	// 5. Invalid marker refusal
	err = journal.RefuseInvalidMarker(stream, journal.ErrInvalidMarker)
	if !errors.Is(err, journal.ErrInvalidMarker) {
		t.Errorf("expected errors.Is(err, ErrInvalidMarker) to be true")
	}
	msg = err.Error()
	if strings.Contains(msg, "\n") {
		t.Errorf("refusal message contains newline: %q", msg)
	}
	expectedMarkerInvalid := "refusal: replay failed: invalid marker on stream repo-alpha (invalid marker) (marker.json in object storage is invalid)"
	if msg != expectedMarkerInvalid {
		t.Errorf("unexpected invalid marker refusal: got %q, want %q", msg, expectedMarkerInvalid)
	}

	// 6. Marker signature mismatch refusal (section 7.6 item 6 / 8.1 rule 16)
	err = journal.RefuseMarkerSignatureMismatch(stream, journal.Seq(3))
	if !errors.Is(err, journal.ErrSignatureMismatch) {
		t.Errorf("expected errors.Is(err, ErrSignatureMismatch) to be true")
	}
	msg = err.Error()
	if strings.Contains(msg, "\n") {
		t.Errorf("refusal message contains newline: %q", msg)
	}
	expectedMarkerSignatureMismatch := "refusal: replay failed: signature mismatch for marker on stream repo-alpha at sequence 3"
	if msg != expectedMarkerSignatureMismatch {
		t.Errorf("unexpected marker signature mismatch refusal: got %q, want %q", msg, expectedMarkerSignatureMismatch)
	}

	// 8. Marker ref not in snapshot refusal (section 7.6 item 8 / 8.1 rule 18). Not
	// wired to a caller in this package: deciding whether a marker's ref set is
	// covered by its snapshot pack means enumerating the pack's objects, which
	// needs either exec'ing git or reimplementing pack handling — AGENTS.md
	// reserves that to code that wraps git, not to internal/journal. Enforcing
	// Guarantee 3 (section 7.3) belongs to whatever reads the snapshot pack
	// (a future compactor/reader), not to this package. Pinned here anyway so
	// the published string cannot drift from section 7.6 item 8 with this check
	// command still green.
	err = journal.RefuseMarkerRefNotInSnapshot(stream, "refs/heads/main", "4b825dc642cb6eb9a060e54bf8d69288fbee4904")
	if !errors.Is(err, journal.ErrInvalidMarker) {
		t.Errorf("expected errors.Is(err, ErrInvalidMarker) to be true")
	}
	msg = err.Error()
	if strings.Contains(msg, "\n") {
		t.Errorf("refusal message contains newline: %q", msg)
	}
	expectedMarkerRefNotInSnapshot := "refusal: replay failed: marker on stream repo-alpha names refs/heads/main at 4b825dc642cb6eb9a060e54bf8d69288fbee4904, which the snapshot pack does not carry (marker.json in object storage is invalid)"
	if msg != expectedMarkerRefNotInSnapshot {
		t.Errorf("unexpected marker ref not in snapshot refusal: got %q, want %q", msg, expectedMarkerRefNotInSnapshot)
	}
}

func TestValidateSnapshotFromReader(t *testing.T) {
	pack := validEmptyPackfile()
	hash := journal.ComputeSegmentHash(pack)

	// 1. Valid streaming snapshot
	n, err := journal.ValidateSnapshotFromReader(bytes.NewReader(pack), hash)
	if err != nil {
		t.Fatalf("ValidateSnapshotFromReader failed: %v", err)
	}
	if n != int64(len(pack)) {
		t.Errorf("bytes read = %d, want %d", n, len(pack))
	}

	// 2. Case-insensitive hash match
	n, err = journal.ValidateSnapshotFromReader(bytes.NewReader(pack), strings.ToUpper(hash))
	if err != nil {
		t.Fatalf("ValidateSnapshotFromReader with uppercase hash failed: %v", err)
	}
	if n != int64(len(pack)) {
		t.Errorf("bytes read = %d, want %d", n, len(pack))
	}

	// 3. Nil reader
	_, err = journal.ValidateSnapshotFromReader(nil, hash)
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for nil reader, got %v", err)
	}

	// 4. Invalid expected hash
	_, err = journal.ValidateSnapshotFromReader(bytes.NewReader(pack), "not-a-hash")
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for invalid hash format, got %v", err)
	}

	// 5. Short stream (< 32 bytes)
	_, err = journal.ValidateSnapshotFromReader(bytes.NewReader([]byte("PACK short")), hash)
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for short stream, got %v", err)
	}

	// 6. Corrupt header magic
	corruptHdr := make([]byte, 32)
	copy(corruptHdr, pack)
	corruptHdr[0] = 'Z'
	_, err = journal.ValidateSnapshotFromReader(bytes.NewReader(corruptHdr), hash)
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for corrupt header, got %v", err)
	}

	// 7. Hash mismatch
	wrongHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	_, err = journal.ValidateSnapshotFromReader(bytes.NewReader(pack), wrongHash)
	if err == nil || !errors.Is(err, journal.ErrSnapshotHashMismatch) {
		t.Errorf("expected ErrSnapshotHashMismatch, got %v", err)
	}
}

func TestValidateSnapshotSHA256FromReader(t *testing.T) {
	pack := validEmptyPackfileSHA256()
	hash := journal.ComputeSegmentHash(pack)

	// 1. Valid streaming SHA-256 snapshot
	n, err := journal.ValidateSnapshotSHA256FromReader(bytes.NewReader(pack), hash)
	if err != nil {
		t.Fatalf("ValidateSnapshotSHA256FromReader failed: %v", err)
	}
	if n != int64(len(pack)) {
		t.Errorf("bytes read = %d, want %d", n, len(pack))
	}

	// 2. Too short for SHA-256 repo (< 44 bytes)
	sha1Pack := validEmptyPackfile()
	sha1Hash := journal.ComputeSegmentHash(sha1Pack)
	_, err = journal.ValidateSnapshotSHA256FromReader(bytes.NewReader(sha1Pack), sha1Hash)
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for 32-byte pack in SHA-256 validator, got %v", err)
	}

	// 3. Nil reader
	_, err = journal.ValidateSnapshotSHA256FromReader(nil, hash)
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for nil reader, got %v", err)
	}

	// 4. Invalid expected hash
	_, err = journal.ValidateSnapshotSHA256FromReader(bytes.NewReader(pack), "not-a-hash")
	if err == nil || !errors.Is(err, journal.ErrSnapshotCorrupt) {
		t.Errorf("expected ErrSnapshotCorrupt for invalid hash format, got %v", err)
	}

	// 5. Hash mismatch
	_, err = journal.ValidateSnapshotSHA256FromReader(bytes.NewReader(pack), sha1Hash)
	if err == nil || !errors.Is(err, journal.ErrSnapshotHashMismatch) {
		t.Errorf("expected ErrSnapshotHashMismatch, got %v", err)
	}
}
