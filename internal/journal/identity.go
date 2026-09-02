package journal

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrInvalidKey          = errors.New("invalid public key format")
	ErrInvalidSignature    = errors.New("invalid signature format")
	ErrSignatureMismatch   = errors.New("signature verification failed")
	ErrUnchainableRotation = errors.New("key rotation does not chain to active key")
	ErrGenesisMissing      = errors.New("genesis record missing")
	ErrInvalidGenesis      = errors.New("invalid genesis record")
	ErrInvalidRotation     = errors.New("invalid key rotation record")
)

const (
	// PublicKeyPrefix is the required prefix for Ed25519 public keys.
	PublicKeyPrefix = "ed25519:"

	// SignaturePrefix is the required prefix for Ed25519 signatures.
	SignaturePrefix = "ed25519:"

	// RecordTypeGenesis identifies the genesis record in the meta stream.
	RecordTypeGenesis = "genesis"

	// RecordTypeKeyRotation identifies a key rotation record in the meta stream.
	RecordTypeKeyRotation = "key_rotation"
)

// GenesisRecord represents the initial record (seq 0) on the _meta stream declaring the server's signing identity.
type GenesisRecord struct {
	Version   string   `json:"version"`
	Stream    StreamID `json:"stream"`
	Seq       Seq      `json:"seq"`
	Type      string   `json:"type"`
	PublicKey string   `json:"public_key"`
	Timestamp string   `json:"timestamp"`
}

// KeyRotationRecord represents a key rotation on the _meta stream, signed by the outgoing key.
type KeyRotationRecord struct {
	Version      string   `json:"version"`
	Stream       StreamID `json:"stream"`
	Seq          Seq      `json:"seq"`
	Type         string   `json:"type"`
	OldPublicKey string   `json:"old_public_key"`
	NewPublicKey string   `json:"new_public_key"`
	Timestamp    string   `json:"timestamp"`
	Signature    string   `json:"signature"`
}

// GenerateKeypair generates a new Ed25519 keypair for walden server signing.
func GenerateKeypair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ed25519 keypair: %w", err)
	}
	return priv, pub, nil
}

// FormatPublicKey formats an ed25519.PublicKey as "ed25519:<64-hex>".
func FormatPublicKey(pub ed25519.PublicKey) string {
	return PublicKeyPrefix + hex.EncodeToString(pub)
}

// ParsePublicKey parses and validates an "ed25519:<64-hex>" string.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(s, PublicKeyPrefix) {
		return nil, fmt.Errorf("%w: missing prefix %q in %q", ErrInvalidKey, PublicKeyPrefix, s)
	}
	hexStr := strings.TrimPrefix(s, PublicKeyPrefix)
	if len(hexStr) != 64 {
		return nil, fmt.Errorf("%w: public key hex must be 64 characters, got %d", ErrInvalidKey, len(hexStr))
	}
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("%w: hex decode error: %w", ErrInvalidKey, err)
	}
	if len(bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: invalid key length %d", ErrInvalidKey, len(bytes))
	}
	return ed25519.PublicKey(bytes), nil
}

// FormatSignature formats an Ed25519 signature as "ed25519:<128-hex>".
func FormatSignature(sig []byte) string {
	return SignaturePrefix + hex.EncodeToString(sig)
}

// ParseSignature parses and validates an "ed25519:<128-hex>" string.
func ParseSignature(s string) ([]byte, error) {
	if !strings.HasPrefix(s, SignaturePrefix) {
		return nil, fmt.Errorf("%w: missing prefix %q in %q", ErrInvalidSignature, SignaturePrefix, s)
	}
	hexStr := strings.TrimPrefix(s, SignaturePrefix)
	if len(hexStr) != 128 {
		return nil, fmt.Errorf("%w: signature hex must be 128 characters, got %d", ErrInvalidSignature, len(hexStr))
	}
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("%w: hex decode error: %w", ErrInvalidSignature, err)
	}
	if len(bytes) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: invalid signature length %d", ErrInvalidSignature, len(bytes))
	}
	return bytes, nil
}

// CanonicalRotationPayload returns the deterministic canonical bytes to sign/verify for a KeyRotationRecord.
func CanonicalRotationPayload(stream StreamID, seq Seq, oldKey, newKey, timestamp string) []byte {
	return []byte(fmt.Sprintf("walden-key-rotation:v1\nstream:%s\nseq:%d\nold_public_key:%s\nnew_public_key:%s\ntimestamp:%s\n",
		stream, seq, oldKey, newKey, timestamp))
}

// SignRotation signs a KeyRotationRecord using the outgoing private key.
func SignRotation(priv ed25519.PrivateKey, r *KeyRotationRecord) error {
	pub := priv.Public().(ed25519.PublicKey)
	formattedPub := FormatPublicKey(pub)
	if r.OldPublicKey != formattedPub {
		return fmt.Errorf("%w: private key does not match old public key %q", ErrInvalidKey, r.OldPublicKey)
	}
	payload := CanonicalRotationPayload(r.Stream, r.Seq, r.OldPublicKey, r.NewPublicKey, r.Timestamp)
	sig := ed25519.Sign(priv, payload)
	r.Signature = FormatSignature(sig)
	return nil
}

// VerifyRotation verifies that a key rotation record is cryptographically valid and chains to expectedActiveKey.
func VerifyRotation(r *KeyRotationRecord, expectedActiveKey string) error {
	if r.Version != VersionPrefix {
		return fmt.Errorf("%w: unsupported version %q", ErrInvalidRotation, r.Version)
	}
	if r.Stream != MetaStreamID {
		return fmt.Errorf("%w: key rotation must be in meta stream, got %q", ErrInvalidRotation, r.Stream)
	}
	if r.Type != RecordTypeKeyRotation {
		return fmt.Errorf("%w: expected type %q, got %q", ErrInvalidRotation, RecordTypeKeyRotation, r.Type)
	}
	if r.OldPublicKey != expectedActiveKey {
		return fmt.Errorf("%w: rotation old_public_key %q does not match active key %q", ErrUnchainableRotation, r.OldPublicKey, expectedActiveKey)
	}
	if r.NewPublicKey == r.OldPublicKey {
		return fmt.Errorf("%w: new public key must differ from old public key", ErrInvalidRotation)
	}
	pubKey, err := ParsePublicKey(r.OldPublicKey)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRotation, err)
	}
	if _, err := ParsePublicKey(r.NewPublicKey); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRotation, err)
	}
	sigBytes, err := ParseSignature(r.Signature)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRotation, err)
	}
	payload := CanonicalRotationPayload(r.Stream, r.Seq, r.OldPublicKey, r.NewPublicKey, r.Timestamp)
	if !ed25519.Verify(pubKey, payload, sigBytes) {
		return fmt.Errorf("%w: signature mismatch for key rotation at seq %d", ErrSignatureMismatch, r.Seq)
	}
	return nil
}

// SigningChain tracks the active server signing key verified from genesis forward.
type SigningChain struct {
	activeKey   string
	lastMetaSeq Seq
	initialized bool
}

// NewSigningChain creates an uninitialized signing chain.
func NewSigningChain() *SigningChain {
	return &SigningChain{}
}

// ActiveKey returns the currently active public key string ("ed25519:<hex>").
func (c *SigningChain) ActiveKey() string {
	return c.activeKey
}

// LastMetaSeq returns the last processed meta sequence number.
func (c *SigningChain) LastMetaSeq() Seq {
	return c.lastMetaSeq
}

// IsInitialized returns whether the signing chain has loaded genesis.
func (c *SigningChain) IsInitialized() bool {
	return c.initialized
}

// ApplyGenesis applies the genesis record as the root of trust (seq 0).
func (c *SigningChain) ApplyGenesis(g *GenesisRecord) error {
	if c.initialized {
		return fmt.Errorf("%w: signing chain already initialized", ErrInvalidGenesis)
	}
	if g.Version != VersionPrefix {
		return fmt.Errorf("%w: unsupported version %q", ErrInvalidGenesis, g.Version)
	}
	if g.Stream != MetaStreamID {
		return fmt.Errorf("%w: genesis stream must be %q, got %q", ErrInvalidGenesis, MetaStreamID, g.Stream)
	}
	if g.Seq != 0 {
		return fmt.Errorf("%w: genesis seq must be 0, got %d", ErrInvalidGenesis, g.Seq)
	}
	if g.Type != RecordTypeGenesis {
		return fmt.Errorf("%w: expected type %q, got %q", ErrInvalidGenesis, RecordTypeGenesis, g.Type)
	}
	if _, err := ParsePublicKey(g.PublicKey); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidGenesis, err)
	}
	c.activeKey = g.PublicKey
	c.lastMetaSeq = 0
	c.initialized = true
	return nil
}

// ApplyRotation applies and validates a key rotation record in the meta stream.
func (c *SigningChain) ApplyRotation(r *KeyRotationRecord) error {
	if !c.initialized {
		return fmt.Errorf("%w: cannot apply rotation before genesis", ErrGenesisMissing)
	}
	if r.Seq != c.lastMetaSeq+1 {
		return fmt.Errorf("%w: sequence gap or out-of-order rotation (expected %d, got %d)", ErrInvalidRotation, c.lastMetaSeq+1, r.Seq)
	}
	if err := VerifyRotation(r, c.activeKey); err != nil {
		return err
	}
	c.activeKey = r.NewPublicKey
	c.lastMetaSeq = r.Seq
	return nil
}

// AdvanceMetaSeq records non-rotation meta records to keep the sequence contiguous.
func (c *SigningChain) AdvanceMetaSeq(seq Seq) error {
	if !c.initialized {
		return fmt.Errorf("%w: cannot advance meta sequence before genesis", ErrGenesisMissing)
	}
	if seq != c.lastMetaSeq+1 {
		return fmt.Errorf("%w: sequence gap (expected %d, got %d)", ErrInvalidSeq, c.lastMetaSeq+1, seq)
	}
	c.lastMetaSeq = seq
	return nil
}
