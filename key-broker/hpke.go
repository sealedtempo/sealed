package keybroker

import (
	"crypto/ecdh"
	"crypto/hpke"
	"errors"
	"fmt"
)

// ReleaseInfo is the HPKE info string of a key release (INTERFACES.md section 9). The aad is the 32-byte nonce.
const ReleaseInfo = "sealed/kb-release/v1"

// HPKE suite of the release: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM (RFC 9180 base mode).
var (
	releaseKEM  = hpke.DHKEM(ecdh.X25519())
	releaseKDF  = hpke.HKDFSHA256()
	releaseAEAD = hpke.AES256GCM()
)

// ErrBadEphemeralKey is returned for an ephemeral public key HPKE cannot encapsulate to (for example a low-order
// X25519 point).
var ErrBadEphemeralKey = errors.New("ephemeralPub is not a usable X25519 public key")

// SealRelease encrypts plaintext to the agent's ephemeral X25519 key with info "sealed/kb-release/v1" and aad = nonce.
// It returns the encapsulated key (32 bytes) and the AEAD ciphertext as separate values.
func SealRelease(ephemeralPub, nonce [32]byte, plaintext []byte) (enc, ciphertext []byte, err error) {
	pk, err := releaseKEM.NewPublicKey(ephemeralPub[:])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrBadEphemeralKey, err)
	}
	enc, sender, err := hpke.NewSender(pk, releaseKDF, releaseAEAD, []byte(ReleaseInfo))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrBadEphemeralKey, err)
	}
	ciphertext, err = sender.Seal(nonce[:], plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("hpke seal: %w", err)
	}
	return enc, ciphertext, nil
}

// OpenRelease decrypts a release with the agent's ephemeral private key. The broker never calls it; agents written
// in Go and the tests do.
func OpenRelease(priv hpke.PrivateKey, nonce [32]byte, enc, ciphertext []byte) ([]byte, error) {
	r, err := hpke.NewRecipient(enc, priv, releaseKDF, releaseAEAD, []byte(ReleaseInfo))
	if err != nil {
		return nil, fmt.Errorf("hpke recipient: %w", err)
	}
	pt, err := r.Open(nonce[:], ciphertext)
	if err != nil {
		return nil, fmt.Errorf("hpke open: %w", err)
	}
	return pt, nil
}

// GenerateEphemeralKey returns a fresh X25519 key pair for a release request and its raw 32-byte public key.
func GenerateEphemeralKey() (hpke.PrivateKey, [32]byte, error) {
	var pub [32]byte
	k, err := releaseKEM.GenerateKey()
	if err != nil {
		return nil, pub, err
	}
	b := k.PublicKey().Bytes()
	if len(b) != 32 {
		return nil, pub, fmt.Errorf("X25519 public key is %d bytes", len(b))
	}
	copy(pub[:], b)
	return k, pub, nil
}

// DeriveEphemeralKey is GenerateEphemeralKey from fixed input keying material (RFC 9180 DeriveKeyPair), for test
// vectors shared with @sealed/core.
func DeriveEphemeralKey(ikm []byte) (hpke.PrivateKey, [32]byte, error) {
	var pub [32]byte
	k, err := releaseKEM.DeriveKeyPair(ikm)
	if err != nil {
		return nil, pub, err
	}
	copy(pub[:], k.PublicKey().Bytes())
	return k, pub, nil
}
