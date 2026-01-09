package crypto

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

// X25519KeyPair represents an ephemeral ECDH keypair.
type X25519KeyPair struct {
	PublicKey  [32]byte
	PrivateKey [32]byte
}

var (
	ErrInvalidPublicKey = errors.New("crypto: invalid X25519 public key")
)

// GenerateX25519 generates a new ephemeral X25519 keypair.
func GenerateX25519() (X25519KeyPair, error) {
	var kp X25519KeyPair
	if _, err := io.ReadFull(rand.Reader, kp.PrivateKey[:]); err != nil {
		return X25519KeyPair{}, err
	}
	// Clamp private key per RFC 7748
	kp.PrivateKey[0] &= 248
	kp.PrivateKey[31] &= 127
	kp.PrivateKey[31] |= 64

	curve25519.ScalarBaseMult(&kp.PublicKey, &kp.PrivateKey)
	return kp, nil
}

// ECDH computes the shared secret using X25519.
// Returns 32 bytes of raw shared secret (should be passed to HKDF).
func ECDH(privateKey, peerPublicKey [32]byte) ([]byte, error) {
	// Check for low-order points (all zeros is invalid)
	var zero [32]byte
	if peerPublicKey == zero {
		return nil, ErrInvalidPublicKey
	}
	shared, err := curve25519.X25519(privateKey[:], peerPublicKey[:])
	if err != nil {
		return nil, err
	}
	return shared, nil
}
