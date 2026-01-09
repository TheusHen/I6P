package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrCiphertextTooShort = errors.New("crypto: ciphertext too short")
	ErrDecryptionFailed   = errors.New("crypto: decryption failed")
)

// AEAD wraps ChaCha20-Poly1305 with automatic nonce management.
// It uses a 64-bit counter + 32-bit random prefix for the 96-bit nonce.
// This allows ~2^64 messages per key with no nonce reuse.
type AEAD struct {
	aead   cipher.AEAD
	prefix [4]byte
	seq    atomic.Uint64
}

// NewAEAD creates a new AEAD cipher from a 32-byte key.
func NewAEAD(key []byte) (*AEAD, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("crypto: invalid key size for ChaCha20-Poly1305")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	a := &AEAD{aead: aead}
	if _, err := io.ReadFull(rand.Reader, a.prefix[:]); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *AEAD) nextNonce() []byte {
	seq := a.seq.Add(1)
	nonce := make([]byte, chacha20poly1305.NonceSize) // 12 bytes
	copy(nonce[:4], a.prefix[:])
	binary.BigEndian.PutUint64(nonce[4:], seq)
	return nonce
}

// Seal encrypts and authenticates plaintext.
// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
func (a *AEAD) Seal(plaintext, additionalData []byte) []byte {
	nonce := a.nextNonce()
	ciphertext := a.aead.Seal(nil, nonce, plaintext, additionalData)
	out := make([]byte, len(nonce)+len(ciphertext))
	copy(out, nonce)
	copy(out[len(nonce):], ciphertext)
	return out
}

// Open decrypts and verifies ciphertext.
// Input format: nonce (12 bytes) || ciphertext || tag (16 bytes)
func (a *AEAD) Open(ciphertext, additionalData []byte) ([]byte, error) {
	nonceSize := chacha20poly1305.NonceSize
	if len(ciphertext) < nonceSize+a.aead.Overhead() {
		return nil, ErrCiphertextTooShort
	}
	nonce := ciphertext[:nonceSize]
	ct := ciphertext[nonceSize:]
	plaintext, err := a.aead.Open(nil, nonce, ct, additionalData)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

// Overhead returns the authentication tag overhead.
func (a *AEAD) Overhead() int { return a.aead.Overhead() }

// NonceSize returns the nonce size.
func (a *AEAD) NonceSize() int { return chacha20poly1305.NonceSize }
