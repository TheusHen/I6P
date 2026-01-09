package crypto

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveKey derives a key of the specified length using HKDF-SHA256.
// salt can be nil (uses zero salt), info provides context binding.
func DeriveKey(secret, salt, info []byte, length int) ([]byte, error) {
	hk := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, length)
	if _, err := io.ReadFull(hk, key); err != nil {
		return nil, err
	}
	return key, nil
}

// DeriveSessionKeys derives encryption keys for both directions from the shared secret.
// Returns: (initiatorKey, responderKey, each 32 bytes)
func DeriveSessionKeys(sharedSecret []byte, initiatorPub, responderPub [32]byte) ([]byte, []byte, error) {
	// Context includes both public keys to bind the keys to this specific session
	info := make([]byte, 0, 64+len("i6p-session-keys"))
	info = append(info, []byte("i6p-session-keys")...)
	info = append(info, initiatorPub[:]...)
	info = append(info, responderPub[:]...)

	keyMaterial, err := DeriveKey(sharedSecret, nil, info, 64)
	if err != nil {
		return nil, nil, err
	}
	return keyMaterial[:32], keyMaterial[32:64], nil
}
