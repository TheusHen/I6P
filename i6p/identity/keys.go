package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
)

// KeyPair holds an Ed25519 keypair used for peer identity.
type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

func GenerateKeyPair() (KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{PublicKey: pub, PrivateKey: priv}, nil
}

func NewKeyPair(publicKey, privateKey []byte) (KeyPair, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return KeyPair{}, errors.New("invalid Ed25519 public key size")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return KeyPair{}, errors.New("invalid Ed25519 private key size")
	}
	return KeyPair{PublicKey: ed25519.PublicKey(publicKey), PrivateKey: ed25519.PrivateKey(privateKey)}, nil
}

func (kp KeyPair) PeerID() PeerID {
	return PeerIDFromPublicKey(kp.PublicKey)
}

func (kp KeyPair) Sign(message []byte) []byte {
	return ed25519.Sign(kp.PrivateKey, message)
}

func Verify(publicKey ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(publicKey, message, signature)
}
