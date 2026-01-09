package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// PeerID is the stable identifier for a peer.
// It is defined as: PeerID = SHA-256(PublicKey).
type PeerID [32]byte

func PeerIDFromPublicKey(publicKey []byte) PeerID {
	sum := sha256.Sum256(publicKey)
	return PeerID(sum)
}

func ParsePeerIDHex(s string) (PeerID, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return PeerID{}, err
	}
	if len(b) != 32 {
		return PeerID{}, errors.New("invalid PeerID length")
	}
	var id PeerID
	copy(id[:], b)
	return id, nil
}

func (id PeerID) String() string {
	return hex.EncodeToString(id[:])
}
