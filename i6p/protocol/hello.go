package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/TheusHen/I6P/i6p/identity"
)

var (
	ErrHelloPeerIDMismatch = errors.New("hello peerid does not match public key")
	ErrHelloBadSignature   = errors.New("hello invalid signature")
	ErrHelloMissingKey     = errors.New("hello missing public key")
)

// Hello binds a session to an Ed25519 identity.
// The signature is computed over SigningBytes().
type Hello struct {
	PeerID       string            `json:"peer_id"`
	PublicKey    []byte            `json:"public_key"`
	TimestampSec int64             `json:"timestamp_sec"`
	Nonce        []byte            `json:"nonce"`
	Capabilities map[string]string `json:"capabilities,omitempty"`
	Signature    []byte            `json:"signature"`
}

func NewHello(kp identity.KeyPair, capabilities map[string]string) (Hello, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return Hello{}, err
	}
	// Copy caps to avoid external mutation.
	capsCopy := map[string]string{}
	for k, v := range capabilities {
		capsCopy[k] = v
	}
	return Hello{
		PeerID:       kp.PeerID().String(),
		PublicKey:    append([]byte(nil), kp.PublicKey...),
		TimestampSec: time.Now().Unix(),
		Nonce:        nonce,
		Capabilities: capsCopy,
	}, nil
}

func (h Hello) SigningBytes() ([]byte, error) {
	if len(h.PublicKey) != ed25519.PublicKeySize {
		return nil, ErrHelloMissingKey
	}
	id, err := identity.ParsePeerIDHex(h.PeerID)
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	b.Write(id[:])
	b.Write(h.PublicKey)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(h.TimestampSec))
	b.Write(ts[:])
	b.Write(h.Nonce)

	keys := make([]string, 0, len(h.Capabilities))
	for k := range h.Capabilities {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := h.Capabilities[k]
		var kl [2]byte
		binary.BigEndian.PutUint16(kl[:], uint16(len(k)))
		b.Write(kl[:])
		b.WriteString(k)
		var vl [2]byte
		binary.BigEndian.PutUint16(vl[:], uint16(len(v)))
		b.Write(vl[:])
		b.WriteString(v)
	}
	return b.Bytes(), nil
}

func (h *Hello) Sign(kp identity.KeyPair) error {
	toSign, err := h.SigningBytes()
	if err != nil {
		return err
	}
	h.Signature = kp.Sign(toSign)
	return nil
}

func (h Hello) Verify() error {
	if len(h.PublicKey) != ed25519.PublicKeySize {
		return ErrHelloMissingKey
	}
	derived := identity.PeerIDFromPublicKey(h.PublicKey)
	claimed, err := identity.ParsePeerIDHex(h.PeerID)
	if err != nil {
		return err
	}
	if derived != claimed {
		return ErrHelloPeerIDMismatch
	}
	toVerify, err := h.SigningBytes()
	if err != nil {
		return err
	}
	if !identity.Verify(ed25519.PublicKey(h.PublicKey), toVerify, h.Signature) {
		return ErrHelloBadSignature
	}
	return nil
}

func EncodeHello(h Hello) ([]byte, error) {
	return json.Marshal(h)
}

func DecodeHello(b []byte) (Hello, error) {
	var h Hello
	if err := json.Unmarshal(b, &h); err != nil {
		return Hello{}, err
	}
	if h.PeerID == "" {
		return Hello{}, fmt.Errorf("hello missing peer_id")
	}
	return h, nil
}
