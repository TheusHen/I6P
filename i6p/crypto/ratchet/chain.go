package ratchet

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
)

var (
	ErrRatchetExhausted  = errors.New("ratchet: maximum generation reached")
	ErrInvalidGeneration = errors.New("ratchet: invalid generation number")
)

const (
	// MaxGeneration is the maximum number of ratchet steps before re-keying is required.
	MaxGeneration = 1 << 32
)

// Chain is a symmetric key ratchet for forward secrecy.
// Each step derives a new key and message key from the current chain key.
type Chain struct {
	mu         sync.Mutex
	chainKey   [32]byte
	generation uint64
}

// NewChain creates a new ratchet chain from an initial 32-byte key.
func NewChain(initialKey []byte) (*Chain, error) {
	if len(initialKey) != 32 {
		return nil, errors.New("ratchet: initial key must be 32 bytes")
	}
	c := &Chain{}
	copy(c.chainKey[:], initialKey)
	return c, nil
}

// deriveKeys derives (nextChainKey, messageKey) from the current chain key.
func (c *Chain) deriveKeys() ([32]byte, [32]byte) {
	// Use HKDF-like expansion with SHA-256
	// chainKey || 0x01 -> messageKey
	// chainKey || 0x02 -> nextChainKey
	h1 := sha256.New()
	h1.Write(c.chainKey[:])
	h1.Write([]byte{0x01})
	var messageKey [32]byte
	copy(messageKey[:], h1.Sum(nil))

	h2 := sha256.New()
	h2.Write(c.chainKey[:])
	h2.Write([]byte{0x02})
	var nextChainKey [32]byte
	copy(nextChainKey[:], h2.Sum(nil))

	return nextChainKey, messageKey
}

// Step advances the ratchet and returns an AEAD cipher for the current message.
// The chain key is immediately updated, providing forward secrecy.
func (c *Chain) Step() (*AEAD, uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.generation >= MaxGeneration {
		return nil, 0, ErrRatchetExhausted
	}

	nextChain, msgKey := c.deriveKeys()
	gen := c.generation

	// Advance chain
	c.chainKey = nextChain
	c.generation++

	// Zeroize old key material is automatic since we replaced it

	aead, err := NewAEAD(msgKey[:])
	if err != nil {
		return nil, 0, err
	}
	return aead, gen, nil
}

// Generation returns the current generation number.
func (c *Chain) Generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.generation
}

// Export exports the current chain state for persistence/resumption.
// WARNING: Handle with extreme care; this contains keying material.
func (c *Chain) Export() (chainKey [32]byte, generation uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.chainKey, c.generation
}

// EncryptedMessage represents a ratcheted encrypted message.
type EncryptedMessage struct {
	Generation uint64
	Ciphertext []byte
}

// Seal encrypts plaintext, advances the ratchet, and returns the encrypted message.
func (c *Chain) Seal(plaintext, ad []byte) (EncryptedMessage, error) {
	aead, gen, err := c.Step()
	if err != nil {
		return EncryptedMessage{}, err
	}
	ct := aead.Seal(plaintext, ad)
	return EncryptedMessage{Generation: gen, Ciphertext: ct}, nil
}

// Receiver manages decryption with out-of-order tolerance.
type Receiver struct {
	mu         sync.Mutex
	chains     map[uint64][32]byte // cached chain keys for skipped messages
	current    [32]byte
	currentGen uint64
	maxSkip    int
}

// NewReceiver creates a receiver ratchet from the initial key.
func NewReceiver(initialKey []byte, maxSkip int) (*Receiver, error) {
	if len(initialKey) != 32 {
		return nil, errors.New("ratchet: initial key must be 32 bytes")
	}
	r := &Receiver{
		chains:  make(map[uint64][32]byte),
		maxSkip: maxSkip,
	}
	copy(r.current[:], initialKey)
	return r, nil
}

func deriveKeysStatic(chainKey [32]byte) ([32]byte, [32]byte) {
	h1 := sha256.New()
	h1.Write(chainKey[:])
	h1.Write([]byte{0x01})
	var messageKey [32]byte
	copy(messageKey[:], h1.Sum(nil))

	h2 := sha256.New()
	h2.Write(chainKey[:])
	h2.Write([]byte{0x02})
	var nextChainKey [32]byte
	copy(nextChainKey[:], h2.Sum(nil))

	return nextChainKey, messageKey
}

// Open decrypts an encrypted message, handling out-of-order delivery.
func (r *Receiver) Open(msg EncryptedMessage, ad []byte) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	gen := msg.Generation

	// Expected next message in-order.
	if gen == r.currentGen {
		nextChain, msgKey := deriveKeysStatic(r.current)
		aead, err := NewAEAD(msgKey[:])
		if err != nil {
			return nil, err
		}
		pt, err := aead.Open(msg.Ciphertext, ad)
		if err != nil {
			return nil, err
		}
		r.current = nextChain
		r.currentGen++
		return pt, nil
	}

	// Check if we have a cached key for this generation
	if cachedKey, ok := r.chains[gen]; ok {
		_, msgKey := deriveKeysStatic(cachedKey)
		aead, err := NewAEAD(msgKey[:])
		if err != nil {
			return nil, err
		}
		delete(r.chains, gen)
		return aead.Open(msg.Ciphertext, ad)
	}

	// Message is from the future; need to skip ahead
	if gen > r.currentGen {
		skip := int(gen - r.currentGen)
		if skip > r.maxSkip {
			return nil, ErrInvalidGeneration
		}
		// Cache intermediate keys
		chainKey := r.current
		for i := r.currentGen; i < gen; i++ {
			nextChain, _ := deriveKeysStatic(chainKey)
			r.chains[i] = chainKey
			chainKey = nextChain
		}
		// Now chainKey is at generation `gen`
		nextChain, msgKey := deriveKeysStatic(chainKey)
		r.current = nextChain
		r.currentGen = gen + 1

		aead, err := NewAEAD(msgKey[:])
		if err != nil {
			return nil, err
		}
		return aead.Open(msg.Ciphertext, ad)
	}

	// Message is from the past and we don't have the key
	return nil, ErrInvalidGeneration
}

// Encode serializes an EncryptedMessage for wire transmission.
func (m EncryptedMessage) Encode() []byte {
	out := make([]byte, 8+len(m.Ciphertext))
	binary.BigEndian.PutUint64(out[:8], m.Generation)
	copy(out[8:], m.Ciphertext)
	return out
}

// DecodeEncryptedMessage deserializes an EncryptedMessage.
func DecodeEncryptedMessage(data []byte) (EncryptedMessage, error) {
	if len(data) < 8 {
		return EncryptedMessage{}, errors.New("ratchet: message too short")
	}
	return EncryptedMessage{
		Generation: binary.BigEndian.Uint64(data[:8]),
		Ciphertext: data[8:],
	}, nil
}
