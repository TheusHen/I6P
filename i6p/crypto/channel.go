package crypto

import (
	"errors"
	"sync"

	"github.com/TheusHen/I6P/i6p/crypto/ratchet"
)

var (
	ErrChannelNotEstablished = errors.New("crypto: secure channel not established")
)

// SecureChannel provides an end-to-end encrypted channel with forward secrecy.
// It combines X25519 key exchange with symmetric key ratcheting.
type SecureChannel struct {
	mu           sync.Mutex
	established  bool
	isInitiator  bool
	localEph     X25519KeyPair
	remoteEphPub [32]byte
	sendChain    *ratchet.Chain
	recvChain    *ratchet.Receiver
}

// NewSecureChannelInitiator creates a channel as the initiating party.
func NewSecureChannelInitiator() (*SecureChannel, error) {
	eph, err := GenerateX25519()
	if err != nil {
		return nil, err
	}
	return &SecureChannel{
		isInitiator: true,
		localEph:    eph,
	}, nil
}

// NewSecureChannelResponder creates a channel as the responding party.
func NewSecureChannelResponder() (*SecureChannel, error) {
	eph, err := GenerateX25519()
	if err != nil {
		return nil, err
	}
	return &SecureChannel{
		isInitiator: false,
		localEph:    eph,
	}, nil
}

// LocalEphemeralPublic returns the local ephemeral public key (to send to peer).
func (sc *SecureChannel) LocalEphemeralPublic() [32]byte {
	return sc.localEph.PublicKey
}

// Complete completes the key exchange with the peer's ephemeral public key.
func (sc *SecureChannel) Complete(peerEphPub [32]byte) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.established {
		return nil
	}

	sc.remoteEphPub = peerEphPub

	// Compute shared secret
	shared, err := ECDH(sc.localEph.PrivateKey, peerEphPub)
	if err != nil {
		return err
	}

	// Derive session keys
	var initiatorPub, responderPub [32]byte
	if sc.isInitiator {
		initiatorPub = sc.localEph.PublicKey
		responderPub = peerEphPub
	} else {
		initiatorPub = peerEphPub
		responderPub = sc.localEph.PublicKey
	}

	sendKey, recvKey, err := DeriveSessionKeys(shared, initiatorPub, responderPub)
	if err != nil {
		return err
	}

	// Initiator sends with initiatorKey, receives with responderKey
	// Responder sends with responderKey, receives with initiatorKey
	var myKey, theirKey []byte
	if sc.isInitiator {
		myKey = sendKey
		theirKey = recvKey
	} else {
		myKey = recvKey
		theirKey = sendKey
	}

	sc.sendChain, err = ratchet.NewChain(myKey)
	if err != nil {
		return err
	}

	sc.recvChain, err = ratchet.NewReceiver(theirKey, 1000) // allow up to 1000 out-of-order
	if err != nil {
		return err
	}

	sc.established = true
	return nil
}

// IsEstablished returns true if the channel is ready for use.
func (sc *SecureChannel) IsEstablished() bool {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.established
}

// Encrypt encrypts a message with forward secrecy.
func (sc *SecureChannel) Encrypt(plaintext, ad []byte) ([]byte, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if !sc.established {
		return nil, ErrChannelNotEstablished
	}

	msg, err := sc.sendChain.Seal(plaintext, ad)
	if err != nil {
		return nil, err
	}
	return msg.Encode(), nil
}

// Decrypt decrypts a message.
func (sc *SecureChannel) Decrypt(ciphertext, ad []byte) ([]byte, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if !sc.established {
		return nil, ErrChannelNotEstablished
	}

	msg, err := ratchet.DecodeEncryptedMessage(ciphertext)
	if err != nil {
		return nil, err
	}
	return sc.recvChain.Open(msg, ad)
}

// SendGeneration returns the current send generation.
func (sc *SecureChannel) SendGeneration() uint64 {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.sendChain == nil {
		return 0
	}
	return sc.sendChain.Generation()
}
