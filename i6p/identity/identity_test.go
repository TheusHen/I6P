package identity

import (
	"bytes"
	"testing"
)

func TestPeerIDDerivationStable(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	id1 := kp.PeerID()
	id2 := PeerIDFromPublicKey(kp.PublicKey)
	if id1 != id2 {
		t.Fatalf("PeerID mismatch")
	}

	parsed, err := ParsePeerIDHex(id1.String())
	if err != nil {
		t.Fatalf("ParsePeerIDHex: %v", err)
	}
	if parsed != id1 {
		t.Fatalf("ParsePeerIDHex mismatch")
	}
}

func TestSignVerify(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	msg := []byte("hello")
	sig := kp.Sign(msg)
	if len(sig) == 0 {
		t.Fatalf("expected signature")
	}
	if !Verify(kp.PublicKey, msg, sig) {
		t.Fatalf("signature verification failed")
	}
	if Verify(kp.PublicKey, []byte("tampered"), sig) {
		t.Fatalf("expected verification to fail for tampered message")
	}

	kp2, _ := GenerateKeyPair()
	if Verify(kp2.PublicKey, msg, sig) {
		t.Fatalf("expected verification to fail with different public key")
	}

	// signature bytes are not expected to be all zero
	if bytes.Equal(sig, make([]byte, len(sig))) {
		t.Fatalf("unexpected zeroed signature")
	}
}
