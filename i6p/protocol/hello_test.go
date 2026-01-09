package protocol

import (
	"testing"

	"github.com/TheusHen/I6P/i6p/identity"
)

func TestHelloSignAndVerify(t *testing.T) {
	kp, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	hello, err := NewHello(kp, map[string]string{"version": "1.0", "feature": "bulk"})
	if err != nil {
		t.Fatalf("NewHello: %v", err)
	}

	if err := hello.Sign(kp); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if len(hello.Signature) == 0 {
		t.Fatalf("expected signature")
	}

	// Verify
	if err := hello.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Encode/decode round trip
	encoded, err := EncodeHello(hello)
	if err != nil {
		t.Fatalf("EncodeHello: %v", err)
	}

	decoded, err := DecodeHello(encoded)
	if err != nil {
		t.Fatalf("DecodeHello: %v", err)
	}

	if err := decoded.Verify(); err != nil {
		t.Fatalf("Verify after decode: %v", err)
	}

	if decoded.PeerID != hello.PeerID {
		t.Fatalf("PeerID mismatch")
	}
	if decoded.Capabilities["version"] != "1.0" {
		t.Fatalf("capabilities mismatch")
	}
}

func TestHelloVerifyFailures(t *testing.T) {
	kp, _ := identity.GenerateKeyPair()
	hello, _ := NewHello(kp, nil)
	_ = hello.Sign(kp)

	// Tamper with signature
	tampered := hello
	tampered.Signature[0] ^= 0xff
	if err := tampered.Verify(); err != ErrHelloBadSignature {
		t.Fatalf("expected ErrHelloBadSignature, got %v", err)
	}

	// Wrong PeerID
	kp2, _ := identity.GenerateKeyPair()
	hello2, _ := NewHello(kp, nil)
	hello2.PeerID = kp2.PeerID().String() // wrong ID
	_ = hello2.Sign(kp)
	if err := hello2.Verify(); err != ErrHelloPeerIDMismatch {
		t.Fatalf("expected ErrHelloPeerIDMismatch, got %v", err)
	}
}
