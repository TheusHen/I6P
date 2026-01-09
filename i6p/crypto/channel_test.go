package crypto

import (
	"bytes"
	"testing"
)

func TestSecureChannelRoundTrip(t *testing.T) {
	initiator, err := NewSecureChannelInitiator()
	if err != nil {
		t.Fatalf("NewSecureChannelInitiator: %v", err)
	}

	responder, err := NewSecureChannelResponder()
	if err != nil {
		t.Fatalf("NewSecureChannelResponder: %v", err)
	}

	// Exchange ephemeral keys
	if err := initiator.Complete(responder.LocalEphemeralPublic()); err != nil {
		t.Fatalf("initiator.Complete: %v", err)
	}
	if err := responder.Complete(initiator.LocalEphemeralPublic()); err != nil {
		t.Fatalf("responder.Complete: %v", err)
	}

	// Test bidirectional encryption
	messages := [][]byte{
		[]byte("hello from initiator"),
		[]byte("hello from responder"),
		[]byte("another message"),
	}

	// Initiator -> Responder
	for _, msg := range messages {
		ct, err := initiator.Encrypt(msg, nil)
		if err != nil {
			t.Fatalf("initiator.Encrypt: %v", err)
		}
		pt, err := responder.Decrypt(ct, nil)
		if err != nil {
			t.Fatalf("responder.Decrypt: %v", err)
		}
		if !bytes.Equal(pt, msg) {
			t.Fatalf("message mismatch")
		}
	}

	// Responder -> Initiator
	for _, msg := range messages {
		ct, err := responder.Encrypt(msg, nil)
		if err != nil {
			t.Fatalf("responder.Encrypt: %v", err)
		}
		pt, err := initiator.Decrypt(ct, nil)
		if err != nil {
			t.Fatalf("initiator.Decrypt: %v", err)
		}
		if !bytes.Equal(pt, msg) {
			t.Fatalf("message mismatch")
		}
	}
}

func TestSecureChannelOutOfOrder(t *testing.T) {
	initiator, _ := NewSecureChannelInitiator()
	responder, _ := NewSecureChannelResponder()

	_ = initiator.Complete(responder.LocalEphemeralPublic())
	_ = responder.Complete(initiator.LocalEphemeralPublic())

	// Encrypt multiple messages
	ct0, _ := initiator.Encrypt([]byte("msg0"), nil)
	ct1, _ := initiator.Encrypt([]byte("msg1"), nil)
	ct2, _ := initiator.Encrypt([]byte("msg2"), nil)

	// Decrypt out of order
	pt2, err := responder.Decrypt(ct2, nil)
	if err != nil {
		t.Fatalf("Decrypt ct2: %v", err)
	}
	if string(pt2) != "msg2" {
		t.Fatalf("expected msg2")
	}

	pt0, err := responder.Decrypt(ct0, nil)
	if err != nil {
		t.Fatalf("Decrypt ct0: %v", err)
	}
	if string(pt0) != "msg0" {
		t.Fatalf("expected msg0")
	}

	pt1, err := responder.Decrypt(ct1, nil)
	if err != nil {
		t.Fatalf("Decrypt ct1: %v", err)
	}
	if string(pt1) != "msg1" {
		t.Fatalf("expected msg1")
	}
}

func BenchmarkSecureChannelEncrypt(b *testing.B) {
	initiator, _ := NewSecureChannelInitiator()
	responder, _ := NewSecureChannelResponder()
	_ = initiator.Complete(responder.LocalEphemeralPublic())
	_ = responder.Complete(initiator.LocalEphemeralPublic())

	msg := make([]byte, 1024)
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = initiator.Encrypt(msg, nil)
	}
}

func BenchmarkSecureChannelDecrypt(b *testing.B) {
	initiator, _ := NewSecureChannelInitiator()
	responder, _ := NewSecureChannelResponder()
	_ = initiator.Complete(responder.LocalEphemeralPublic())
	_ = responder.Complete(initiator.LocalEphemeralPublic())

	msg := make([]byte, 1024)
	var ciphertexts [][]byte
	for i := 0; i < b.N; i++ {
		ct, _ := initiator.Encrypt(msg, nil)
		ciphertexts = append(ciphertexts, ct)
	}

	b.SetBytes(int64(len(msg)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = responder.Decrypt(ciphertexts[i], nil)
	}
}
