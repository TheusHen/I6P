package ratchet

import (
	"bytes"
	"testing"
)

func TestChainRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	sender, err := NewChain(key)
	if err != nil {
		t.Fatalf("NewChain sender: %v", err)
	}
	receiver, err := NewReceiver(key, 100)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}

	messages := [][]byte{
		[]byte("message 0"),
		[]byte("message 1"),
		[]byte("message 2"),
	}

	var encrypted []EncryptedMessage
	for _, m := range messages {
		em, err := sender.Seal(m, nil)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		encrypted = append(encrypted, em)
	}

	// Decrypt in order
	for i, em := range encrypted {
		pt, err := receiver.Open(em, nil)
		if err != nil {
			t.Fatalf("Open %d: %v", i, err)
		}
		if !bytes.Equal(pt, messages[i]) {
			t.Fatalf("message %d mismatch", i)
		}
	}
}

func TestChainOutOfOrder(t *testing.T) {
	key := make([]byte, 32)
	sender, _ := NewChain(key)
	receiver, _ := NewReceiver(key, 100)

	em0, _ := sender.Seal([]byte("m0"), nil)
	em1, _ := sender.Seal([]byte("m1"), nil)
	em2, _ := sender.Seal([]byte("m2"), nil)

	// Receive out of order: 2, 0, 1
	pt2, err := receiver.Open(em2, nil)
	if err != nil {
		t.Fatalf("Open em2: %v", err)
	}
	if string(pt2) != "m2" {
		t.Fatalf("em2 mismatch")
	}

	pt0, err := receiver.Open(em0, nil)
	if err != nil {
		t.Fatalf("Open em0: %v", err)
	}
	if string(pt0) != "m0" {
		t.Fatalf("em0 mismatch")
	}

	pt1, err := receiver.Open(em1, nil)
	if err != nil {
		t.Fatalf("Open em1: %v", err)
	}
	if string(pt1) != "m1" {
		t.Fatalf("em1 mismatch")
	}
}

func TestEncodeDecodeMessage(t *testing.T) {
	em := EncryptedMessage{Generation: 42, Ciphertext: []byte("hello")}
	encoded := em.Encode()
	decoded, err := DecodeEncryptedMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeEncryptedMessage: %v", err)
	}
	if decoded.Generation != em.Generation {
		t.Fatalf("generation mismatch")
	}
	if !bytes.Equal(decoded.Ciphertext, em.Ciphertext) {
		t.Fatalf("ciphertext mismatch")
	}
}

func BenchmarkChainSeal(b *testing.B) {
	key := make([]byte, 32)
	chain, _ := NewChain(key)
	msg := make([]byte, 1024)
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = chain.Seal(msg, nil)
	}
}
