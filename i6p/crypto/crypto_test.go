package crypto

import (
	"bytes"
	"testing"
)

func TestX25519ECDH(t *testing.T) {
	alice, err := GenerateX25519()
	if err != nil {
		t.Fatalf("GenerateX25519: %v", err)
	}
	bob, err := GenerateX25519()
	if err != nil {
		t.Fatalf("GenerateX25519: %v", err)
	}

	sharedAlice, err := ECDH(alice.PrivateKey, bob.PublicKey)
	if err != nil {
		t.Fatalf("ECDH alice: %v", err)
	}
	sharedBob, err := ECDH(bob.PrivateKey, alice.PublicKey)
	if err != nil {
		t.Fatalf("ECDH bob: %v", err)
	}

	if !bytes.Equal(sharedAlice, sharedBob) {
		t.Fatalf("shared secrets do not match")
	}
}

func TestAEADRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	aead, err := NewAEAD(key)
	if err != nil {
		t.Fatalf("NewAEAD: %v", err)
	}

	plaintext := []byte("hello i6p secure channel")
	ad := []byte("additional data")

	ciphertext := aead.Seal(plaintext, ad)
	if len(ciphertext) != len(plaintext)+aead.NonceSize()+aead.Overhead() {
		t.Fatalf("unexpected ciphertext length")
	}

	decrypted, err := aead.Open(ciphertext, ad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted != plaintext")
	}

	// Tamper with ciphertext
	ciphertext[len(ciphertext)-1] ^= 0xff
	_, err = aead.Open(ciphertext, ad)
	if err != ErrDecryptionFailed {
		t.Fatalf("expected decryption failure on tampered ciphertext")
	}
}

func TestDeriveSessionKeys(t *testing.T) {
	alice, _ := GenerateX25519()
	bob, _ := GenerateX25519()
	shared, _ := ECDH(alice.PrivateKey, bob.PublicKey)

	k1, k2, err := DeriveSessionKeys(shared, alice.PublicKey, bob.PublicKey)
	if err != nil {
		t.Fatalf("DeriveSessionKeys: %v", err)
	}
	if len(k1) != 32 || len(k2) != 32 {
		t.Fatalf("unexpected key lengths")
	}
	if bytes.Equal(k1, k2) {
		t.Fatalf("initiator and responder keys should differ")
	}
}

func BenchmarkAEADSeal(b *testing.B) {
	key := make([]byte, 32)
	aead, _ := NewAEAD(key)
	plaintext := make([]byte, 64*1024) // 64 KB
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = aead.Seal(plaintext, nil)
	}
}

func BenchmarkAEADOpen(b *testing.B) {
	key := make([]byte, 32)
	aead, _ := NewAEAD(key)
	plaintext := make([]byte, 64*1024)
	ciphertext := aead.Seal(plaintext, nil)
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = aead.Open(ciphertext, nil)
	}
}
