package main

import (
	"fmt"
	"log"

	"github.com/TheusHen/I6P/i6p/crypto"
)

func main() {
	log.Println("=== I6P Secure Channel Demo ===")
	log.Println("Demonstrating X25519 key exchange + ChaCha20-Poly1305 + symmetric ratchet")
	fmt.Println()

	// Create secure channels for both parties
	alice, err := crypto.NewSecureChannelInitiator()
	if err != nil {
		log.Fatalf("alice: %v", err)
	}

	bob, err := crypto.NewSecureChannelResponder()
	if err != nil {
		log.Fatalf("bob: %v", err)
	}

	log.Println("1. Ephemeral X25519 keys generated")
	alicePub := alice.LocalEphemeralPublic()
	bobPub := bob.LocalEphemeralPublic()
	log.Printf("   Alice public: %x...", alicePub[:8])
	log.Printf("   Bob public:   %x...", bobPub[:8])

	// Exchange public keys (in real usage, sent over the wire)
	if err := alice.Complete(bob.LocalEphemeralPublic()); err != nil {
		log.Fatalf("alice complete: %v", err)
	}
	if err := bob.Complete(alice.LocalEphemeralPublic()); err != nil {
		log.Fatalf("bob complete: %v", err)
	}

	log.Println("2. Key exchange complete, channels established")
	fmt.Println()

	// Demonstrate forward secrecy - each message uses a new key
	messages := []string{
		"Hello Bob, this is Alice!",
		"The weather is nice today.",
		"Let's exchange some files over I6P!",
	}

	log.Println("3. Alice sends messages to Bob:")
	for i, msg := range messages {
		ct, err := alice.Encrypt([]byte(msg), nil)
		if err != nil {
			log.Fatalf("encrypt: %v", err)
		}

		pt, err := bob.Decrypt(ct, nil)
		if err != nil {
			log.Fatalf("decrypt: %v", err)
		}

		log.Printf("   [%d] \"%s\"", i, string(pt))
		log.Printf("       Ciphertext size: %d bytes (plaintext: %d)", len(ct), len(msg))
	}
	fmt.Println()

	log.Println("4. Bob replies to Alice:")
	reply := "Got your messages, Alice! Ready for file transfer."
	ct, _ := bob.Encrypt([]byte(reply), nil)
	pt, _ := alice.Decrypt(ct, nil)
	log.Printf("   \"%s\"", string(pt))
	fmt.Println()

	// Demonstrate out-of-order decryption
	log.Println("5. Demonstrating out-of-order message handling:")
	ct1, _ := alice.Encrypt([]byte("Message 1"), nil)
	ct2, _ := alice.Encrypt([]byte("Message 2"), nil)
	ct3, _ := alice.Encrypt([]byte("Message 3"), nil)

	// Decrypt in reverse order
	pt3, _ := bob.Decrypt(ct3, nil)
	pt1, _ := bob.Decrypt(ct1, nil)
	pt2, _ := bob.Decrypt(ct2, nil)

	log.Printf("   Received (out of order): %s, %s, %s", pt3, pt1, pt2)
	fmt.Println()

	log.Printf("6. Send generation counter: %d", alice.SendGeneration())
	log.Println("   (Each generation uses a unique derived key for forward secrecy)")

	fmt.Println()
	log.Println("=== Summary ===")
	log.Println("✓ X25519 ECDH key exchange (Curve25519)")
	log.Println("✓ ChaCha20-Poly1305 AEAD encryption")
	log.Println("✓ HKDF-SHA256 key derivation")
	log.Println("✓ Symmetric key ratchet for forward secrecy")
	log.Println("✓ Out-of-order message support")
}
