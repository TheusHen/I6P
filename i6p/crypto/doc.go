// Package crypto provides high-performance cryptographic primitives for I6P.
//
// Design goals:
//   - Fast on commodity hardware (no AES-NI required)
//   - Forward secrecy via ephemeral X25519 key exchange
//   - AEAD encryption via ChaCha20-Poly1305 (RFC 8439)
//   - Key derivation via HKDF-SHA256
//   - Constant-time operations where applicable
package crypto
