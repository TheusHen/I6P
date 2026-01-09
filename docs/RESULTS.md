# I6P — Results achieved (Go)

This document summarizes, in an objective manner, what has already been implemented and validated in the repository.

## Quality status

- Unit tests covering the main packages (`go test ./...` passing)
- Executable examples in `examples/`
- CI in GitHub Actions with formatting, testing, vulnerability checking, and lint

## Main deliverables (differentiators)

### Identity and authentication

- Cryptographic identity based on Ed25519
- `PeerID = SHA-256(PublicKey)`
- Handshake that **links** session to identity via signed `HELLO` exchange

### Transport and session

- Transport over QUIC/TLS 1.3 (via `quic-go`)
- Session authenticated by `HELLO` (control in dedicated stream)

### Cryptography (fast and strong)

- X25519 (ECDH) + HKDF-SHA256 for key derivation
- ChaCha20-Poly1305 as AEAD
- Symmetric ratchet per message (continuous forward secrecy)
- Reference SecureChannel (initiator/responder) with out-of-order support

### Bulk sending

- Chunking with hash per chunk
- Integrity via Merkle tree (root as commitment)
- LZ4 compression
- Batching to reduce syscall overhead
- Pool of parallel streams to saturate bandwidth
- Reed-Solomon erasure coding (optional) for loss resilience

### Session reuse

- Ticket store with issuance/validation and encrypted ticket encoding (basis for resumption)

## Artifacts (where everything is)

- High-level API (peer): `i6p/peer.go`
- Identity: `i6p/identity/`
- Protocol: `i6p/protocol/`
- Session/Handshake: `i6p/session/`
- Crypto + ratchet: `i6p/crypto/` and `i6p/crypto/ratchet/`
- Transfer/bulk: `i6p/transfer/` and `i6p/transfer/erasure/`
- Examples: `examples/`

## Recommended next step

- Formalize and freeze a minimal public API (interfaces), decoupling the application from QUIC details.
- Formal documentation of the handshake, messages, states, and API: see `docs/SPEC.md`.