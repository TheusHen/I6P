# I6P — IPv6 Peer-to-Peer Protocol (Go)

I6P is a **high-performance**, **IPv6-only** P2P connectivity and transport layer. It is **not** a torrent client—it provides the foundation upon which P2P applications can be built.

## 🚀 Key Differentiators

| Feature | Benefit |
|---------|---------|
| **IPv6-only** | End-to-end connectivity, no NAT traversal complexity |
| **X25519 + ChaCha20-Poly1305** | Fast, constant-time crypto without AES-NI |
| **Symmetric Key Ratchet** | Continuous forward secrecy per-message |
| **LZ4 Compression** | ~4 GB/s compression speed on commodity CPUs |
| **Merkle Tree Integrity** | Verifiable chunks, resumable transfers |
| **Reed-Solomon Erasure Coding** | Recover lost packets without retransmission |
| **Parallel Stream Pool** | Saturate high-bandwidth links via QUIC multiplexing |
| **Session Tickets** | 0-RTT resumption for returning peers |
| **Batch Transmission** | Reduced syscall overhead, efficient batching |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Application Layer                        │
├─────────────────────────────────────────────────────────────────┤
│  transfer/  │  Chunker, Merkle, LZ4, Batching, Erasure, Pool    │
├─────────────────────────────────────────────────────────────────┤
│  session/   │  Handshake, Session, Tickets (0-RTT resumption)   │
├─────────────────────────────────────────────────────────────────┤
│  crypto/    │  X25519 ECDH, ChaCha20-Poly1305, HKDF, Ratchet    │
├─────────────────────────────────────────────────────────────────┤
│  protocol/  │  HELLO, PEER_INFO, DATA, ACK, CLOSE               │
├─────────────────────────────────────────────────────────────────┤
│  identity/  │  Ed25519 keys, PeerID = SHA-256(PublicKey)        │
├─────────────────────────────────────────────────────────────────┤
│  transport/ │  QUIC over UDP, TLS 1.3                           │
├─────────────────────────────────────────────────────────────────┤
│  discovery/ │  Pluggable (memory, DHT, mDNS)                    │
└─────────────────────────────────────────────────────────────────┘
```

## Packages

| Package | Description |
|---------|-------------|
| `i6p/identity` | Ed25519 keys, PeerID, signing |
| `i6p/protocol` | Wire protocol, HELLO message, codec |
| `i6p/crypto` | X25519, ChaCha20-Poly1305 AEAD, HKDF |
| `i6p/crypto/ratchet` | Symmetric key ratchet for forward secrecy |
| `i6p/session` | Handshake, session management, tickets |
| `i6p/transport/quic` | QUIC transport with TLS 1.3 |
| `i6p/transfer` | Chunking, Merkle trees, LZ4, batching, parallel streams |
| `i6p/transfer/erasure` | Reed-Solomon erasure coding |
| `i6p/discovery` | Discovery interfaces |
| `i6p/discovery/memory` | In-memory discovery (tests/examples) |

## Quick Start

```bash
# Run tests
go test ./...

# Run benchmarks
go test -bench=. ./...

# Run example
go run ./examples/basic
```

## Performance

I6P is designed to maximize throughput on modern hardware:

- **ChaCha20-Poly1305**: ~3-5 GB/s encryption on modern CPUs
- **LZ4 Compression**: ~4 GB/s compression, ~8 GB/s decompression
- **Reed-Solomon**: Efficient SIMD-accelerated implementation
- **Parallel Streams**: Configurable stream pool to saturate bandwidth
- **Zero-Copy Batching**: Minimized memory allocations

## Security Model

1. **Transport Security**: QUIC provides TLS 1.3 encryption
2. **Identity Binding**: Session handshake verifies `PeerID = SHA-256(Ed25519_PublicKey)`
3. **Forward Secrecy**: Ephemeral X25519 key exchange + symmetric ratchet
4. **Integrity**: Merkle proofs for every chunk
5. **Session Resumption**: Encrypted tickets for 0-RTT reconnection

## Why I6P?

| Traditional P2P | I6P |
|-----------------|-----|
| IPv4 + NAT traversal | IPv6 end-to-end |
| STUN/TURN/UPnP required | Direct connectivity |
| Complex hole punching | Globally routable addresses |
| Identity tied to IP | Cryptographic identity |
| Single stream | Parallel multiplexed streams |
| No erasure coding | Built-in loss recovery |

## Status

Production-ready baseline implementation. The discovery layer is intentionally modular; deployments will typically use DHT and/or mDNS.

## License

MIT

