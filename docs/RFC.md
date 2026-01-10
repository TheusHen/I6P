# RFC: I6P — IPv6 Peer-to-Peer Transport and Session Protocol

**Status:** Informational draft, implementation reference for `github.com/TheusHen/I6P`  
**Intended audience:** Implementers of interoperable I6P nodes and reviewers of the reference Go implementation.

## 1. Abstract

I6P is an **IPv6-only**, high-performance peer-to-peer transport that layers an authenticated control channel on top of QUIC/TLS 1.3. Identity is bound to Ed25519 public keys, while application data is exchanged over multiplexed QUIC streams and may additionally use an end-to-end secure channel with forward secrecy. This document normatively defines the wire formats, handshake, state machines, integrity, and transfer mechanisms that constitute the I6P protocol surface.

## 2. Conventions and Terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in RFC 2119.

- **Node**: Local process that can `Listen` and/or `Dial`.
- **Peer**: Remote entity identified by a `PeerID`.
- **PeerID**: `SHA-256(Ed25519_PublicKey)` (32 bytes).
- **Session**: Authenticated, multiplexed QUIC connection between two peers.
- **Control stream**: Dedicated QUIC stream reserved for protocol control frames.
- **Application stream**: QUIC stream used for data transfer after authentication.

## 3. Goals and Non-Goals

- **Goals:** Low-latency authenticated connectivity over IPv6, predictable forward secrecy, resumable bulk transfers with integrity and loss recovery, and a small, stable API surface.
- **Non-Goals:** NAT traversal (IPv6 is required), PKI-based identity (identity is self-certifying), and application-level semantics (I6P is a transport substrate).

## 4. Transport Requirements

- I6P nodes **MUST** operate over IPv6. IPv4 is out of scope.
- QUIC (TLS 1.3) is the transport substrate. ALPN **MUST** be set to `i6p/1`.
- TLS certificates are self-signed; peer authentication happens at the session layer (HELLO signature). `InsecureSkipVerify` at TLS is therefore permitted.
- A dedicated **control stream** **MUST** be opened by the initiator and is reserved for protocol frames only.

## 5. Identities and Cryptography

### 5.1 Identity

- Long-term identity keys are Ed25519. Public keys are 32 bytes.
- `PeerID = SHA-256(publicKey)`; peers **MUST** verify this binding during handshake.
- Keys are encoded as raw bytes on the wire; `PeerID` is hex-encoded in HELLO payloads.

### 5.2 Transport Confidentiality

QUIC/TLS 1.3 provides hop-to-hop confidentiality and integrity for all streams, including the control stream.

### 5.3 Optional End-to-End Secure Channel

- Ephemeral X25519 key exchange derives two traffic keys via HKDF-SHA256.
- Traffic keys feed a symmetric ratchet using ChaCha20-Poly1305 AEAD with a maximum out-of-order tolerance of **1000** messages **per receive chain**. Each receive chain tracks monotonically increasing generation numbers; the receiver remembers the highest accepted generation and accepts ciphertexts whose generation lies within `[highest-1000, highest]`. Accepting a new message advances `highest` and slides the window; ciphertexts outside the window fail decryption and are discarded.
- Initiators send with the initiator-derived key; responders send with the responder-derived key.
- Application data MAY be additionally wrapped with this secure channel using associated data defined by the application.

## 6. Wire Format

### 6.1 Control Frame Container

All control-plane messages are carried inside a `Frame` on the control stream.

- `type` (1 byte) — `MessageType`
- `payload_len` (4 bytes, big-endian)
- `payload` (`payload_len` bytes)

Constraints:

- `payload_len` **MUST NOT** exceed `1,048,576` bytes (`MaxFramePayload = 1 MiB`).
- `type` **MUST** be non-zero. Unknown types **MUST** be ignored after consuming the payload.

### 6.2 Message Types

| Value | Name       | Status      |
|-------|------------|-------------|
| 1     | `HELLO`    | Implemented |
| 2     | `PEER_INFO`| Reserved    |
| 3     | `DATA`     | Reserved    |
| 4     | `ACK`      | Reserved    |
| 5     | `CLOSE`    | Reserved    |

Future message types **SHOULD** maintain backward compatibility and respect the 1 MiB payload limit.

### 6.3 HELLO Payload (JSON)

```jsonc
{
  "peer_id": "hex",            // 64 hex chars of SHA-256(pub)
  "public_key": "base64",      // Ed25519 public key (32 bytes)
  "timestamp_sec": 0,          // int64
  "nonce": "base64",           // 32 random bytes
  "capabilities": { "k": "v" },// optional, string map
  "signature": "base64"        // Ed25519 over SigningBytes()
}
```

Signing bytes (`SigningBytes()`):

1. `PeerID` (32 bytes)
2. `PublicKey` (32 bytes)
3. `TimestampSec` (uint64 big-endian)
4. `Nonce` (32 bytes)
5. `Capabilities` serialized deterministically:
   - Keys sorted lexicographically.
   - For each `(k, v)`: `len(k)` (uint16 BE) + `k` + `len(v)` (uint16 BE) + `v`.

Verification (`Verify()`):

- `len(PublicKey) == 32`
- `PeerIDFromPublicKey(PublicKey) == PeerID`
- `ed25519.Verify(PublicKey, SigningBytes(), Signature) == true`

Peers **SHOULD** reject HELLO messages failing any check. Timestamp and nonce are present to aid replay detection; implementations MAY enforce local freshness policies.

## 7. Handshake

### 7.1 Client (Initiator)

1. Establish QUIC connection with ALPN `i6p/1`.
2. Open control stream.
3. Build local `HELLO`, sign with Ed25519, send as `Frame{Type: HELLO}`.
4. Read a frame from the control stream; it **MUST** be `HELLO`.
5. Decode and `Verify()` the remote `HELLO`.
6. Mark session **ESTABLISHED** with remote `PeerID` and capabilities.

### 7.2 Server (Responder)

1. Accept QUIC connection.
2. Accept control stream (opened by client).
3. Read initial frame; it **MUST** be `HELLO`.
4. Decode and `Verify()` the client's `HELLO`.
5. Send signed server `HELLO` in response on the same control stream.
6. Mark session **ESTABLISHED**.

### 7.3 Failure Behavior

- Invalid frame type or failed verification **MUST** abort the session.
- The control stream **MUST NOT** be used for application data.

## 8. Session Lifecycle

### 8.1 States

- **HANDSHAKING**: Control stream established, HELLO exchange in progress.
- **ESTABLISHED**: Remote identity verified; application streams permitted.
- **CLOSING/CLOSED**: Terminal states triggered by application or errors.

Application streams **MUST NOT** be opened before **ESTABLISHED**. The control stream is reserved for protocol control for the lifetime of the session.

### 8.2 Node States

- **NEW** → `Listen()` → **LISTENING**
- **NEW** → `Dial()` → **DIALING** → **ESTABLISHED**
- **LISTENING**/ **ESTABLISHED** → `Close()` → **CLOSED**

### 8.3 Capabilities

`capabilities` is an optional `map[string]string` advertised in HELLO. Keys **MUST** be unique; receivers **SHOULD** prefer lexicographic ordering when producing signing bytes.

## 9. Session Resumption (Tickets)

- Tickets provide 0-RTT resumption without re-authenticating HELLO.
- Ticket lifetime: **24 hours** (`TicketLifetime`).
- Ticket ID: **16 bytes** random.
- Stored payload (80 bytes): `PeerID (32)` || `IssuedAt (8)` || `ExpiresAt (8)` || `SessionKey (32)`.
- Encoding: AEAD seal with a 32-byte store key (`TicketKeySize`) using the ticket ID as **associated data**. Format: `ticket_id(16)` || `aead_output`, where `aead_output = nonce(12) || ciphertext || tag`. The nonce (4-byte random prefix + 8-byte counter, big-endian) is auto-generated and prepended by `AEAD.Seal`; the ticket ID is not used for nonce derivation.
- Servers **MAY** share the 32-byte store key to enable clustered validation.
- Expired tickets **MUST** be rejected; revoked tickets are deleted from the store.

## 10. Data Transfer Pipeline

### 10.1 Chunking and Integrity

- Default chunk size: **256 KiB** (`DefaultChunkSize`). Implementations MAY choose a different positive size.
- Each chunk carries `Index`, `Data`, and `Hash = SHA-256(Data)`.
- A Merkle tree over chunk hashes provides whole-object integrity:
  - Root hash can be advertised out-of-band.
  - Proofs contain sibling hashes and positions; verification recomputes the root.
  - Missing or corrupted chunks **MUST** fail verification.

### 10.2 Compression

- LZ4 is used for high-throughput compression.
- Compression levels: `Fast`, `Default`, `Best` (speed vs ratio).
- A chunk is left uncompressed if compression does not reduce size.
- Each compressed chunk records `Compressed` (bool) and `OrigHash` of the uncompressed data; decompression **MUST** verify the hash.

### 10.3 Erasure Coding

- Reed-Solomon coding (via `klauspost/reedsolomon`) MAY be applied to shard data into data + parity shards.
- Any subset with sufficient parity to reconstruct **MUST** result in identical chunk hashes, preserving Merkle integrity.

### 10.4 Batching

  - Batches group multiple (possibly compressed) chunks:
    - Magic: `0x49365042` (`"I6PB"`).
    - Layout: `magic (4)` || `chunk_count (4)` || for **each chunk**: `index (4)` || `compressed (1)` || `hash_len (2)` || `hash` || `data_len (4)` || `data`.
    - All multi-byte integer fields are encoded in big-endian order.
    - Maximum serialized batch size: **4 MiB** (`MaxBatchSize`). Larger batches **MUST** be rejected.
- Batches are length-prefixed (`uint32` big-endian) when written to streams.

### 10.5 Parallel Streams (Pool)

- Stream pool opens multiple QUIC streams to saturate bandwidth.
- Default maximum pool size: **8** streams (configurable, `maxSize <= 0` defaults to 8).
- Acquire semantics:
  - Reuse existing idle streams if available.
  - Create new streams up to `maxSize`; otherwise wait or fail with context cancellation.
- Release returns streams to the pool; excess streams are closed.
- Parallel writers/readers typically spawn **4** workers by default.

## 11. API Surface (Informative)

The proposed stable API (from `docs/SPEC.md`) remains:

- `Node` exposes `Listen`, `Dial`, `Accept`, `Close`.
- `Session` exposes peer identities, capability map, stream open/accept, and close routines.
- `Stream` is an `io.ReadWriteCloser` abstraction over QUIC streams.

Implementations **SHOULD** preserve these signatures for `v1` compatibility.

## 12. Error Handling and Limits

- `MaxFramePayload` = 1 MiB; `Frame` writes **MUST** enforce this and `MessageType != 0`.
- `Batch` payload **MUST NOT** exceed 4 MiB.
- `Ticket` expiry is enforced at decode time; expired tickets **MUST** be rejected.
- Any signature failure, mismatched `PeerID`, or invalid frame type **MUST** abort the handshake.
- Control stream usage for application data is **NOT RECOMMENDED** and may be closed by peers.

## 13. Security Considerations

- Identity binding relies on Ed25519 signatures and `PeerID = SHA-256(pub)`; tampering is detected during HELLO verification.
- QUIC/TLS provides confidentiality against passive observers; optional end-to-end secure channel protects data from on-path QUIC endpoints.
- Nonces in HELLO prevent naive replay; deployments SHOULD enforce freshness policies (e.g., maximum clock skew) and use TLS-level anti-replay where available.
- Merkle roots and chunk hashes detect corruption; erasure-coded reconstruction MUST verify Merkle proofs.
- Session tickets are encrypted and authenticated; loss of the ticket store key invalidates issued tickets but does not compromise past sessions.

## 14. IANA Considerations

This document makes no requests of IANA. ALPN `i6p/1` is used by convention within the protocol.

## 15. Implementation Status

The Go reference implementation in this repository implements:

- HELLO handshake and verification, QUIC/TLS with ALPN `i6p/1`.
- Frame codec with 1 MiB limit.
- Chunking, Merkle proofs, LZ4 compression, Reed-Solomon erasure coding, batching, and parallel stream pool.
- Session tickets with 24h lifetime and 32-byte session keys.
- Optional secure channel with X25519 + ChaCha20-Poly1305 ratchet.

Reserved message types (`PEER_INFO`, `DATA`, `ACK`, `CLOSE`) are not yet defined beyond framing constraints; future drafts will specify them while preserving compatibility guarantees outlined above.
