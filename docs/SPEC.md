# I6P — Specification (Handshake, Messages, States, and Public API)

This document describes the **formal** behavior expected of I6P at the session/protocol level and proposes a **freezable public API** for consumption by applications.

> Scope note: the current implementation covers the authenticated handshake (`HELLO`) and the base infrastructure (QUIC/TLS, identity, codec, crypto, and transfer). Some message types listed are **reserved** for protocol evolution.

## 1) Terms

- **Node**: local entity (e.g., process) that has an identity and can `Listen` and/or `Dial`.
- **Peer**: remote entity identified by `PeerID`.
- **PeerID**: stable identifier derived from the Ed25519 public key.
- **Session**: authenticated and multiplexed (QUIC) connection between two peers.
- **Control stream**: stream dedicated to control (handshake and control messages).

## 2) Handshake

### 2.1 Objectives

- Authenticate the remote peer via Ed25519 signature.
- Link `PeerID` to the presented public key (`PeerID = SHA-256(PublicKey)`).
- Exchange capabilities (`map[string]string`) for simple feature negotiation.

### 2.2 Flow (Client/Initiator)

1. Open a QUIC connection to the server address.
2. Open a **control stream** (dedicated stream).
3. Send a `Frame{Type: HELLO, Payload: EncodeHello(Hello)}`.
4. Read the response `Frame` from the server.
5. Validate that `Type == HELLO`.
6. Decode `Hello` and **verify**:
   - `PeerID` is valid (hex) and matches `SHA-256(PublicKey)`.
   - `Signature` validates for the signature bytes defined below.
7. Session is marked as **ESTABLISHED**.

### 2.3 Flow (Server/Responder)

1. Accept QUIC connection.
2. Accept **control stream** (opened by client).
3. Read initial `Frame`.
4. Validate that `Type == HELLO`.
5. Decode and verify client `Hello`.
6. Respond with signed server `HELLO`.
7. Session is marked as **ESTABLISHED**.

### 2.4 Properties

- **Authenticity**: guaranteed by Ed25519.
- **Identity binding**: guaranteed by checking `PeerID == SHA-256(PublicKey)`.
- **Confidentiality**: provided by QUIC/TLS 1.3 (transport layer). Optionally, an E2E layer can be used via `crypto.SecureChannel`.

## 3) Messages

### 3.1 Container (Frame)

I6P uses binary frames in the control stream.

Format:

- `type`: 1 byte
- `payload_len`: 4 bytes big-endian
- `payload`: N bytes

Limits:

- `payload_len <= 1 MiB`

### 3.2 Message Types (MessageType)

Values:

- `1 = HELLO` (implemented and used in the handshake)
- `2 = PEER_INFO` (reserved)
- `3 = DATA` (reserved)
- `4 = ACK` (reserved)
- `5 = CLOSE` (reserved)

> Important: currently, the handshake uses **only** `HELLO` in the control stream. Application data transfer occurs in QUIC streams opened after the handshake.

### 3.3 HELLO (JSON payload)

Fields:

- `peer_id` (string): hex of `PeerID`
- `public_key` (bytes): Ed25519 public key
- `timestamp_sec` (int64)
- `nonce` (bytes): 32 random bytes
- `capabilities` (map[string]string, optional)
- `signature` (bytes): Ed25519 signature

Signed bytes (`SigningBytes()`):

1. `PeerID` (32 bytes)
2. `PublicKey` (32 bytes)
3. `TimestampSec` (uint64 big-endian)
4. `Nonce` (32 bytes)
5. `Capabilities` in deterministic order:
   - sort keys lexicographically
   - for each pair (k,v): write `len(k)` (uint16 BE) + `k` + `len(v)` (uint16 BE) + `v`

Verification (`Verify()`):

- `len(PublicKey) == 32`
- `PeerIDFromPublicKey(PublicKey) == PeerID` (binary comparison)
- `ed25519.Verify(PublicKey, SigningBytes(), Signature) == true`

## 4) States

### 4.1 Node States

- **NEW**: instantiated, no listener.
- **LISTENING**: active QUIC listener.
- **DIALING**: connection attempt in progress.
- **CLOSED**: node closed, does not accept new connections.

Typical transitions:

- `NEW -> LISTENING` via `Listen(...)`
- `LISTENING -> CLOSED` via `Close()`
- `NEW -> DIALING -> ESTABLISHED_SESSION` via `Dial(...)`

### 4.2 Session States

- **HANDSHAKING**: control stream created/accepted and `HELLO` exchanged.
- **ESTABLISHED**: peer identity verified.
- **CLOSING/CLOSED**: closure due to error/application code.

Invariants:

- Application streams should only be used after `ESTABLISHED`.
- The control stream is reserved and should not carry application data.

### 4.3 SecureChannel State (optional)

When used, `crypto.SecureChannel` has:

- **NEW**: ephemeral keys generated.
- **ESTABLISHED**: `Complete(peerPub)` performed and ratchets initialized.

## 5) Freezable public API (proposal)

The idea of "freezable" is to provide a minimal, stable, and easy-to-version surface.

### 5.1 Compatibility principles

- `v1`: changes should **not** break existing signatures.
- Additions are allowed via:
  - new methods on concrete types (not interfaces) and/or
  - new optional interfaces
- Stable interfaces should be small and focused.

### 5.2 Suggested Interfaces (v1)

```go
package i6p

import (
    "context"
    "io"
    "net/netip"

    "github.com/TheusHen/I6P/i6p/identity"
)

type PeerID = identity.PeerID

type PeerInfo struct {
    ID           PeerID
    Addr         netip.AddrPort
    Capabilities map[string]string
}

// Stream is the smallest useful abstraction for application data.
// (Implementations can expose extras via type assertion.)
type Stream interface {
    io.Reader
    io.Writer
    io.Closer
}

type Session interface {
    LocalPeerID() PeerID
    RemotePeerID() PeerID
    RemoteCapabilities() map[string]string

    OpenStream(ctx context.Context) (Stream, error)
    AcceptStream(ctx context.Context) (Stream, error)

    Close() error
    CloseWithError(code uint64, msg string) error
}

type Node interface {
    ID() PeerID
    Capabilities() map[string]string

    Listen(addr netip.AddrPort) error
    ListenAddr() (netip.AddrPort, bool)
    Close() error

    Accept(ctx context.Context) (Session, error)
    Dial(ctx context.Context, peer PeerInfo) (Session, error)
}
```

### 5.3 Mapping to the current implementation

- Today, the main entrypoint is `i6p.Peer` with:
  - `Listen(addr string) error`
  - `Dial(ctx, addr string) (*session.Session, error)`
  - `Accept(ctx) (*session.Session, error)`

The above proposal standardizes `netip.AddrPort` and hides the QUIC stream type behind `Stream`.

## 6) Compliance checklist (for review)

- Handshake: signed and verified `HELLO`
- Frame: type + length + payload, 1 MiB limit
- States: Node/Session defined and explicit invariants
- Freezable API: small interfaces, focus on compatibility