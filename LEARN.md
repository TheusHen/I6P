# Learn I6P (IPv6 Peer-to-Peer Protocol)

Welcome! This guide helps you understand the I6P project, explore the codebase, and run it locally.

## 1) What is I6P?
I6P is an IPv6 peer-to-peer protocol implementation in Go. It focuses on establishing direct peer connections, message exchange, and discovery across IPv6 networks.

## 2) Repository at a glance
- **Language:** Go (~99%)
- **Build/automation:** Makefile
- **Probable layout (typical Go project):**
  - `cmd/` — entrypoints or binaries.
  - `pkg/` or `internal/` — core libraries and protocol logic.
  - `go.mod` / `go.sum` — module definition and dependencies.
  - `Makefile` — common tasks (build, test, lint, etc.).
  - `README.md` — quick overview and usage.
  - Additional directories may contain protocol handlers, peer discovery, message types, and networking utilities.

> If the actual layout differs, adjust your navigation accordingly.

## 3) Getting started
### Prerequisites
- Go (≥1.20 recommended)
- `make` (for convenience)
- IPv6-enabled networking environment
- Git

### Install dependencies
```bash
go mod download
```

### Build
```bash
make build       # if defined
# or
go build ./...
```

### Test
```bash
make test        # if defined
# or
go test ./...
```

### Run (example)
If there is a main package (e.g., `cmd/i6p`):
```bash
go run ./cmd/i6p
```
Check `README.md` or `Makefile` for concrete targets and flags.

## 4) How the protocol likely works (mental model)
- **Transport & sockets:** Listens/binds on IPv6 addresses/ports; may use UDP or TCP (check code).
- **Peer identity:** Public keys / node IDs (verify type and format).
- **Handshake:** Exchange of identity and capabilities; may include versioning.
- **Routing/lookup:** Peer discovery and neighbor tables; may use DHT-like lookups.
- **Messaging:** Serialization format (e.g., protobuf/JSON/custom); request/response or pub/sub.
- **Security:** Encryption/authentication of peers; key exchange; replay protections.
- **NAT traversal (if any):** STUN/ICE-like techniques for IPv6 (often simpler than IPv4).

> Inspect wire/message definitions (e.g., `message.go`, `proto/`, or `wire/`) and connection handlers (`peer`, `session`, `conn`) to confirm.

## 5) Suggested first code reads
1) `README.md` — usage and config.
2) `Makefile` — available tasks.
3) Entry point in `cmd/` — how the service boots.
4) Protocol/message definitions — structures and encoding.
5) Connection lifecycle — dial/listen, handshake, retry, and teardown.
6) Peer store / routing table — how peers are tracked and updated.
7) Security layer — key handling, signing/verification, encryption.

## 6) Common tasks
- **Format:** `gofmt` or `go fmt ./...`
- **Build binary:** `go build ./cmd/<binary>`
- **Run unit tests:** `go test ./...`
- **Run specific test:** `go test ./pkg/... -run TestName -v`

## 7) Debugging tips
- Enable verbose logging flags or env vars if available (e.g., `LOG_LEVEL=debug`).
- Use `tcpdump`/`wireshark` for IPv6 traffic inspection.
- Validate that your host and router permit IPv6 inbound/outbound connections.
- Check firewall rules for the chosen port.

## 8) Contributing workflow (suggested)
1) Fork or create a feature branch.
2) Make changes; keep `go fmt` clean.
3) Add/adjust tests.
4) Run `make test` or `go test ./...`.
5) Open a PR with a clear description and testing notes.

## 9) Next steps
- Confirm actual directories, binaries, and config flags.
- Add concrete run examples (ports, flags, sample peers).
- Document message formats and handshake flow once verified.
