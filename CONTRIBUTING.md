# Contributing

Thanks for your interest in contributing to I6P.

## Development

- Go: 1.22+
- Run tests: `go test ./...`
- Format: `gofmt -w .`
- Lint: `golangci-lint run`

## Pull requests

- Keep changes focused and well-scoped.
- Add/update tests when behavior changes.
- Update documentation when public APIs change.
- Use English for code, documentation, and commit messages.

## Design principles

- IPv6-first/only
- Identity is Ed25519; `PeerID = SHA-256(PublicKey)`
- QUIC provides transport encryption; I6P verifies peer identity at the session layer.
