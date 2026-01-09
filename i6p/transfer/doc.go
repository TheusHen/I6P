// Package transfer provides high-performance bulk data transfer primitives.
//
// Key features:
//   - Chunked transfer with configurable chunk sizes
//   - Merkle tree for integrity verification (detect corruption, resume partial transfers)
//   - LZ4 compression (extremely fast, good for network-bound transfers)
//   - Batching for reduced syscall overhead
//   - Parallel stream support via the Stream Pool
//
// This package is designed to saturate high-bandwidth IPv6 links efficiently.
package transfer
