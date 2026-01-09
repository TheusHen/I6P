// Package erasure provides Reed-Solomon erasure coding for I6P transfers.
//
// Erasure coding allows recovering lost chunks without retransmission,
// dramatically improving throughput on lossy links. For example, with
// 10 data shards and 4 parity shards, any 4 shards can be lost and the
// data is still fully recoverable.
//
// This implementation uses the klauspost/reedsolomon library for high performance.
package erasure
