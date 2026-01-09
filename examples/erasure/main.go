package main

import (
	"bytes"
	"fmt"
	"log"
	"time"

	"github.com/TheusHen/I6P/i6p/transfer"
	"github.com/TheusHen/I6P/i6p/transfer/erasure"
)

func main() {
	// Demonstrate erasure coding capabilities
	log.Println("=== I6P Erasure Coding Demo ===")

	// Create 10 data shards + 4 parity shards
	// This means we can lose ANY 4 shards and still recover
	codec, err := erasure.NewCodec(10, 4)
	if err != nil {
		log.Fatalf("NewCodec: %v", err)
	}

	log.Printf("Configuration: %d data + %d parity = %d total shards",
		codec.DataShards(), codec.ParityShards(), codec.TotalShards())
	log.Printf("Overhead: %.1f%%", (codec.Overhead()-1)*100)

	// Create test data (1 MB)
	dataSize := 1024 * 1024
	data := make([]byte, dataSize)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Encode with erasure coding
	start := time.Now()
	shards, err := codec.EncodeData(data)
	if err != nil {
		log.Fatalf("EncodeData: %v", err)
	}
	encodeTime := time.Since(start)

	log.Printf("Encoded %d bytes into %d shards in %v", dataSize, len(shards), encodeTime)
	log.Printf("Shard size: %d bytes", len(shards[0]))
	log.Printf("Encoding throughput: %.2f MB/s", float64(dataSize)/encodeTime.Seconds()/1024/1024)

	// Verify shards
	ok, _ := codec.Verify(shards)
	log.Printf("Verification: %v", ok)

	// Simulate losing 4 shards (the maximum we can lose)
	log.Println("\n--- Simulating loss of 4 shards ---")
	lostShards := []int{2, 5, 7, 13}
	for _, i := range lostShards {
		shards[i] = nil
	}
	log.Printf("Lost shards: %v", lostShards)

	// Reconstruct
	start = time.Now()
	if err := codec.Reconstruct(shards); err != nil {
		log.Fatalf("Reconstruct: %v", err)
	}
	reconstructTime := time.Since(start)

	log.Printf("Reconstructed in %v", reconstructTime)
	log.Printf("Reconstruction throughput: %.2f MB/s", float64(dataSize)/reconstructTime.Seconds()/1024/1024)

	// Verify after reconstruction
	ok, _ = codec.Verify(shards)
	log.Printf("Post-reconstruction verification: %v", ok)

	// Join back to original data
	recovered, err := codec.Join(shards, dataSize)
	if err != nil {
		log.Fatalf("Join: %v", err)
	}

	if bytes.Equal(recovered, data) {
		log.Println("✓ Data fully recovered and verified!")
	} else {
		log.Println("✗ Data recovery failed!")
	}

	// Demonstrate integration with chunking + compression
	log.Println("\n=== Combined: Chunking + Compression + Erasure ===")

	chunker := transfer.NewChunker(64 * 1024) // 64 KB chunks
	chunks := chunker.Split(data)
	log.Printf("Split into %d chunks", len(chunks))

	var totalCompressed int64
	var totalOriginal int64
	for _, chunk := range chunks {
		cc := transfer.CompressChunk(chunk, transfer.CompressionFast)
		totalOriginal += int64(len(chunk.Data))
		totalCompressed += int64(len(cc.Data))
	}

	log.Printf("Original: %d bytes, Compressed: %d bytes", totalOriginal, totalCompressed)
	log.Printf("Compression ratio: %.2fx", float64(totalOriginal)/float64(totalCompressed))

	// Build Merkle tree for integrity
	var hashes [][]byte
	for _, c := range chunks {
		hashes = append(hashes, c.Hash)
	}
	tree, _ := transfer.BuildMerkleTree(hashes)
	log.Printf("Merkle root: %s", tree.RootHex()[:16]+"...")

	fmt.Println("\n=== Summary ===")
	fmt.Println("I6P Transfer Features:")
	fmt.Println("  • LZ4 compression: ~4 GB/s throughput")
	fmt.Println("  • Merkle trees: verifiable chunks")
	fmt.Println("  • Erasure coding: recover from packet loss")
	fmt.Println("  • Batching: reduced syscall overhead")
	fmt.Println("  • Parallel streams: saturate bandwidth")
}
