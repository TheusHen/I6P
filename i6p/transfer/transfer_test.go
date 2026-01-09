package transfer

import (
	"bytes"
	"testing"
)

func TestMerkleTreeBuildAndVerify(t *testing.T) {
	data := [][]byte{
		[]byte("chunk0"),
		[]byte("chunk1"),
		[]byte("chunk2"),
		[]byte("chunk3"),
	}
	var hashes [][]byte
	for _, d := range data {
		hashes = append(hashes, HashChunk(d))
	}

	tree, err := BuildMerkleTree(hashes)
	if err != nil {
		t.Fatalf("BuildMerkleTree: %v", err)
	}

	root := tree.Root()
	if len(root) != 32 {
		t.Fatalf("unexpected root length")
	}

	// Verify each chunk
	for i := range data {
		proof, err := tree.GenerateProof(i)
		if err != nil {
			t.Fatalf("GenerateProof(%d): %v", i, err)
		}
		if err := VerifyProof(proof, root); err != nil {
			t.Fatalf("VerifyProof(%d): %v", i, err)
		}
	}

	// Tamper with a proof
	proof, _ := tree.GenerateProof(0)
	proof.ChunkHash[0] ^= 0xff
	if err := VerifyProof(proof, root); err != ErrMerkleProofFail {
		t.Fatalf("expected proof failure for tampered hash")
	}
}

func TestChunkerSplitReassemble(t *testing.T) {
	data := make([]byte, 1024*1024+123) // ~1 MB + odd bytes
	for i := range data {
		data[i] = byte(i % 256)
	}

	c := NewChunker(64 * 1024)
	chunks := c.Split(data)

	if len(chunks) != 17 { // ceil(1024*1024+123 / 64*1024) = 17
		t.Fatalf("unexpected chunk count: %d", len(chunks))
	}

	reassembled := Reassemble(chunks)
	if !bytes.Equal(reassembled, data) {
		t.Fatalf("reassembled data does not match original")
	}
}

func TestCompressDecompress(t *testing.T) {
	data := bytes.Repeat([]byte("hello world "), 1000)

	compressed, err := Compress(data, CompressionFast)
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}
	if len(compressed) >= len(data) {
		t.Logf("warning: compression not effective (input %d, output %d)", len(data), len(compressed))
	}

	decompressed, err := Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if !bytes.Equal(decompressed, data) {
		t.Fatalf("decompressed != original")
	}
}

func TestBatchEncodeDecode(t *testing.T) {
	chunks := []Chunk{
		{Index: 0, Data: []byte("chunk0"), Hash: HashChunk([]byte("chunk0"))},
		{Index: 1, Data: []byte("chunk1"), Hash: HashChunk([]byte("chunk1"))},
	}

	batch := NewBatch()
	for _, c := range chunks {
		cc := CompressChunk(c, CompressionFast)
		batch.Add(cc)
	}

	encoded, err := batch.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	decoded, err := DecodeBatch(encoded)
	if err != nil {
		t.Fatalf("DecodeBatch: %v", err)
	}

	if len(decoded.Chunks) != len(batch.Chunks) {
		t.Fatalf("chunk count mismatch")
	}

	for i, cc := range decoded.Chunks {
		orig, err := DecompressChunk(cc)
		if err != nil {
			t.Fatalf("DecompressChunk %d: %v", i, err)
		}
		if orig.Index != chunks[i].Index {
			t.Fatalf("chunk %d index mismatch", i)
		}
	}
}

func BenchmarkChunkAndCompress(b *testing.B) {
	data := make([]byte, 4*1024*1024) // 4 MB
	for i := range data {
		data[i] = byte(i % 256)
	}
	c := NewChunker(256 * 1024)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		chunks := c.Split(data)
		for _, chunk := range chunks {
			_ = CompressChunk(chunk, CompressionFast)
		}
	}
}
