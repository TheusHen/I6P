package transfer

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
)

// mockStream implements io.ReadWriteCloser for testing.
type mockStream struct {
	buf    bytes.Buffer
	mu     sync.Mutex
	closed bool
}

func (m *mockStream) Read(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.buf.Read(p)
}

func (m *mockStream) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.buf.Write(p)
}

func (m *mockStream) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// mockOpener implements StreamOpener for testing.
type mockOpener struct {
	streams []*mockStream
	mu      sync.Mutex
	idx     int
}

func newMockOpener(n int) *mockOpener {
	opener := &mockOpener{
		streams: make([]*mockStream, n),
	}
	for i := 0; i < n; i++ {
		opener.streams[i] = &mockStream{}
	}
	return opener
}

func (m *mockOpener) OpenStreamSync(ctx context.Context) (io.ReadWriteCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.idx >= len(m.streams) {
		return &mockStream{}, nil
	}
	s := m.streams[m.idx]
	m.idx++
	return s, nil
}

func TestStreamPoolAcquireRelease(t *testing.T) {
	opener := newMockOpener(4)
	pool := NewStreamPool(opener, 4)
	defer pool.Close()

	ctx := context.Background()

	// Acquire all streams
	var streams []io.ReadWriteCloser
	for i := 0; i < 4; i++ {
		s, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("Acquire %d: %v", i, err)
		}
		streams = append(streams, s)
	}

	if pool.Created() != 4 {
		t.Fatalf("expected 4 created, got %d", pool.Created())
	}

	// Release all
	for _, s := range streams {
		pool.Release(s)
	}

	if pool.Size() != 4 {
		t.Fatalf("expected pool size 4, got %d", pool.Size())
	}
}

func TestBulkReceiverAssemble(t *testing.T) {
	receiver := NewBulkReceiver(DefaultTransferConfig())

	// Create test chunks
	data := []byte("hello world test data for bulk receiver")
	chunker := NewChunker(10)
	chunks := chunker.Split(data)

	receiver.SetExpectedChunks(len(chunks))

	// Receive out of order
	for i := len(chunks) - 1; i >= 0; i-- {
		cc := CompressChunk(chunks[i], CompressionFast)
		if err := receiver.ReceiveChunk(cc); err != nil {
			t.Fatalf("ReceiveChunk: %v", err)
		}
	}

	if !receiver.IsComplete() {
		t.Fatalf("expected complete")
	}

	// Build expected Merkle root
	var hashes [][]byte
	for _, c := range chunks {
		hashes = append(hashes, c.Hash)
	}
	tree, _ := BuildMerkleTree(hashes)

	assembled, err := receiver.Assemble(tree.Root())
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	if !bytes.Equal(assembled, data) {
		t.Fatalf("assembled data mismatch")
	}
}

func BenchmarkBulkSendSimulated(b *testing.B) {
	data := make([]byte, 10*1024*1024) // 10 MB
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		config := DefaultTransferConfig()
		chunker := NewChunker(config.ChunkSize)
		chunks := chunker.Split(data)

		// Simulate compression
		for _, c := range chunks {
			_ = CompressChunk(c, config.Compression)
		}

		// Simulate Merkle tree
		var hashes [][]byte
		for _, c := range chunks {
			hashes = append(hashes, c.Hash)
		}
		_, _ = BuildMerkleTree(hashes)
	}
}
