package transfer

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
	"sync/atomic"
)

var (
	ErrTransferFailed      = errors.New("transfer: transfer failed")
	ErrIntegrityCheckFailed = errors.New("transfer: integrity check failed")
)

// TransferConfig configures a bulk transfer operation.
type TransferConfig struct {
	ChunkSize        int              // bytes per chunk (default: 256KB)
	Compression      CompressionLevel // compression level
	ErasureData      int              // data shards for erasure coding (0 = disabled)
	ErasureParity    int              // parity shards for erasure coding
	ParallelStreams  int              // number of parallel streams to use
	ParallelWorkers  int              // number of worker goroutines
}

// DefaultTransferConfig returns sensible defaults for high-throughput transfers.
func DefaultTransferConfig() TransferConfig {
	return TransferConfig{
		ChunkSize:       256 * 1024,  // 256 KB chunks
		Compression:     CompressionFast,
		ErasureData:     0,           // disabled by default
		ErasureParity:   0,
		ParallelStreams: 8,
		ParallelWorkers: 4,
	}
}

// TransferStats tracks transfer progress and metrics.
type TransferStats struct {
	TotalBytes      atomic.Int64
	CompressedBytes atomic.Int64
	ChunksSent      atomic.Int64
	ChunksReceived  atomic.Int64
	Errors          atomic.Int64
}

// CompressionRatio returns the compression ratio (original / compressed).
func (s *TransferStats) CompressionRatio() float64 {
	comp := s.CompressedBytes.Load()
	if comp == 0 {
		return 1.0
	}
	return float64(s.TotalBytes.Load()) / float64(comp)
}

// BulkSender handles sending large data efficiently.
type BulkSender struct {
	config   TransferConfig
	pool     *StreamPool
	stats    TransferStats
	chunker  *Chunker
}

// NewBulkSender creates a new bulk sender.
func NewBulkSender(opener StreamOpener, config TransferConfig) *BulkSender {
	if config.ChunkSize <= 0 {
		config.ChunkSize = DefaultChunkSize
	}
	return &BulkSender{
		config:  config,
		pool:    NewStreamPool(opener, config.ParallelStreams),
		chunker: NewChunker(config.ChunkSize),
	}
}

// Send transmits data efficiently using all configured optimizations.
// Returns the Merkle root hash for integrity verification.
func (bs *BulkSender) Send(ctx context.Context, data []byte) (merkleRoot []byte, err error) {
	chunks := bs.chunker.Split(data)
	
	// Build Merkle tree
	var hashes [][]byte
	for _, c := range chunks {
		hashes = append(hashes, c.Hash)
	}
	tree, err := BuildMerkleTree(hashes)
	if err != nil {
		return nil, err
	}

	bs.stats.TotalBytes.Store(int64(len(data)))

	// Compress chunks
	var compressedChunks []CompressedChunk
	var compressedSize int64
	for _, c := range chunks {
		cc := CompressChunk(c, bs.config.Compression)
		compressedChunks = append(compressedChunks, cc)
		compressedSize += int64(len(cc.Data))
	}
	bs.stats.CompressedBytes.Store(compressedSize)

	// Send using parallel writer
	pw := NewParallelWriter(bs.pool, bs.config.ParallelWorkers)
	pw.Start(ctx)

	for _, cc := range compressedChunks {
		if err := pw.Send(cc); err != nil {
			return nil, err
		}
		bs.stats.ChunksSent.Add(1)
	}

	if err := pw.Wait(); err != nil {
		return nil, err
	}

	return tree.Root(), nil
}

// SendReader transmits data from a reader.
func (bs *BulkSender) SendReader(ctx context.Context, r io.Reader) (merkleRoot []byte, err error) {
	chunks, err := bs.chunker.SplitReader(r)
	if err != nil {
		return nil, err
	}

	var totalSize int64
	var hashes [][]byte
	for _, c := range chunks {
		hashes = append(hashes, c.Hash)
		totalSize += int64(len(c.Data))
	}
	bs.stats.TotalBytes.Store(totalSize)

	tree, err := BuildMerkleTree(hashes)
	if err != nil {
		return nil, err
	}

	// Compress and send
	pw := NewParallelWriter(bs.pool, bs.config.ParallelWorkers)
	pw.Start(ctx)

	var compressedSize int64
	for _, c := range chunks {
		cc := CompressChunk(c, bs.config.Compression)
		compressedSize += int64(len(cc.Data))
		if err := pw.Send(cc); err != nil {
			return nil, err
		}
		bs.stats.ChunksSent.Add(1)
	}
	bs.stats.CompressedBytes.Store(compressedSize)

	if err := pw.Wait(); err != nil {
		return nil, err
	}

	return tree.Root(), nil
}

// Stats returns transfer statistics.
func (bs *BulkSender) Stats() TransferStats {
	return bs.stats
}

// Close closes the sender and releases resources.
func (bs *BulkSender) Close() error {
	return bs.pool.Close()
}

// BulkReceiver handles receiving large data efficiently.
type BulkReceiver struct {
	config      TransferConfig
	stats       TransferStats
	mu          sync.Mutex
	chunks      map[int]Chunk
	totalChunks int
}

// NewBulkReceiver creates a new bulk receiver.
func NewBulkReceiver(config TransferConfig) *BulkReceiver {
	return &BulkReceiver{
		config: config,
		chunks: make(map[int]Chunk),
	}
}

// ReceiveChunk processes an incoming compressed chunk.
func (br *BulkReceiver) ReceiveChunk(cc CompressedChunk) error {
	chunk, err := DecompressChunk(cc)
	if err != nil {
		br.stats.Errors.Add(1)
		return err
	}

	br.mu.Lock()
	br.chunks[chunk.Index] = chunk
	br.mu.Unlock()

	br.stats.ChunksReceived.Add(1)
	return nil
}

// ReceiveBatch processes an incoming batch of chunks.
func (br *BulkReceiver) ReceiveBatch(batch *Batch) error {
	for _, cc := range batch.Chunks {
		if err := br.ReceiveChunk(cc); err != nil {
			return err
		}
	}
	return nil
}

// SetExpectedChunks sets the expected number of chunks.
func (br *BulkReceiver) SetExpectedChunks(n int) {
	br.totalChunks = n
}

// Progress returns the reception progress (0.0 to 1.0).
func (br *BulkReceiver) Progress() float64 {
	if br.totalChunks == 0 {
		return 0
	}
	br.mu.Lock()
	defer br.mu.Unlock()
	return float64(len(br.chunks)) / float64(br.totalChunks)
}

// IsComplete returns true if all expected chunks have been received.
func (br *BulkReceiver) IsComplete() bool {
	if br.totalChunks == 0 {
		return false
	}
	br.mu.Lock()
	defer br.mu.Unlock()
	return len(br.chunks) == br.totalChunks
}

// Assemble reconstructs the original data from received chunks.
// Verifies integrity against the expected Merkle root if provided.
func (br *BulkReceiver) Assemble(expectedRoot []byte) ([]byte, error) {
	br.mu.Lock()
	chunkSlice := make([]Chunk, 0, len(br.chunks))
	for _, c := range br.chunks {
		chunkSlice = append(chunkSlice, c)
	}
	br.mu.Unlock()

	// Sort chunks by index
	for i := range chunkSlice {
		for j := i + 1; j < len(chunkSlice); j++ {
			if chunkSlice[j].Index < chunkSlice[i].Index {
				chunkSlice[i], chunkSlice[j] = chunkSlice[j], chunkSlice[i]
			}
		}
	}

	// Verify Merkle root if provided
	if len(expectedRoot) > 0 {
		var hashes [][]byte
		for _, c := range chunkSlice {
			hashes = append(hashes, c.Hash)
		}
		tree, err := BuildMerkleTree(hashes)
		if err != nil {
			return nil, err
		}
		if !bytesEqual(tree.Root(), expectedRoot) {
			return nil, ErrIntegrityCheckFailed
		}
	}

	return Reassemble(chunkSlice), nil
}

// Stats returns receiver statistics.
func (br *BulkReceiver) Stats() TransferStats {
	return br.stats
}

// QuickHash computes SHA-256 of data (utility function).
func QuickHash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
