package transfer

import (
	"bytes"
	"io"
	"sync"
)

// ChunkSize is the default chunk size (256 KB) - optimal for high-bandwidth links.
const DefaultChunkSize = 256 * 1024

// Chunker splits data into fixed-size chunks.
type Chunker struct {
	chunkSize int
}

// NewChunker creates a new chunker with the specified chunk size.
func NewChunker(chunkSize int) *Chunker {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	return &Chunker{chunkSize: chunkSize}
}

// ChunkSize returns the configured chunk size.
func (c *Chunker) ChunkSize() int { return c.chunkSize }

// Chunk represents a single data chunk.
type Chunk struct {
	Index int
	Data  []byte
	Hash  []byte
}

// Split splits data into chunks and computes hashes.
func (c *Chunker) Split(data []byte) []Chunk {
	var chunks []Chunk
	for i := 0; i < len(data); i += c.chunkSize {
		end := i + c.chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]
		chunks = append(chunks, Chunk{
			Index: len(chunks),
			Data:  chunk,
			Hash:  HashChunk(chunk),
		})
	}
	return chunks
}

// SplitReader splits data from a reader into chunks.
func (c *Chunker) SplitReader(r io.Reader) ([]Chunk, error) {
	var chunks []Chunk
	buf := make([]byte, c.chunkSize)
	for {
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			chunks = append(chunks, Chunk{
				Index: len(chunks),
				Data:  chunk,
				Hash:  HashChunk(chunk),
			})
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return chunks, nil
}

// Reassemble combines chunks back into the original data.
func Reassemble(chunks []Chunk) []byte {
	// Sort by index
	sorted := make([]Chunk, len(chunks))
	copy(sorted, chunks)
	for i := range sorted {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].Index < sorted[i].Index {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	var buf bytes.Buffer
	for _, c := range sorted {
		buf.Write(c.Data)
	}
	return buf.Bytes()
}

// ChunkPool provides reusable byte buffers for chunk operations.
type ChunkPool struct {
	pool sync.Pool
	size int
}

// NewChunkPool creates a pool of reusable chunk buffers.
func NewChunkPool(chunkSize int) *ChunkPool {
	return &ChunkPool{
		pool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, chunkSize)
				return &buf
			},
		},
		size: chunkSize,
	}
}

// Get returns a buffer from the pool.
func (p *ChunkPool) Get() *[]byte {
	return p.pool.Get().(*[]byte)
}

// Put returns a buffer to the pool.
func (p *ChunkPool) Put(buf *[]byte) {
	if len(*buf) == p.size {
		p.pool.Put(buf)
	}
}
