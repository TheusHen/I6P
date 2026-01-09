package transfer

import (
	"bytes"
	"errors"
	"io"
	"sync"

	"github.com/pierrec/lz4/v4"
)

var (
	ErrCompressionFailed   = errors.New("transfer: compression failed")
	ErrDecompressionFailed = errors.New("transfer: decompression failed")
)

// CompressionLevel controls the speed/ratio tradeoff.
type CompressionLevel int

const (
	CompressionFast    CompressionLevel = iota // Fastest, lower ratio
	CompressionDefault                         // Balanced
	CompressionBest                            // Best ratio, slower
)

// compressorPool reuses LZ4 writers to reduce allocations.
var compressorPool = sync.Pool{
	New: func() interface{} {
		return lz4.NewWriter(nil)
	},
}

// decompressorPool reuses LZ4 readers.
var decompressorPool = sync.Pool{
	New: func() interface{} {
		return lz4.NewReader(nil)
	},
}

// Compress compresses data using LZ4.
// LZ4 is chosen for its exceptional speed on commodity hardware.
func Compress(data []byte, level CompressionLevel) ([]byte, error) {
	var buf bytes.Buffer
	w := compressorPool.Get().(*lz4.Writer)
	defer compressorPool.Put(w)

	w.Reset(&buf)

	switch level {
	case CompressionFast:
		_ = w.Apply(lz4.CompressionLevelOption(lz4.Fast))
	case CompressionBest:
		_ = w.Apply(lz4.CompressionLevelOption(lz4.Level9))
	default:
		_ = w.Apply(lz4.CompressionLevelOption(lz4.Level4))
	}

	if _, err := w.Write(data); err != nil {
		return nil, ErrCompressionFailed
	}
	if err := w.Close(); err != nil {
		return nil, ErrCompressionFailed
	}

	return buf.Bytes(), nil
}

// Decompress decompresses LZ4-compressed data.
func Decompress(data []byte) ([]byte, error) {
	r := decompressorPool.Get().(*lz4.Reader)
	defer decompressorPool.Put(r)

	r.Reset(bytes.NewReader(data))

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return nil, ErrDecompressionFailed
	}
	return buf.Bytes(), nil
}

// CompressedChunk wraps a chunk with compression metadata.
type CompressedChunk struct {
	Index      int
	Compressed bool
	Data       []byte
	OrigHash   []byte // hash of original uncompressed data
}

// CompressChunk compresses a chunk if beneficial.
// Returns the original chunk if compression doesn't help.
func CompressChunk(chunk Chunk, level CompressionLevel) CompressedChunk {
	compressed, err := Compress(chunk.Data, level)
	if err != nil || len(compressed) >= len(chunk.Data) {
		// Compression not beneficial
		return CompressedChunk{
			Index:      chunk.Index,
			Compressed: false,
			Data:       chunk.Data,
			OrigHash:   chunk.Hash,
		}
	}
	return CompressedChunk{
		Index:      chunk.Index,
		Compressed: true,
		Data:       compressed,
		OrigHash:   chunk.Hash,
	}
}

// DecompressChunk decompresses a chunk and verifies integrity.
func DecompressChunk(cc CompressedChunk) (Chunk, error) {
	var data []byte
	if cc.Compressed {
		var err error
		data, err = Decompress(cc.Data)
		if err != nil {
			return Chunk{}, err
		}
	} else {
		data = cc.Data
	}

	// Verify hash
	hash := HashChunk(data)
	if !bytesEqual(hash, cc.OrigHash) {
		return Chunk{}, errors.New("transfer: chunk hash mismatch after decompression")
	}

	return Chunk{
		Index: cc.Index,
		Data:  data,
		Hash:  hash,
	}, nil
}
