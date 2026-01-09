package transfer

import (
	"encoding/binary"
	"errors"
	"io"
)

var (
	ErrBatchTooLarge = errors.New("transfer: batch exceeds maximum size")
)

const (
	// MaxBatchSize is the maximum batch payload size (4 MB).
	MaxBatchSize = 4 * 1024 * 1024
	// BatchMagic identifies a batch frame.
	BatchMagic = uint32(0x49365042) // "I6PB"
)

// Batch groups multiple chunks for efficient transmission.
// This reduces per-chunk overhead and syscall frequency.
type Batch struct {
	Chunks []CompressedChunk
}

// NewBatch creates an empty batch.
func NewBatch() *Batch {
	return &Batch{Chunks: make([]CompressedChunk, 0)}
}

// Add adds a chunk to the batch.
func (b *Batch) Add(cc CompressedChunk) {
	b.Chunks = append(b.Chunks, cc)
}

// Size returns the total serialized size of the batch.
func (b *Batch) Size() int {
	size := 4 + 4 // magic + count
	for _, cc := range b.Chunks {
		// index(4) + compressed(1) + hashLen(2) + hash + dataLen(4) + data
		size += 4 + 1 + 2 + len(cc.OrigHash) + 4 + len(cc.Data)
	}
	return size
}

// Encode serializes the batch for wire transmission.
// Format:
//
//	4 bytes: magic
//	4 bytes: chunk count
//	For each chunk:
//		4 bytes: index
//		1 byte: compressed flag
//		2 bytes: hash length
//		N bytes: hash
//		4 bytes: data length
//		N bytes: data
func (b *Batch) Encode() ([]byte, error) {
	size := b.Size()
	if size > MaxBatchSize {
		return nil, ErrBatchTooLarge
	}

	buf := make([]byte, size)
	offset := 0

	binary.BigEndian.PutUint32(buf[offset:], BatchMagic)
	offset += 4
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(b.Chunks)))
	offset += 4

	for _, cc := range b.Chunks {
		binary.BigEndian.PutUint32(buf[offset:], uint32(cc.Index))
		offset += 4

		if cc.Compressed {
			buf[offset] = 1
		} else {
			buf[offset] = 0
		}
		offset++

		binary.BigEndian.PutUint16(buf[offset:], uint16(len(cc.OrigHash)))
		offset += 2
		copy(buf[offset:], cc.OrigHash)
		offset += len(cc.OrigHash)

		binary.BigEndian.PutUint32(buf[offset:], uint32(len(cc.Data)))
		offset += 4
		copy(buf[offset:], cc.Data)
		offset += len(cc.Data)
	}

	return buf, nil
}

// DecodeBatch deserializes a batch from wire format.
func DecodeBatch(data []byte) (*Batch, error) {
	if len(data) < 8 {
		return nil, errors.New("transfer: batch too short")
	}

	magic := binary.BigEndian.Uint32(data[:4])
	if magic != BatchMagic {
		return nil, errors.New("transfer: invalid batch magic")
	}

	count := binary.BigEndian.Uint32(data[4:8])
	offset := 8

	b := &Batch{Chunks: make([]CompressedChunk, 0, count)}

	for i := uint32(0); i < count; i++ {
		if offset+4+1+2 > len(data) {
			return nil, errors.New("transfer: batch truncated")
		}

		index := int(binary.BigEndian.Uint32(data[offset:]))
		offset += 4

		compressed := data[offset] == 1
		offset++

		hashLen := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2

		if offset+hashLen+4 > len(data) {
			return nil, errors.New("transfer: batch truncated")
		}

		hash := make([]byte, hashLen)
		copy(hash, data[offset:offset+hashLen])
		offset += hashLen

		dataLen := int(binary.BigEndian.Uint32(data[offset:]))
		offset += 4

		if offset+dataLen > len(data) {
			return nil, errors.New("transfer: batch truncated")
		}

		chunkData := make([]byte, dataLen)
		copy(chunkData, data[offset:offset+dataLen])
		offset += dataLen

		b.Chunks = append(b.Chunks, CompressedChunk{
			Index:      index,
			Compressed: compressed,
			Data:       chunkData,
			OrigHash:   hash,
		})
	}

	return b, nil
}

// WriteBatch writes a batch to a writer.
func WriteBatch(w io.Writer, b *Batch) error {
	data, err := b.Encode()
	if err != nil {
		return err
	}
	// Write length prefix
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// ReadBatch reads a batch from a reader.
func ReadBatch(r io.Reader) (*Batch, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	dataLen := binary.BigEndian.Uint32(lenBuf[:])
	if dataLen > MaxBatchSize {
		return nil, ErrBatchTooLarge
	}
	data := make([]byte, dataLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return DecodeBatch(data)
}
