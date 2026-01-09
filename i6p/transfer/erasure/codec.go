package erasure

import (
	"errors"

	"github.com/klauspost/reedsolomon"
)

var (
	ErrTooManyLost       = errors.New("erasure: too many shards lost, cannot recover")
	ErrInvalidConfig     = errors.New("erasure: invalid data/parity configuration")
	ErrShardSizeMismatch = errors.New("erasure: shard sizes do not match")
)

// Codec provides Reed-Solomon encoding/decoding.
type Codec struct {
	enc        reedsolomon.Encoder
	dataShards int
	parityShards int
}

// NewCodec creates a new erasure codec.
// dataShards: number of data shards
// parityShards: number of parity shards (can lose up to this many)
func NewCodec(dataShards, parityShards int) (*Codec, error) {
	if dataShards <= 0 || parityShards <= 0 {
		return nil, ErrInvalidConfig
	}
	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, err
	}
	return &Codec{
		enc:          enc,
		dataShards:   dataShards,
		parityShards: parityShards,
	}, nil
}

// DataShards returns the number of data shards.
func (c *Codec) DataShards() int { return c.dataShards }

// ParityShards returns the number of parity shards.
func (c *Codec) ParityShards() int { return c.parityShards }

// TotalShards returns the total number of shards (data + parity).
func (c *Codec) TotalShards() int { return c.dataShards + c.parityShards }

// Split splits data into data shards (does not compute parity yet).
// The data is padded if necessary.
func (c *Codec) Split(data []byte) ([][]byte, error) {
	return c.enc.Split(data)
}

// Encode computes parity shards for the given data shards.
// The shards slice must have exactly TotalShards() elements,
// with the first DataShards() containing data and the rest being parity (to be filled).
func (c *Codec) Encode(shards [][]byte) error {
	return c.enc.Encode(shards)
}

// EncodeData is a convenience function that splits data and computes parity.
// Returns all shards (data + parity).
func (c *Codec) EncodeData(data []byte) ([][]byte, error) {
	shards, err := c.Split(data)
	if err != nil {
		return nil, err
	}
	if err := c.Encode(shards); err != nil {
		return nil, err
	}
	return shards, nil
}

// Verify checks if the parity shards are consistent with data shards.
func (c *Codec) Verify(shards [][]byte) (bool, error) {
	return c.enc.Verify(shards)
}

// Reconstruct attempts to reconstruct missing shards.
// Missing shards should be set to nil in the slice.
// Returns ErrTooManyLost if too many shards are missing.
func (c *Codec) Reconstruct(shards [][]byte) error {
	err := c.enc.Reconstruct(shards)
	if err != nil {
		if err == reedsolomon.ErrTooFewShards {
			return ErrTooManyLost
		}
		return err
	}
	return nil
}

// ReconstructData reconstructs only the data shards (faster if parity not needed).
func (c *Codec) ReconstructData(shards [][]byte) error {
	err := c.enc.ReconstructData(shards)
	if err != nil {
		if err == reedsolomon.ErrTooFewShards {
			return ErrTooManyLost
		}
		return err
	}
	return nil
}

// Join joins data shards back into the original data.
// outSize is the original data size (before padding).
func (c *Codec) Join(shards [][]byte, outSize int) ([]byte, error) {
	// Only use data shards
	data := make([]byte, 0, outSize)
	for i := 0; i < c.dataShards && len(data) < outSize; i++ {
		remaining := outSize - len(data)
		if remaining >= len(shards[i]) {
			data = append(data, shards[i]...)
		} else {
			data = append(data, shards[i][:remaining]...)
		}
	}
	return data, nil
}

// ShardSize calculates the shard size for a given data size.
func (c *Codec) ShardSize(dataSize int) int {
	shardSize := dataSize / c.dataShards
	if dataSize%c.dataShards != 0 {
		shardSize++
	}
	return shardSize
}

// EncodedSize returns the total size of all shards for a given data size.
func (c *Codec) EncodedSize(dataSize int) int {
	return c.ShardSize(dataSize) * c.TotalShards()
}

// Overhead returns the storage overhead ratio (e.g., 1.4 for 10+4 config).
func (c *Codec) Overhead() float64 {
	return float64(c.TotalShards()) / float64(c.dataShards)
}
