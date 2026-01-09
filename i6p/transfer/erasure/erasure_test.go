package erasure

import (
	"bytes"
	"testing"
)

func TestCodecRoundTrip(t *testing.T) {
	codec, err := NewCodec(10, 4)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}

	data := []byte("Hello, I6P erasure coding test data that spans multiple shards!")
	originalSize := len(data)

	shards, err := codec.EncodeData(data)
	if err != nil {
		t.Fatalf("EncodeData: %v", err)
	}

	if len(shards) != 14 {
		t.Fatalf("expected 14 shards, got %d", len(shards))
	}

	// Verify
	ok, err := codec.Verify(shards)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatalf("verification failed")
	}

	// Simulate losing 4 shards (the maximum we can lose)
	shards[0] = nil
	shards[5] = nil
	shards[10] = nil
	shards[13] = nil

	// Reconstruct
	if err := codec.Reconstruct(shards); err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}

	// Join
	recovered, err := codec.Join(shards, originalSize)
	if err != nil {
		t.Fatalf("Join: %v", err)
	}

	if !bytes.Equal(recovered, data) {
		t.Fatalf("recovered data does not match original")
	}
}

func TestCodecTooManyLost(t *testing.T) {
	codec, err := NewCodec(10, 4)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}

	data := make([]byte, 1024)
	shards, _ := codec.EncodeData(data)

	// Lose 5 shards (more than parity allows)
	shards[0] = nil
	shards[1] = nil
	shards[2] = nil
	shards[3] = nil
	shards[4] = nil

	err = codec.Reconstruct(shards)
	if err != ErrTooManyLost {
		t.Fatalf("expected ErrTooManyLost, got %v", err)
	}
}

func TestCodecOverhead(t *testing.T) {
	codec, _ := NewCodec(10, 4)
	overhead := codec.Overhead()
	if overhead < 1.39 || overhead > 1.41 {
		t.Fatalf("unexpected overhead: %f", overhead)
	}
}

func BenchmarkEncode(b *testing.B) {
	codec, _ := NewCodec(10, 4)
	data := make([]byte, 1024*1024) // 1 MB
	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = codec.EncodeData(data)
	}
}

func BenchmarkReconstruct(b *testing.B) {
	codec, _ := NewCodec(10, 4)
	data := make([]byte, 1024*1024)
	shards, _ := codec.EncodeData(data)

	// Make a copy with some shards removed
	template := make([][]byte, len(shards))
	for i := range shards {
		if i < 4 {
			template[i] = nil // lose first 4 shards
		} else {
			template[i] = shards[i]
		}
	}

	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Copy template
		work := make([][]byte, len(template))
		copy(work, template)
		_ = codec.Reconstruct(work)
	}
}
