package transfer

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
)

var (
	ErrPoolClosed     = errors.New("transfer: stream pool closed")
	ErrPoolExhausted  = errors.New("transfer: no available streams")
)

// StreamOpener is the interface for opening new streams.
type StreamOpener interface {
	OpenStreamSync(ctx context.Context) (io.ReadWriteCloser, error)
}

// StreamPool manages a pool of parallel streams for high-throughput transfers.
// Multiple streams can saturate the available bandwidth more effectively than a single stream.
type StreamPool struct {
	opener  StreamOpener
	maxSize int
	streams chan io.ReadWriteCloser
	mu      sync.Mutex
	closed  atomic.Bool
	created atomic.Int32
}

// NewStreamPool creates a pool that can manage up to maxSize concurrent streams.
func NewStreamPool(opener StreamOpener, maxSize int) *StreamPool {
	if maxSize <= 0 {
		maxSize = 8
	}
	return &StreamPool{
		opener:  opener,
		maxSize: maxSize,
		streams: make(chan io.ReadWriteCloser, maxSize),
	}
}

// Acquire gets a stream from the pool or opens a new one.
func (p *StreamPool) Acquire(ctx context.Context) (io.ReadWriteCloser, error) {
	if p.closed.Load() {
		return nil, ErrPoolClosed
	}

	// Try to get an existing stream first
	select {
	case s := <-p.streams:
		return s, nil
	default:
	}

	// Try to create a new stream if under limit
	if int(p.created.Load()) < p.maxSize {
		p.mu.Lock()
		if int(p.created.Load()) < p.maxSize {
			p.created.Add(1)
			p.mu.Unlock()
			s, err := p.opener.OpenStreamSync(ctx)
			if err != nil {
				p.created.Add(-1)
				return nil, err
			}
			return s, nil
		}
		p.mu.Unlock()
	}

	// Wait for an available stream
	select {
	case s := <-p.streams:
		return s, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Release returns a stream to the pool for reuse.
func (p *StreamPool) Release(s io.ReadWriteCloser) {
	if p.closed.Load() {
		_ = s.Close()
		return
	}

	select {
	case p.streams <- s:
	default:
		// Pool is full, close the stream
		_ = s.Close()
		p.created.Add(-1)
	}
}

// Close closes all streams in the pool.
func (p *StreamPool) Close() error {
	if p.closed.Swap(true) {
		return nil
	}

	close(p.streams)
	for s := range p.streams {
		_ = s.Close()
	}
	return nil
}

// Size returns the current number of pooled streams.
func (p *StreamPool) Size() int {
	return len(p.streams)
}

// Created returns the total number of streams created.
func (p *StreamPool) Created() int {
	return int(p.created.Load())
}

// ParallelWriter provides parallel chunk transmission across multiple streams.
type ParallelWriter struct {
	pool      *StreamPool
	workers   int
	chunkChan chan CompressedChunk
	errChan   chan error
	wg        sync.WaitGroup
}

// NewParallelWriter creates a writer that sends chunks in parallel.
func NewParallelWriter(pool *StreamPool, workers int) *ParallelWriter {
	if workers <= 0 {
		workers = 4
	}
	return &ParallelWriter{
		pool:      pool,
		workers:   workers,
		chunkChan: make(chan CompressedChunk, workers*2),
		errChan:   make(chan error, workers),
	}
}

// Start begins the worker goroutines.
func (pw *ParallelWriter) Start(ctx context.Context) {
	for i := 0; i < pw.workers; i++ {
		pw.wg.Add(1)
		go pw.worker(ctx)
	}
}

func (pw *ParallelWriter) worker(ctx context.Context) {
	defer pw.wg.Done()

	for {
		select {
		case chunk, ok := <-pw.chunkChan:
			if !ok {
				return
			}
			if err := pw.sendChunk(ctx, chunk); err != nil {
				select {
				case pw.errChan <- err:
				default:
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

func (pw *ParallelWriter) sendChunk(ctx context.Context, chunk CompressedChunk) error {
	stream, err := pw.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer pw.pool.Release(stream)

	// Create a single-chunk batch for transmission
	batch := NewBatch()
	batch.Add(chunk)
	return WriteBatch(stream, batch)
}

// Send queues a chunk for transmission.
func (pw *ParallelWriter) Send(chunk CompressedChunk) error {
	select {
	case err := <-pw.errChan:
		return err
	default:
	}

	pw.chunkChan <- chunk
	return nil
}

// Wait waits for all pending chunks to be sent.
func (pw *ParallelWriter) Wait() error {
	close(pw.chunkChan)
	pw.wg.Wait()

	select {
	case err := <-pw.errChan:
		return err
	default:
		return nil
	}
}

// ParallelReader provides parallel chunk reception across multiple streams.
type ParallelReader struct {
	pool       *StreamPool
	workers    int
	resultChan chan Chunk
	errChan    chan error
	wg         sync.WaitGroup
}

// NewParallelReader creates a reader that receives chunks in parallel.
func NewParallelReader(pool *StreamPool, workers int, bufferSize int) *ParallelReader {
	if workers <= 0 {
		workers = 4
	}
	if bufferSize <= 0 {
		bufferSize = workers * 2
	}
	return &ParallelReader{
		pool:       pool,
		workers:    workers,
		resultChan: make(chan Chunk, bufferSize),
		errChan:    make(chan error, workers),
	}
}

// StartReader begins reading from a single stream (for testing).
func (pr *ParallelReader) StartReader(ctx context.Context, stream io.ReadWriteCloser) {
	pr.wg.Add(1)
	go func() {
		defer pr.wg.Done()
		pr.readFromStream(ctx, stream)
	}()
}

func (pr *ParallelReader) readFromStream(ctx context.Context, stream io.ReadWriteCloser) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		batch, err := ReadBatch(stream)
		if err != nil {
			if err != io.EOF {
				select {
				case pr.errChan <- err:
				default:
				}
			}
			return
		}

		for _, cc := range batch.Chunks {
			chunk, err := DecompressChunk(cc)
			if err != nil {
				select {
				case pr.errChan <- err:
				default:
				}
				continue
			}
			select {
			case pr.resultChan <- chunk:
			case <-ctx.Done():
				return
			}
		}
	}
}

// Results returns the channel for received chunks.
func (pr *ParallelReader) Results() <-chan Chunk {
	return pr.resultChan
}

// Errors returns the channel for errors.
func (pr *ParallelReader) Errors() <-chan error {
	return pr.errChan
}

// Wait waits for all readers to complete.
func (pr *ParallelReader) Wait() {
	pr.wg.Wait()
	close(pr.resultChan)
}
