package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/TheusHen/I6P/i6p"
	"github.com/TheusHen/I6P/i6p/identity"
	"github.com/TheusHen/I6P/i6p/transfer"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverKP, _ := identity.GenerateKeyPair()
	clientKP, _ := identity.GenerateKeyPair()

	server := i6p.NewPeer(serverKP, map[string]string{
		"role":    "server",
		"feature": "bulk-transfer",
	})
	if err := server.Listen("[::1]:0"); err != nil {
		log.Fatalf("server listen: %v", err)
	}
	defer server.Close()

	addr := server.ListenAddr()
	log.Printf("Server listening on %s", addr)
	log.Printf("Server PeerID: %s", serverKP.PeerID().String()[:16]+"...")

	// Generate test data (1 MB)
	dataSize := 1024 * 1024
	testData := make([]byte, dataSize)
	if _, err := rand.Read(testData); err != nil {
		log.Fatalf("generate test data: %v", err)
	}
	log.Printf("Generated %d bytes of test data", dataSize)

	// Server goroutine
	resultCh := make(chan []byte, 1)
	errCh := make(chan error, 1)

	go func() {
		sess, err := server.Accept(ctx)
		if err != nil {
			errCh <- fmt.Errorf("accept: %w", err)
			return
		}
		log.Printf("Server accepted connection from %s", sess.RemotePeerID().String()[:16]+"...")

		st, err := sess.AcceptStream(ctx)
		if err != nil {
			errCh <- fmt.Errorf("accept stream: %w", err)
			return
		}
		defer st.Close()

		// Receive data using bulk receiver
		receiver := transfer.NewBulkReceiver(transfer.DefaultTransferConfig())

		for {
			batch, err := transfer.ReadBatch(st)
			if err != nil {
				if err == io.EOF {
					break
				}
				errCh <- fmt.Errorf("read batch: %w", err)
				return
			}
			if err := receiver.ReceiveBatch(batch); err != nil {
				errCh <- fmt.Errorf("receive batch: %w", err)
				return
			}
		}

		data, err := receiver.Assemble(nil)
		if err != nil {
			errCh <- fmt.Errorf("assemble: %w", err)
			return
		}

		log.Printf("Server received %d bytes, %d chunks", len(data), receiver.Stats().ChunksReceived.Load())
		resultCh <- data
	}()

	// Client sends data
	client := i6p.NewPeer(clientKP, map[string]string{
		"role":    "client",
		"feature": "bulk-transfer",
	})

	sess, err := client.Dial(ctx, addr)
	if err != nil {
		log.Fatalf("client dial: %v", err)
	}
	log.Printf("Client connected to %s", sess.RemotePeerID().String()[:16]+"...")

	st, err := sess.OpenStream(ctx)
	if err != nil {
		log.Fatalf("open stream: %v", err)
	}

	// Send using chunker + compression + batching
	config := transfer.DefaultTransferConfig()
	chunker := transfer.NewChunker(config.ChunkSize)
	chunks := chunker.Split(testData)

	log.Printf("Sending %d chunks (chunk size: %d bytes)", len(chunks), config.ChunkSize)

	start := time.Now()

	// Send in batches
	batch := transfer.NewBatch()
	batchSize := 0
	maxBatchSize := 256 * 1024 // 256 KB per batch

	for _, chunk := range chunks {
		cc := transfer.CompressChunk(chunk, config.Compression)
		batch.Add(cc)
		batchSize += len(cc.Data)

		if batchSize >= maxBatchSize {
			if err := transfer.WriteBatch(st, batch); err != nil {
				log.Fatalf("write batch: %v", err)
			}
			batch = transfer.NewBatch()
			batchSize = 0
		}
	}

	// Send remaining
	if len(batch.Chunks) > 0 {
		if err := transfer.WriteBatch(st, batch); err != nil {
			log.Fatalf("write final batch: %v", err)
		}
	}

	_ = st.Close()
	elapsed := time.Since(start)

	log.Printf("Client sent %d bytes in %v", dataSize, elapsed)
	log.Printf("Throughput: %.2f MB/s", float64(dataSize)/elapsed.Seconds()/1024/1024)

	// Wait for result
	select {
	case received := <-resultCh:
		if bytes.Equal(received, testData) {
			log.Printf("✓ Data integrity verified!")
		} else {
			log.Printf("✗ Data mismatch!")
		}
	case err := <-errCh:
		log.Fatalf("Error: %v", err)
	case <-ctx.Done():
		log.Fatalf("Timeout")
	}
}
