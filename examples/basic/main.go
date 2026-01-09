package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/TheusHen/I6P/i6p"
	"github.com/TheusHen/I6P/i6p/identity"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverKP, err := identity.GenerateKeyPair()
	if err != nil {
		log.Fatalf("server identity: %v", err)
	}
	clientKP, err := identity.GenerateKeyPair()
	if err != nil {
		log.Fatalf("client identity: %v", err)
	}

	server := i6p.NewPeer(serverKP, map[string]string{"role": "server"})
	if err := server.Listen("[::1]:0"); err != nil {
		log.Fatalf("server listen: %v", err)
	}
	defer server.Close()

	addr := server.ListenAddr()
	log.Printf("server listening on %s", addr)

	errCh := make(chan error, 1)
	go func() {
		sess, err := server.Accept(ctx)
		if err != nil {
			errCh <- err
			return
		}
		st, err := sess.AcceptStream(ctx)
		if err != nil {
			errCh <- err
			return
		}
		defer st.Close()
		b, err := io.ReadAll(st)
		if err != nil {
			errCh <- err
			return
		}
		log.Printf("server got: %q from %s", string(b), sess.RemotePeerID().String())
		errCh <- nil
	}()

	client := i6p.NewPeer(clientKP, map[string]string{"role": "client"})
	csess, err := client.Dial(ctx, addr)
	if err != nil {
		log.Fatalf("client dial: %v", err)
	}

	st, err := csess.OpenStream(ctx)
	if err != nil {
		log.Fatalf("open stream: %v", err)
	}
	_, _ = fmt.Fprint(st, "hello over i6p")
	_ = st.Close()

	if err := <-errCh; err != nil {
		log.Fatalf("server error: %v", err)
	}
	log.Printf("done")
}
