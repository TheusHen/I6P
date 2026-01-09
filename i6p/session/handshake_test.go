package session

import (
	"context"
	"testing"
	"time"

	"github.com/TheusHen/I6P/i6p/identity"
	"github.com/TheusHen/I6P/i6p/transport/quic"
)

func TestHandshakeClientServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverKP, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatalf("server GenerateKeyPair: %v", err)
	}
	clientKP, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatalf("client GenerateKeyPair: %v", err)
	}

	ln, err := quic.Listen("[::1]:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	addr := ln.AddrString()
	if addr == "" {
		t.Fatalf("expected listener addr")
	}

	errCh := make(chan error, 1)
	var serverRemote identity.PeerID

	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			errCh <- err
			return
		}
		sess, err := HandshakeServer(ctx, conn, serverKP, HandshakeOptions{Capabilities: map[string]string{"role": "server"}})
		if err != nil {
			errCh <- err
			return
		}
		serverRemote = sess.RemotePeerID()
		errCh <- nil
	}()

	conn, err := quic.Dial(ctx, addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	clientSess, err := HandshakeClient(ctx, conn, clientKP, HandshakeOptions{Capabilities: map[string]string{"role": "client"}})
	if err != nil {
		t.Fatalf("HandshakeClient: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	if clientSess.RemotePeerID() != serverKP.PeerID() {
		t.Fatalf("client expected server peerid")
	}
	if serverRemote != clientKP.PeerID() {
		t.Fatalf("server expected client peerid")
	}
}
