package i6p

import (
	"context"
	"errors"

	"github.com/TheusHen/I6P/i6p/identity"
	"github.com/TheusHen/I6P/i6p/session"
	"github.com/TheusHen/I6P/i6p/transport/quic"
)

var ErrNotListening = errors.New("peer is not listening")

// Peer is a high-level helper that combines transport + session.
// It intentionally stays small so applications can customize discovery and higher-level behavior.
type Peer struct {
	KeyPair      identity.KeyPair
	Capabilities map[string]string
	listener     *quic.Listener
}

func NewPeer(kp identity.KeyPair, capabilities map[string]string) *Peer {
	capsCopy := map[string]string{}
	for k, v := range capabilities {
		capsCopy[k] = v
	}
	return &Peer{KeyPair: kp, Capabilities: capsCopy}
}

func (p *Peer) Listen(addr string) error {
	ln, err := quic.Listen(addr)
	if err != nil {
		return err
	}
	p.listener = ln
	return nil
}

func (p *Peer) Close() error {
	if p.listener == nil {
		return nil
	}
	return p.listener.Close()
}

func (p *Peer) ListenAddr() string {
	if p.listener == nil {
		return ""
	}
	return p.listener.AddrString()
}

func (p *Peer) Accept(ctx context.Context) (*session.Session, error) {
	if p.listener == nil {
		return nil, ErrNotListening
	}
	conn, err := p.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return session.HandshakeServer(ctx, conn, p.KeyPair, session.HandshakeOptions{Capabilities: p.Capabilities})
}

func (p *Peer) Dial(ctx context.Context, addr string) (*session.Session, error) {
	conn, err := quic.Dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	return session.HandshakeClient(ctx, conn, p.KeyPair, session.HandshakeOptions{Capabilities: p.Capabilities})
}
