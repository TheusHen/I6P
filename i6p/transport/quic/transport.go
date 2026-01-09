package quic

import (
	"context"
	"net"

	q "github.com/quic-go/quic-go"
)

type Listener struct {
	inner *q.Listener
}

func Listen(addr string) (*Listener, error) {
	tlsConf, err := NewServerTLSConfig()
	if err != nil {
		return nil, err
	}
	ln, err := q.ListenAddr(addr, tlsConf, &q.Config{})
	if err != nil {
		return nil, err
	}
	return &Listener{inner: ln}, nil
}

func (l *Listener) Accept(ctx context.Context) (*q.Conn, error) {
	return l.inner.Accept(ctx)
}

func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

func (l *Listener) AddrString() string {
	if l.inner == nil {
		return ""
	}
	return l.inner.Addr().String()
}

func (l *Listener) Close() error { return l.inner.Close() }

func Dial(ctx context.Context, addr string) (*q.Conn, error) {
	tlsConf, err := NewClientTLSConfig()
	if err != nil {
		return nil, err
	}
	return q.DialAddr(ctx, addr, tlsConf, &q.Config{})
}
