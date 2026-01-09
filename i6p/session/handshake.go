package session

import (
	"context"
	"errors"

	"github.com/TheusHen/I6P/i6p/identity"
	"github.com/TheusHen/I6P/i6p/protocol"
	q "github.com/quic-go/quic-go"
)

var (
	ErrHandshakeExpectedHello = errors.New("handshake expected HELLO")
)

type HandshakeOptions struct {
	Capabilities map[string]string
}

// HandshakeClient performs the I6P session handshake as a client.
// The client opens a dedicated control stream.
func HandshakeClient(ctx context.Context, conn q.Connection, kp identity.KeyPair, opts HandshakeOptions) (*Session, error) {
	control, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}

	localHello, err := protocol.NewHello(kp, opts.Capabilities)
	if err != nil {
		return nil, err
	}
	if err := localHello.Sign(kp); err != nil {
		return nil, err
	}
	payload, err := protocol.EncodeHello(localHello)
	if err != nil {
		return nil, err
	}
	if err := protocol.WriteFrame(control, protocol.Frame{Type: protocol.MessageTypeHello, Payload: payload}); err != nil {
		return nil, err
	}

	frame, err := protocol.ReadFrame(control)
	if err != nil {
		return nil, err
	}
	if frame.Type != protocol.MessageTypeHello {
		return nil, ErrHandshakeExpectedHello
	}
	remoteHello, err := protocol.DecodeHello(frame.Payload)
	if err != nil {
		return nil, err
	}
	if err := remoteHello.Verify(); err != nil {
		return nil, err
	}
	remoteID, err := identity.ParsePeerIDHex(remoteHello.PeerID)
	if err != nil {
		return nil, err
	}

	return &Session{
		conn:         conn,
		control:      control,
		controlID:    control.StreamID(),
		localPeerID:  kp.PeerID(),
		remotePeerID: remoteID,
		caps:         remoteHello.Capabilities,
	}, nil
}

// HandshakeServer performs the I6P session handshake as a server.
// The server accepts a dedicated control stream (opened by the client).
func HandshakeServer(ctx context.Context, conn q.Connection, kp identity.KeyPair, opts HandshakeOptions) (*Session, error) {
	control, err := conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}

	frame, err := protocol.ReadFrame(control)
	if err != nil {
		return nil, err
	}
	if frame.Type != protocol.MessageTypeHello {
		return nil, ErrHandshakeExpectedHello
	}
	remoteHello, err := protocol.DecodeHello(frame.Payload)
	if err != nil {
		return nil, err
	}
	if err := remoteHello.Verify(); err != nil {
		return nil, err
	}
	remoteID, err := identity.ParsePeerIDHex(remoteHello.PeerID)
	if err != nil {
		return nil, err
	}

	localHello, err := protocol.NewHello(kp, opts.Capabilities)
	if err != nil {
		return nil, err
	}
	if err := localHello.Sign(kp); err != nil {
		return nil, err
	}
	payload, err := protocol.EncodeHello(localHello)
	if err != nil {
		return nil, err
	}
	if err := protocol.WriteFrame(control, protocol.Frame{Type: protocol.MessageTypeHello, Payload: payload}); err != nil {
		return nil, err
	}

	return &Session{
		conn:         conn,
		control:      control,
		controlID:    control.StreamID(),
		localPeerID:  kp.PeerID(),
		remotePeerID: remoteID,
		caps:         remoteHello.Capabilities,
	}, nil
}
