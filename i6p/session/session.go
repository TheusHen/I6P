package session

import (
	"context"

	"github.com/TheusHen/I6P/i6p/identity"
	q "github.com/quic-go/quic-go"
)

// Session is an authenticated I6P session over a QUIC connection.
// The QUIC connection provides encryption; identity is bound via the signed HELLO exchange.
type Session struct {
	conn         q.Connection
	control      q.Stream
	controlID    q.StreamID
	localPeerID  identity.PeerID
	remotePeerID identity.PeerID
	caps         map[string]string
}

func (s *Session) Connection() q.Connection { return s.conn }

func (s *Session) LocalPeerID() identity.PeerID { return s.localPeerID }

func (s *Session) RemotePeerID() identity.PeerID { return s.remotePeerID }

func (s *Session) RemoteCapabilities() map[string]string {
	out := map[string]string{}
	for k, v := range s.caps {
		out[k] = v
	}
	return out
}

// OpenStream opens an application data stream.
func (s *Session) OpenStream(ctx context.Context) (q.Stream, error) {
	return s.conn.OpenStreamSync(ctx)
}

// AcceptStream accepts an application data stream, skipping the control stream.
func (s *Session) AcceptStream(ctx context.Context) (q.Stream, error) {
	for {
		st, err := s.conn.AcceptStream(ctx)
		if err != nil {
			return nil, err
		}
		if st.StreamID() == s.controlID {
			_ = st.Close()
			continue
		}
		return st, nil
	}
}

func (s *Session) CloseWithError(code q.ApplicationErrorCode, msg string) error {
	return s.conn.CloseWithError(code, msg)
}
