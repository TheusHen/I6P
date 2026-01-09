package memory

import (
	"sync"

	"github.com/TheusHen/I6P/i6p/discovery"
	"github.com/TheusHen/I6P/i6p/identity"
)

// Store is an in-memory discovery resolver.
// It is useful for tests, examples and embedding in applications.
type Store struct {
	mu    sync.RWMutex
	peers map[identity.PeerID]discovery.AddrInfo
}

func New() *Store {
	return &Store{peers: map[identity.PeerID]discovery.AddrInfo{}}
}

func (s *Store) Announce(info discovery.AddrInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyCaps := map[string]string{}
	for k, v := range info.Capabilities {
		copyCaps[k] = v
	}
	info.Capabilities = copyCaps
	s.peers[info.PeerID] = info
	return nil
}

func (s *Store) Lookup(peerID identity.PeerID) (discovery.AddrInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	info, ok := s.peers[peerID]
	if !ok {
		return discovery.AddrInfo{}, discovery.ErrNotFound
	}
	copyCaps := map[string]string{}
	for k, v := range info.Capabilities {
		copyCaps[k] = v
	}
	info.Capabilities = copyCaps
	return info, nil
}

func (s *Store) List() ([]discovery.AddrInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]discovery.AddrInfo, 0, len(s.peers))
	for _, info := range s.peers {
		copyCaps := map[string]string{}
		for k, v := range info.Capabilities {
			copyCaps[k] = v
		}
		info.Capabilities = copyCaps
		out = append(out, info)
	}
	return out, nil
}
