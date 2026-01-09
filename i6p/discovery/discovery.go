package discovery

import (
	"errors"
	"net/netip"

	"github.com/TheusHen/I6P/i6p/identity"
)

var (
	ErrNotFound = errors.New("peer not found")
)

// AddrInfo is the minimal set of information discovery provides.
// The application is responsible for deciding how to use capabilities.
type AddrInfo struct {
	PeerID       identity.PeerID
	Addr         netip.Addr
	Port         uint16
	Capabilities map[string]string
}

// Resolver is a generic discovery interface.
// Implementations can be backed by DHT, mDNS/DNS-SD, bootstrap lists, etc.
type Resolver interface {
	Announce(info AddrInfo) error
	Lookup(peerID identity.PeerID) (AddrInfo, error)
	List() ([]AddrInfo, error)
}
