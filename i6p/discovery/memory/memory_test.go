package memory

import (
	"net/netip"
	"testing"

	"github.com/TheusHen/I6P/i6p/discovery"
	"github.com/TheusHen/I6P/i6p/identity"
)

func TestStoreAnnounceLookup(t *testing.T) {
	kp, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	s := New()
	info := discovery.AddrInfo{
		PeerID: kp.PeerID(),
		Addr:   netip.MustParseAddr("2001:db8::1"),
		Port:   4242,
		Capabilities: map[string]string{
			"role": "seed",
		},
	}
	if err := s.Announce(info); err != nil {
		t.Fatalf("Announce: %v", err)
	}

	got, err := s.Lookup(kp.PeerID())
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Port != info.Port || got.Addr != info.Addr {
		t.Fatalf("unexpected addrinfo")
	}
	if got.Capabilities["role"] != "seed" {
		t.Fatalf("unexpected capabilities")
	}
}
