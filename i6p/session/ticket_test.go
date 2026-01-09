package session

import (
	"testing"
	"time"

	"github.com/TheusHen/I6P/i6p/identity"
)

func TestTicketIssueAndLookup(t *testing.T) {
	store, err := NewTicketStore()
	if err != nil {
		t.Fatalf("NewTicketStore: %v", err)
	}

	kp, _ := identity.GenerateKeyPair()
	var sessionKey [32]byte
	for i := range sessionKey {
		sessionKey[i] = byte(i)
	}

	ticket, err := store.Issue(kp.PeerID(), sessionKey)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if store.Count() != 1 {
		t.Fatalf("expected 1 ticket, got %d", store.Count())
	}

	got, err := store.Lookup(ticket.ID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.PeerID != kp.PeerID() {
		t.Fatalf("PeerID mismatch")
	}
	if got.SessionKey != sessionKey {
		t.Fatalf("SessionKey mismatch")
	}
}

func TestTicketEncodeDeccode(t *testing.T) {
	store, _ := NewTicketStore()
	kp, _ := identity.GenerateKeyPair()
	var sessionKey [32]byte

	ticket, _ := store.Issue(kp.PeerID(), sessionKey)

	encoded, err := store.EncodeTicket(ticket)
	if err != nil {
		t.Fatalf("EncodeTicket: %v", err)
	}

	decoded, err := store.DecodeTicket(encoded)
	if err != nil {
		t.Fatalf("DecodeTicket: %v", err)
	}

	if decoded.ID != ticket.ID {
		t.Fatalf("ID mismatch")
	}
	if decoded.PeerID != ticket.PeerID {
		t.Fatalf("PeerID mismatch")
	}
}

func TestTicketExpiration(t *testing.T) {
	store, _ := NewTicketStore()
	kp, _ := identity.GenerateKeyPair()
	var sessionKey [32]byte

	ticket, _ := store.Issue(kp.PeerID(), sessionKey)
	// Manually expire the ticket
	ticket.ExpiresAt = time.Now().Add(-time.Hour).Unix()
	store.tickets[ticket.ID] = ticket

	_, err := store.Lookup(ticket.ID)
	if err != ErrTicketExpired {
		t.Fatalf("expected ErrTicketExpired, got %v", err)
	}
}

func TestTicketRevoke(t *testing.T) {
	store, _ := NewTicketStore()
	kp, _ := identity.GenerateKeyPair()
	var sessionKey [32]byte

	ticket, _ := store.Issue(kp.PeerID(), sessionKey)
	store.Revoke(ticket.ID)

	_, err := store.Lookup(ticket.ID)
	if err != ErrTicketNotFound {
		t.Fatalf("expected ErrTicketNotFound, got %v", err)
	}
}
