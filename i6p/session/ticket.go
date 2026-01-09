package session

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/TheusHen/I6P/i6p/crypto"
	"github.com/TheusHen/I6P/i6p/identity"
)

var (
	ErrTicketExpired  = errors.New("session: ticket expired")
	ErrTicketInvalid  = errors.New("session: ticket invalid")
	ErrTicketNotFound = errors.New("session: ticket not found")
)

const (
	TicketKeySize   = 32
	TicketNonceSize = 16
	TicketLifetime  = 24 * time.Hour
)

// Ticket enables fast session resumption without full handshake.
// The ticket contains encrypted session state that only the issuer can decrypt.
type Ticket struct {
	ID         [16]byte // unique ticket identifier
	IssuedAt   int64    // unix timestamp
	ExpiresAt  int64
	PeerID     identity.PeerID
	SessionKey [32]byte // pre-shared key for resumed session
}

// TicketStore manages session tickets for resumption.
type TicketStore struct {
	mu      sync.RWMutex
	tickets map[[16]byte]*Ticket
	key     [TicketKeySize]byte // encryption key for ticket data
}

// NewTicketStore creates a new ticket store.
func NewTicketStore() (*TicketStore, error) {
	ts := &TicketStore{
		tickets: make(map[[16]byte]*Ticket),
	}
	if _, err := rand.Read(ts.key[:]); err != nil {
		return nil, err
	}
	return ts, nil
}

// NewTicketStoreWithKey creates a ticket store with a specific key (for clustering).
func NewTicketStoreWithKey(key [TicketKeySize]byte) *TicketStore {
	return &TicketStore{
		tickets: make(map[[16]byte]*Ticket),
		key:     key,
	}
}

// Issue creates a new ticket for the given peer and session key.
func (ts *TicketStore) Issue(peerID identity.PeerID, sessionKey [32]byte) (*Ticket, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	now := time.Now()
	ticket := &Ticket{
		IssuedAt:   now.Unix(),
		ExpiresAt:  now.Add(TicketLifetime).Unix(),
		PeerID:     peerID,
		SessionKey: sessionKey,
	}
	if _, err := rand.Read(ticket.ID[:]); err != nil {
		return nil, err
	}

	ts.tickets[ticket.ID] = ticket
	return ticket, nil
}

// Lookup retrieves and validates a ticket.
func (ts *TicketStore) Lookup(ticketID [16]byte) (*Ticket, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	ticket, ok := ts.tickets[ticketID]
	if !ok {
		return nil, ErrTicketNotFound
	}

	if time.Now().Unix() > ticket.ExpiresAt {
		return nil, ErrTicketExpired
	}

	return ticket, nil
}

// Revoke invalidates a ticket.
func (ts *TicketStore) Revoke(ticketID [16]byte) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	delete(ts.tickets, ticketID)
}

// Cleanup removes expired tickets.
func (ts *TicketStore) Cleanup() int {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	now := time.Now().Unix()
	removed := 0
	for id, ticket := range ts.tickets {
		if now > ticket.ExpiresAt {
			delete(ts.tickets, id)
			removed++
		}
	}
	return removed
}

// EncodeTicket encrypts a ticket for wire transmission.
// Format: ticketID (16) || nonce (16) || encrypted data
func (ts *TicketStore) EncodeTicket(ticket *Ticket) ([]byte, error) {
	// Serialize ticket data
	// peerID (32) + issuedAt (8) + expiresAt (8) + sessionKey (32) = 80 bytes
	plain := make([]byte, 80)
	copy(plain[0:32], ticket.PeerID[:])
	binary.BigEndian.PutUint64(plain[32:40], uint64(ticket.IssuedAt))
	binary.BigEndian.PutUint64(plain[40:48], uint64(ticket.ExpiresAt))
	copy(plain[48:80], ticket.SessionKey[:])

	aead, err := crypto.NewAEAD(ts.key[:])
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(plain, ticket.ID[:])

	out := make([]byte, 16+len(ciphertext))
	copy(out[:16], ticket.ID[:])
	copy(out[16:], ciphertext)

	return out, nil
}

// DecodeTicket decrypts and validates a ticket from wire format.
func (ts *TicketStore) DecodeTicket(data []byte) (*Ticket, error) {
	if len(data) < 16+12+16+80 { // id + nonce + tag + data
		return nil, ErrTicketInvalid
	}

	var ticketID [16]byte
	copy(ticketID[:], data[:16])
	ciphertext := data[16:]

	aead, err := crypto.NewAEAD(ts.key[:])
	if err != nil {
		return nil, err
	}

	plain, err := aead.Open(ciphertext, ticketID[:])
	if err != nil {
		return nil, ErrTicketInvalid
	}

	if len(plain) != 80 {
		return nil, ErrTicketInvalid
	}

	ticket := &Ticket{ID: ticketID}
	copy(ticket.PeerID[:], plain[0:32])
	ticket.IssuedAt = int64(binary.BigEndian.Uint64(plain[32:40]))
	ticket.ExpiresAt = int64(binary.BigEndian.Uint64(plain[40:48]))
	copy(ticket.SessionKey[:], plain[48:80])

	if time.Now().Unix() > ticket.ExpiresAt {
		return nil, ErrTicketExpired
	}

	return ticket, nil
}

// Count returns the number of active tickets.
func (ts *TicketStore) Count() int {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return len(ts.tickets)
}
