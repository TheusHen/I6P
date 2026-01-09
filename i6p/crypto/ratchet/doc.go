// Package ratchet provides continuous forward secrecy via symmetric key ratcheting.
//
// The ratchet advances the encryption key after each message or batch, so that
// compromise of the current key does not reveal past messages.
//
// This is a single-ratchet (symmetric) design suitable for unidirectional streams.
// For bidirectional communication, use two ratchets (one per direction).
package ratchet
