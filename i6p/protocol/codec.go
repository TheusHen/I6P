package protocol

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// MaxFramePayload limits a single protocol frame payload.
	MaxFramePayload = 1 << 20 // 1 MiB
)

var (
	ErrFrameTooLarge = errors.New("protocol frame payload too large")
	ErrInvalidType   = errors.New("protocol invalid message type")
)

// Frame is the basic wire container.
// Format:
//
//	1 byte: type
//	4 bytes: payload length (big endian)
//	N bytes: payload
//
// Frames are intended for a dedicated control stream.
type Frame struct {
	Type    MessageType
	Payload []byte
}

func WriteFrame(w io.Writer, f Frame) error {
	if f.Type == 0 {
		return ErrInvalidType
	}
	if len(f.Payload) > MaxFramePayload {
		return ErrFrameTooLarge
	}

	bw := bufio.NewWriter(w)
	if err := bw.WriteByte(byte(f.Type)); err != nil {
		return err
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(f.Payload)))
	if _, err := bw.Write(lenBuf[:]); err != nil {
		return err
	}
	if len(f.Payload) > 0 {
		if _, err := bw.Write(f.Payload); err != nil {
			return err
		}
	}
	return bw.Flush()
}

func ReadFrame(r io.Reader) (Frame, error) {
	br := bufio.NewReader(r)
	t, err := br.ReadByte()
	if err != nil {
		return Frame{}, err
	}
	var lenBuf [4]byte
	if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
		return Frame{}, err
	}
	payloadLen := binary.BigEndian.Uint32(lenBuf[:])
	if payloadLen > MaxFramePayload {
		return Frame{}, fmt.Errorf("%w: %d", ErrFrameTooLarge, payloadLen)
	}
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(br, payload); err != nil {
			return Frame{}, err
		}
	}

	mt := MessageType(t)
	if mt == 0 {
		return Frame{}, ErrInvalidType
	}
	return Frame{Type: mt, Payload: payload}, nil
}
