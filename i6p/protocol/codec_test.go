package protocol

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := Frame{Type: MessageTypeAck, Payload: []byte("ok")}
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	out, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if out.Type != in.Type {
		t.Fatalf("type mismatch")
	}
	if !bytes.Equal(out.Payload, in.Payload) {
		t.Fatalf("payload mismatch")
	}
}
