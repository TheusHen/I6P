package protocol

type MessageType uint8

const (
	MessageTypeHello    MessageType = 1
	MessageTypePeerInfo MessageType = 2
	MessageTypeData     MessageType = 3
	MessageTypeAck      MessageType = 4
	MessageTypeClose    MessageType = 5
)

func (t MessageType) String() string {
	switch t {
	case MessageTypeHello:
		return "HELLO"
	case MessageTypePeerInfo:
		return "PEER_INFO"
	case MessageTypeData:
		return "DATA"
	case MessageTypeAck:
		return "ACK"
	case MessageTypeClose:
		return "CLOSE"
	default:
		return "UNKNOWN"
	}
}
