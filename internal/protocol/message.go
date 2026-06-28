package protocol

import (
	"fmt"
)

type Message struct {
	MsgType MessageType
	Data    []byte
}

type MessageType uint8

const (
	MsgAck MessageType = iota
	MsgError

	MsgBlockAdd
	MsgBlockRemove
	MsgBlockList

	MsgCacheList
)

func (m *Message) Marshal() ([]byte, error) {
	dataLen := uint32(len(m.Data))

	buffer := make([]byte, 1+dataLen)
	buffer[0] = byte(m.MsgType)
	copy(buffer[1:], m.Data)

	return buffer, nil
}

func (m *Message) Unmarshal(buffer []byte) error {
	if len(buffer) < 1 {
		return fmt.Errorf("buffer too short")
	}
	m.MsgType = MessageType(buffer[0])
	m.Data = buffer[1:]
	return nil
}
