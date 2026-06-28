package protocol

import (
	"encoding/binary"
	"fmt"
	"net"
)

func Send(conn *net.TCPConn, msg *Message) error {
	// Marshal message
	payload, err := msg.Marshal()
	if err != nil {
		return err
	}

	// Prepend payload size
	payloadSize := make([]byte, 4)
	binary.BigEndian.PutUint32(payloadSize, uint32(len(payload)))

	// Send message
	payload = append(payloadSize, payload...)
	n, err := conn.Write(payload)
	if err != nil {
		return err
	}
	if n != len(payload) {
		return fmt.Errorf("fail to write all payload")
	}
	return nil
}
