package protocol

import (
	"encoding/binary"
	"io"
	"net"
)

func Receive(conn *net.TCPConn) (*Message, error) {
	// Get size of message
	lenBuf, rErr := readN(conn, 4)
	if rErr != nil {
		return nil, rErr
	}
	dataLen := binary.BigEndian.Uint32(lenBuf)

	msgBuf, rErr := readN(conn, int(dataLen))
	if rErr != nil {
		return nil, rErr
	}

	var msg Message
	err := msg.Unmarshal(msgBuf)
	if err != nil {
		return nil, err
	}
	return &msg, nil
}

func readN(conn *net.TCPConn, n int) ([]byte, error) {
	buf := make([]byte, n)

	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	return buf, nil
}
