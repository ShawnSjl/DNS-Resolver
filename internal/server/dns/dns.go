package dns

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/miekg/dns"
)

const (
	MTU            = 1500
	UDPHeaderSize  = 8
	IPv4HeaderSize = 20
	IPv6HeaderSize = 40
	UDP4MTU        = MTU - IPv4HeaderSize - UDPHeaderSize
	UDP6MTU        = MTU - IPv6HeaderSize - UDPHeaderSize
)

type DNS struct {
	ctx    context.Context
	cancel context.CancelFunc

	// inside
	sendInsideQueue     *SendInside
	receivedInsideQueue *ReceiveInside

	// outside
	sendOutsideQueue     *SendOutside
	receivedOutsideQueue *ReceiveOutside

	// cache
	cache *RecordCache

	// question table
	questionTable *QuestionTable

	// blocked domains
	blocked *Blacklist
}

// ******************** Initialization Interface **********************

func NewDNS(parent context.Context) *DNS {
	ctx, cancel := context.WithCancel(parent)
	return &DNS{
		ctx:                  ctx,
		cancel:               cancel,
		sendInsideQueue:      NewSendInside(ctx),
		receivedInsideQueue:  NewReceiveInside(ctx),
		sendOutsideQueue:     NewSendOutside(ctx),
		receivedOutsideQueue: NewReceiveOutside(ctx),
		cache:                NewRecordCache(ctx),
		questionTable:        NewQuestionTable(ctx),
		blocked:              NewBlacklist(),
	}
}

// ******************** Server **********************

func (d *DNS) Run(port uint16) {
	go func() {
		// Create a IPV4 UDP socket listening on specified port
		udpAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("0.0.0.0:%d", port))
		if err != nil {
			log.Fatal("Fail to resolve UDP address: ", err)
		}
		conn, err := net.ListenUDP("udp4", udpAddr)
		if err != nil {
			log.Fatal("Fail to listen UDP: ", err)
		}
		defer func(conn *net.UDPConn) {
			if closeErr := conn.Close(); closeErr != nil {
				log.Println("Fail to close UDP connection: ", closeErr)
			}
		}(conn)

		buffer := make([]byte, UDP4MTU)
		for {
			select {
			case <-d.ctx.Done():
				return

			default:
				// Read UDP packet from socket
				n, addr, readErr := conn.ReadFrom(buffer)
				if readErr != nil {
					log.Println("Fail to read UDP: ", readErr)
					continue
				}

				log.Printf("Received UDP from %s: \n", addr)

				// Unpack the UDP packet into a DNS message
				var msg dns.Msg
				if unpackErr := msg.Unpack(buffer[:n]); unpackErr != nil {
					log.Println("Fail to unpack UDP: ", unpackErr)
					continue
				}

				log.Println("Received UDP from: ", msg.String())
			}
		}
	}()
}

func (d *DNS) Terminate() {
	d.cancel()
}
