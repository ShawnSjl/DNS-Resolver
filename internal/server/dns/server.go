package dns

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	MTU            = 1500
	UDPHeaderSize  = 8
	IPv4HeaderSize = 20
	IPv6HeaderSize = 40
	UDP4MTU        = MTU - IPv4HeaderSize - UDPHeaderSize
	UDP6MTU        = MTU - IPv6HeaderSize - UDPHeaderSize

	queueSize = 1024

	queryInterval = 100 * time.Millisecond
)

type Server struct {
	ctx    context.Context
	cancel context.CancelFunc

	supportIPv6 atomic.Bool

	// inside
	udpConnIPv4        *net.UDPConn
	udpConnIPv6        *net.UDPConn
	insideSendQueue    chan Entry
	insideReceiveQueue chan Entry

	// blocked domains
	blocked *Blacklist

	// global cache
	cache *RecordCache

	// transaction ID pool
	idPool *TransactionIDPool

	// signal to tell the request to send a query to the remote server
	timer       *time.Timer
	querySignal chan bool
}

type Entry struct {
	msg  *dns.Msg
	addr net.Addr
}

// ******************** Initialization Interface **********************

func NewDNSServer(parent context.Context) *Server {
	ctx, cancel := context.WithCancel(parent)

	server := &Server{
		ctx:         ctx,
		cancel:      cancel,
		supportIPv6: atomic.Bool{},

		insideSendQueue:    make(chan Entry, queueSize),
		insideReceiveQueue: make(chan Entry, queueSize),

		blocked:     newBlacklist(),
		cache:       newRecordCache(ctx),
		idPool:      newTransactionIDPool(),
		querySignal: make(chan bool, 1),
	}

	// load root hints
	server.loadRootHints()

	// handle DNS requests and responses
	server.insideRequestHandler()
	server.insideResponseHandler()

	// check IPv6 support
	server.supportIPv6.Store(checkIPv6Support())

	// start the timer to allow sending queries to the remote server
	server.sendIntervalTimer()

	return server
}

func checkIPv6Support() bool {
	// Get all network interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal("Fail to get network interfaces: ", err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Get all addresses of the interface
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP

			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip != nil && ip.To4() == nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				return true
			}
		}
	}
	return false
}

// ******************** Server **********************

func (s *Server) RunIPv4(port uint16) {
	// Create a IPV4 UDP socket listening on specified port
	udpAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		log.Fatal("Fail to resolve UDP IPv4 address: ", err)
	}
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		log.Fatal("Fail to listen UDP: ", err)
	}
	s.udpConnIPv4 = conn

	s.readFromConn(conn, UDP4MTU)
}

func (s *Server) RunIPv6(port uint16) {
	// Create a IPV6 UDP socket listening on specified port
	udpAddr, err := net.ResolveUDPAddr("udp6", fmt.Sprintf("[::]:%d", port))
	if err != nil {
		log.Fatal("Fail to resolve UDP IPv6 address: ", err)
	}
	conn, err := net.ListenUDP("udp6", udpAddr)
	if err != nil {
		log.Fatal("Fail to listen UDP: ", err)
	}
	s.udpConnIPv6 = conn

	s.readFromConn(conn, UDP6MTU)
}

func (s *Server) readFromConn(conn *net.UDPConn, mtu int) {
	go func() {
		buffer := make([]byte, mtu)
		for {
			select {
			case <-s.ctx.Done():
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

				// Send the message to the queue
				reqEntry := Entry{
					msg:  &msg,
					addr: addr,
				}
				s.insideReceiveQueue <- reqEntry
			}
		}
	}()
}

func (s *Server) Terminate() {
	s.cancel()

	// Close the UDP connections
	if s.udpConnIPv4 != nil {
		if closeErr := s.udpConnIPv4.Close(); closeErr != nil {
			log.Println("Fail to close UDP IPv4 connection: ", closeErr)
		}
	}
	if s.udpConnIPv6 != nil {
		if closeErr := s.udpConnIPv6.Close(); closeErr != nil {
			log.Println("Fail to close UDP IPv6 connection: ", closeErr)
		}
	}
}

// ******************** Inside DNS Request Handler **********************

func (s *Server) insideRequestHandler() {
	// goroutine to handle the outgoing DNS requests
	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return

			case reqEntry := <-s.insideReceiveQueue:
				// Check if the message is a DNS query
				if len(reqEntry.msg.Question) == 0 {
					s.handleFormatError(reqEntry.addr, reqEntry.msg)
					continue
				}

				// Get question from the message
				question := reqEntry.msg.Question[0]
				log.Printf("Question: %s\n", question.Name)

				// Check if the domain is blocked
				if s.blocked.contains(question.Name) {
					s.handleBlocked(reqEntry.addr, reqEntry.msg)
					continue
				}

				// Check if the cache has the record of the domain
				if rrSet, ok := s.cache.get(question.Name, question.Qtype, question.Qclass); ok {
					resp := dns.Msg{}
					resp.SetReply(reqEntry.msg)
					for _, rr := range rrSet {
						resp.Answer = append(resp.Answer, rr)
					}
					entry := Entry{
						msg:  &resp,
						addr: reqEntry.addr,
					}
					s.insideSendQueue <- entry
					continue
				}

				// TODO: new feature: support custom record for local network

				// Resolve the request
				resolver := NewResolver(s, reqEntry)
				resolver.resolve()
			}
		}
	}()
}

func (s *Server) handleFormatError(addr net.Addr, req *dns.Msg) {
	// create a response message
	resp := dns.Msg{}
	resp.SetReply(req)
	resp.Rcode = dns.RcodeFormatError

	entry := Entry{
		msg:  &resp,
		addr: addr,
	}
	s.insideSendQueue <- entry
}

func (s *Server) handleBlocked(addr net.Addr, req *dns.Msg) {
	resp := dns.Msg{}
	resp.SetReply(req)
	resp.Rcode = dns.RcodeNameError

	entry := Entry{
		msg:  &resp,
		addr: addr,
	}
	s.insideSendQueue <- entry
}

// ******************** Inside DNS Response Handler **********************

func (s *Server) insideResponseHandler() {
	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return

			case entry := <-s.insideSendQueue:
				s.sendResponse(entry.addr, entry.msg)
			}
		}
	}()
}

func (s *Server) sendResponse(addr net.Addr, resp *dns.Msg) {
	// serialize the message
	data, packErr := resp.Pack()
	if packErr != nil {
		log.Printf("Failed to pack DNS response: %s\n", packErr)
		return
	}

	// select the correct UDP connection
	var conn *net.UDPConn
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		if udpAddr.IP.To4() != nil {
			conn = s.udpConnIPv4
		} else {
			conn = s.udpConnIPv6
		}
	} else {
		log.Printf("Failed to cast address to UDP address: %s\n", addr)
		return
	}

	// send the message
	n, writeErr := conn.WriteToUDP(data, addr.(*net.UDPAddr))
	if writeErr != nil {
		log.Printf("Failed to send DNS response: %s\n", writeErr)
		return
	}
	if n != len(data) {
		log.Printf("Sent size %d didn't match message size %d\n", n, len(data))
	}
}

// ******************** Outside DNS Request Timer **********************

func (s *Server) sendIntervalTimer() {
	go func() {
		s.timer = time.NewTimer(0 * time.Second)

		for {
			select {
			case <-s.ctx.Done():
				if s.timer != nil && !s.timer.Stop() {
					select {
					case <-s.timer.C:
					default:
					}
				}
				return

			case <-s.timer.C:
				// Send a query to the remote server must wait for the timer.
				// signal the request in a non-blocking way
				select {
				case s.querySignal <- true:
				default:
				}
			}
		}
	}()
}

func (s *Server) resetTimer() {
	s.timer.Reset(queryInterval)
}
