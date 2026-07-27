package dns

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"

	"github.com/ShawnSjl/DNS-Resolver/internal/server/blocklist"
	"github.com/ShawnSjl/DNS-Resolver/internal/server/request_throttle"
	"github.com/ShawnSjl/DNS-Resolver/internal/server/rr_cache"
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
)

type Server struct {
	ctx        context.Context
	cancel     context.CancelFunc
	logger     *slog.Logger
	rootLogger *slog.Logger

	supportIPv6 atomic.Bool

	// inside
	udpConnIPv4        *net.UDPConn
	udpConnIPv6        *net.UDPConn
	insideSendQueue    chan Entry
	insideReceiveQueue chan Entry

	// blocked domains
	blocked *blocklist.Blocklist

	// global cache
	cache *rr_cache.Cache

	// signal to tell the request to send a query to the remote server
	throttle *request_throttle.RequestThrottle
}

type Entry struct {
	msg  *dns.Msg
	addr net.Addr
}

// ******************** Initialization Interface **********************

func NewDNSServer(parent context.Context, logger *slog.Logger) *Server {
	ctx, cancel := context.WithCancel(parent)

	server := &Server{
		ctx:        ctx,
		cancel:     cancel,
		logger:     logger.With("module", "dns-server"),
		rootLogger: logger,

		supportIPv6: atomic.Bool{},

		insideSendQueue:    make(chan Entry, queueSize),
		insideReceiveQueue: make(chan Entry, queueSize),

		blocked: blocklist.New(nil),
		cache:   rr_cache.NewCache(ctx, logger),

		throttle: request_throttle.NewRequestThrottle(ctx, 0),
	}

	// load root hints
	server.loadRootHints(ctx)

	// handle DNS requests and responses
	server.insideRequestHandler()
	server.insideResponseHandler()

	// check IPv6 support
	server.supportIPv6.Store(checkIPv6Support())

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
					s.logger.Error("Fail to read UDP",
						"err", readErr,
					)
					continue
				}

				s.logger.Debug("Received UDP",
					"addr", addr.String(),
				)

				// Unpack the UDP packet into a DNS message
				var msg dns.Msg
				if unpackErr := msg.Unpack(buffer[:n]); unpackErr != nil {
					s.logger.Error("Fail to unpack UDP",
						"err", unpackErr,
					)
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
			s.logger.Error("Fail to close UDP IPv4 connection",
				"err", closeErr,
			)
		}
	}
	if s.udpConnIPv6 != nil {
		if closeErr := s.udpConnIPv6.Close(); closeErr != nil {
			s.logger.Error("Fail to close UDP IPv6 connection",
				"err", closeErr,
			)
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

				s.logger.Info("Received DNS request",
					"question", question.String(),
					"addr", reqEntry.addr.String(),
				)

				// Check if the domain is blocked
				if s.blocked.Contains(question.Name) {
					s.handleBlocked(reqEntry.addr, reqEntry.msg)
					continue
				}

				// TODO: new feature: support custom record for local network

				// Resolve the request
				go func() {
					resolver := NewResolver(s, question.Name, question.Qtype)
					result, err := resolver.resolve(1, make(map[string]bool))
					if err != nil {
						s.logger.Error("Fail to resolve DNS request",
							"err", err,
							"question", question.String(),
							"addr", reqEntry.addr.String(),
						)
						return
					}

					// Form a response message
					resp := dns.Msg{}
					resp.SetReply(reqEntry.msg)
					for _, rr := range result {
						resp.Answer = append(resp.Answer, rr)
					}

					// If answer is empty, return NXDOMAIN
					if len(resp.Answer) == 0 {
						resp.Rcode = dns.RcodeNameError
					}
					entry := Entry{
						msg:  &resp,
						addr: reqEntry.addr,
					}
					s.insideSendQueue <- entry
				}()
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
		s.logger.Error("Fail to pack DNS response",
			"err", packErr,
		)
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
		s.logger.Error("Fail to cast address to UDP address",
			"err", fmt.Errorf("invalid address type: %T", addr),
		)
		return
	}

	// send the message
	n, writeErr := conn.WriteToUDP(data, addr.(*net.UDPAddr))
	if writeErr != nil {
		s.logger.Error("Fail to send DNS response",
			"err", writeErr,
			"addr", addr.String(),
		)
		return
	}
	if n != len(data) {
		s.logger.Error("Sent DNS response size doesn't match message size",
			"expected", len(data),
			"actual", n,
			"addr", addr.String(),
		)
	}
}

// ******************** Public Interface **********************

func (s *Server) Block(domain string) bool {
	s.blocked.Add(domain)
	return true
}

func (s *Server) Unblock(domain string) bool {
	s.blocked.Remove(domain)
	return true
}

func (s *Server) ListBlocked() string {
	return strings.Join(s.blocked.List(), "\n")
}

func (s *Server) ListCache() string {
	return s.cache.ToString()
}
