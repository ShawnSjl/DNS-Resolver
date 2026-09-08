package server

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"
	"strings"

	"github.com/ShawnSjl/DNS-Resolver/internal/protocol"
	"github.com/ShawnSjl/DNS-Resolver/internal/server/blocklist"
	"github.com/ShawnSjl/DNS-Resolver/internal/server/config"
	"github.com/ShawnSjl/DNS-Resolver/internal/server/request_throttle"
	"github.com/ShawnSjl/DNS-Resolver/internal/server/resolver"
	"github.com/ShawnSjl/DNS-Resolver/internal/server/root_hints"
	"github.com/ShawnSjl/DNS-Resolver/internal/server/rr_cache"
	"github.com/miekg/dns"
)

type Server struct {
	ctx    context.Context
	cancel context.CancelFunc
	logger *slog.Logger

	// inside
	udpConnIPv4 *net.UDPConn
	udpConnIPv6 *net.UDPConn

	// blocked domains
	blocked *blocklist.Blocklist

	customCache *rr_cache.Cache
}

// ******************** Initialization Interface **********************

func NewDNSServer(parent context.Context, logger *slog.Logger) *Server {
	ctx, cancel := context.WithCancel(parent)

	server := &Server{
		ctx:    ctx,
		cancel: cancel,
		logger: logger.With("module", "dns-server"),

		blocked:     blocklist.New(nil),
		customCache: rr_cache.NewCache(ctx, logger.With("module", "custom-cache")),
	}

	// start a global RR cache
	rr_cache.StartGlobal(ctx, logger.With("module", "global-cache"))

	// load root hints
	root_hints.Load(ctx, logger, rr_cache.Global())

	// start a global request throttle
	request_throttle.StartGlobal(ctx, 0)

	return server
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

	s.readFromConn(conn, config.UDP4MTU)
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

	s.readFromConn(conn, config.UDP6MTU)
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

				// Handle the DNS request in a new goroutine
				go s.insideRequestHandler(addr, &msg)
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

func (s *Server) insideRequestHandler(addr net.Addr, req *dns.Msg) {
	// Check if the message is a DNS query
	if len(req.Question) == 0 {
		s.handleFormatError(addr, req)
		return
	}

	// Get question from the message
	question := req.Question[0]
	s.logger.Info("Received DNS request",
		"question", question.String(),
		"addr", addr.String(),
	)

	// Check if the domain is blocked
	if s.blocked.Contains(question.Name) {
		s.handleBlocked(addr, req)
		return
	}

	// TODO: new feature: support custom record for local network

	// Resolve the request
	s.handleNormalCase(addr, req, question)
}

func (s *Server) handleFormatError(addr net.Addr, req *dns.Msg) {
	// create a response message with format error
	resp := dns.Msg{}
	resp.SetReply(req)
	resp.Rcode = dns.RcodeFormatError

	s.sendResponse(addr, &resp)
}

func (s *Server) handleBlocked(addr net.Addr, req *dns.Msg) {
	// create a response message with non-existent domain
	resp := dns.Msg{}
	resp.SetReply(req)
	resp.Rcode = dns.RcodeNameError

	s.sendResponse(addr, &resp)
}

func (s *Server) handleNormalCase(addr net.Addr, req *dns.Msg, question dns.Question) {
	// Resolve the request
	newResolver := resolver.NewResolver(s.ctx, s.logger, question.Name, question.Qtype)
	result, err := newResolver.Resolve(1, make(map[string]bool))
	if err != nil {
		s.logger.Error("Fail to resolve DNS request",
			"err", err,
			"question", question.String(),
			"addr", addr.String(),
		)
		return
	}

	// Form a response message with the resolved records
	resp := dns.Msg{}
	resp.SetReply(req)
	for _, rr := range result {
		resp.Answer = append(resp.Answer, rr)
	}

	// If answer is empty, return NXDOMAIN
	if len(resp.Answer) == 0 {
		resp.Rcode = dns.RcodeNameError
	}
	s.sendResponse(addr, &resp)
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
	return rr_cache.Global().ToString()
}

// ListCustomRR exposes custom records to the controller. Storage is added in a
// later step, so this currently returns the existing placeholder value.
func (s *Server) ListCustomRR() string {
	return ""
}

// AddCustomRR accepts the typed record decoded by the controller interface.
// Persisting the record is intentionally deferred.
func (s *Server) AddCustomRR(record protocol.CustomRR) bool {
	return true
}

// RemoveCustomRR accepts the typed record decoded by the controller interface.
// Removing the record is intentionally deferred.
func (s *Server) RemoveCustomRR(record protocol.CustomRR) bool {
	return true
}
