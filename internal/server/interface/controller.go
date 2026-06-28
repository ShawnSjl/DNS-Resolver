package _interface

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"
	"strings"

	"github.com/ShawnSjl/DNS-Resolver/internal/protocol"
	"github.com/ShawnSjl/DNS-Resolver/internal/server/dns"
)

func Serve(ctx context.Context, logger *slog.Logger, server *dns.Server, port int) {
	defer func() {
		slog.Info("DNS controller interface exited")
	}()

	tcpAddr, addrErr := net.ResolveTCPAddr("tcp4", fmt.Sprintf(":%d", port))
	if addrErr != nil {
		log.Fatal("Fail to resolve TCP address: ", addrErr)
	}
	listener, listenErr := net.ListenTCP("tcp4", tcpAddr)
	if listenErr != nil {
		log.Fatal("Fail to listen TCP address: ", listenErr)
	}
	defer func(listener *net.TCPListener) {
		if err := listener.Close(); err != nil {
			log.Fatal("Fail to close TCP listener: ", err)
		}
	}(listener)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, acceptErr := listener.AcceptTCP()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Error("Fail to accept TCP connection", "err", acceptErr)
			continue
		}

		// handle the connection and return true if the context is canceled
		go func() {
			handleConn(ctx, logger, server, conn)
		}()
	}
}

func handleConn(ctx context.Context, logger *slog.Logger, server *dns.Server, conn *net.TCPConn) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Receive a request from controller
		req, err := protocol.Receive(conn)

		// Handle error of receiving
		if err != nil {
			// Send error response
			payload := []byte(strings.TrimSpace(err.Error()))
			resp := protocol.Message{
				MsgType: protocol.MsgError,
				Data:    payload,
			}
			if sendErr := protocol.Send(conn, &resp); sendErr != nil {
				logger.Error("Fail to send error response", "err", sendErr)
			}
			return
		}

		// Execute the request
		respType, respData := execute(server, req)
		respPayload := []byte(respData)
		resp := protocol.Message{
			MsgType: respType,
			Data:    respPayload,
		}
		if sendErr := protocol.Send(conn, &resp); sendErr != nil {
			logger.Error("Fail to send response", "err", sendErr)
			return
		}
	}
}

func execute(server *dns.Server, req *protocol.Message) (protocol.MessageType, string) {
	// Validate first, then call into the server.
	switch req.MsgType {
	case protocol.MsgBlockAdd:
		server.Block(string(req.Data))
		return protocol.MsgAck, "OK"
	case protocol.MsgBlockRemove:
		server.Unblock(string(req.Data))
		return protocol.MsgAck, "OK"
	case protocol.MsgBlockList:
		return protocol.MsgAck, server.ListBlocked()
	case protocol.MsgCacheList:
		return protocol.MsgAck, server.ListCache()
	default:
		return protocol.MsgError, "unexpected request type " + string(req.MsgType)
	}
}
