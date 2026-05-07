package _interface

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"
	"strings"

	"github.com/brown-cs1680-s26/final-jiale-xinran/internal/protocol"
	"github.com/brown-cs1680-s26/final-jiale-xinran/internal/server/dns"
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
		if exit := handleConn(ctx, logger, server, conn); exit {
			return
		}
	}
}

func handleConn(ctx context.Context, _ *slog.Logger, server *dns.Server, conn net.Conn) bool {
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	for {
		select {
		case <-ctx.Done():
			return true
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			return false
		}
		line = strings.TrimSpace(line)

		cmd, err := protocol.ParseCommand(line)
		response := ""
		if err != nil {
			response = "ERR " + err.Error() + "\n"
		} else {
			response = execute(server, cmd)
		}

		// END tells clients when to stop reading.
		if _, err := writer.WriteString(response); err != nil {
			return false
		}
		if !strings.HasSuffix(response, "\n") {
			if _, err := writer.WriteString("\n"); err != nil {
				return false
			}
		}
		if _, err := writer.WriteString("END\n"); err != nil {
			return false
		}
		if err := writer.Flush(); err != nil {
			return false
		}
	}
}

func execute(server *dns.Server, cmd protocol.Command) string {
	// Validate first, then call into the server.
	switch cmd.Type {
	case protocol.CommandBlock:
		server.Block(cmd.Domain)
		return "OK blocked " + cmd.Domain + "\n"
	case protocol.CommandUnblock:
		server.Unblock(cmd.Domain)
		return "OK unblocked " + cmd.Domain + "\n"
	case protocol.CommandListBlocks:
		return "OK " + server.ListBlocked() + "\n"
	case protocol.CommandListRecords:
		return "OK " + server.ListCache() + "\n"
	default:
		return fmt.Sprintf("ERR unsupported command %q\n", cmd.Name)
	}
}

func listOrEmpty(lines []string, empty string) string {
	if len(lines) == 0 {
		return empty + "\n"
	}
	return strings.Join(lines, "\n") + "\n"
}
