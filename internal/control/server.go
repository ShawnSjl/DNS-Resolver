package control

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/brown-cs1680-s26/final-jiale-xinran/internal/protocol"
)

// Runtime is the controller's small hook into the DNS server.
type Runtime interface {
	Block(domain string)
	Unblock(domain string)
	ListBlocks() []string
	ListRecords() []string
	Query(ctx context.Context, domain string, qtype uint16) (string, error)
	ClearCache()
}

func Serve(ctx context.Context, ln net.Listener, runtime Runtime, clientTimeout time.Duration) error {
	errCh := make(chan error, 1)
	go func() {
		// Closing the listener unblocks Accept on shutdown.
		<-ctx.Done()
		_ = ln.Close()
	}()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					errCh <- nil
				default:
					errCh <- err
				}
				return
			}
			handleConn(ctx, conn, runtime, clientTimeout)
		}
	}()

	return <-errCh
}

func handleConn(ctx context.Context, conn net.Conn, runtime Runtime, clientTimeout time.Duration) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	for {
		if clientTimeout > 0 {
			_ = conn.SetDeadline(time.Now().Add(clientTimeout))
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)

		cmd, err := protocol.ParseCommand(line)
		response := ""
		if err != nil {
			response = "ERR " + err.Error() + "\n"
		} else {
			response = execute(ctx, runtime, cmd)
		}

		// END tells clients when to stop reading.
		if _, err := writer.WriteString(response); err != nil {
			return
		}
		if !strings.HasSuffix(response, "\n") {
			if _, err := writer.WriteString("\n"); err != nil {
				return
			}
		}
		if _, err := writer.WriteString("END\n"); err != nil {
			return
		}
		if err := writer.Flush(); err != nil {
			return
		}
	}
}

func execute(ctx context.Context, runtime Runtime, cmd protocol.Command) string {
	// Validate first, then call into the server.
	switch cmd.Type {
	case protocol.CommandBlock:
		runtime.Block(cmd.Domain)
		return "OK blocked " + cmd.Domain + "\n"
	case protocol.CommandUnblock:
		runtime.Unblock(cmd.Domain)
		return "OK unblocked " + cmd.Domain + "\n"
	case protocol.CommandListBlocks:
		return listOrEmpty(runtime.ListBlocks(), "no blocked domains")
	case protocol.CommandListRecords:
		return listOrEmpty(runtime.ListRecords(), "cache is empty")
	case protocol.CommandQuery:
		// q uses the server's normal resolver/cache path.
		out, err := runtime.Query(ctx, cmd.Domain, cmd.QType)
		if err != nil {
			return "ERR " + err.Error() + "\n"
		}
		return out
	case protocol.CommandClearCache:
		runtime.ClearCache()
		return "OK cache cleared\n"
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
