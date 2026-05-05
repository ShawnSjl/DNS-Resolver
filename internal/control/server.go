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

type Runtime interface {
	Block(domain string)
	Unblock(domain string)
	ListBlocks() []string
	ListRecords() []string
	Query(ctx context.Context, domain string, qtype uint16) (string, error)
	Mode() string
	SetMode(mode string) error
	Stats() string
	ClearCache()
}

func Serve(ctx context.Context, ln net.Listener, runtime Runtime, clientTimeout time.Duration) error {
	errCh := make(chan error, 1)
	go func() {
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
			go handleConn(ctx, conn, runtime, clientTimeout)
		}
	}()

	return <-errCh
}

func handleConn(ctx context.Context, conn net.Conn, runtime Runtime, clientTimeout time.Duration) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	if clientTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(clientTimeout))
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimSpace(line)
	response := execute(ctx, runtime, line)
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

func execute(ctx context.Context, runtime Runtime, line string) string {
	cmd, err := protocol.ParseCommand(line)
	if err != nil {
		return "ERR " + err.Error() + "\n"
	}

	switch cmd.Name {
	case "block":
		runtime.Block(cmd.Domain)
		return "OK blocked " + cmd.Domain + "\n"
	case "unblock":
		runtime.Unblock(cmd.Domain)
		return "OK unblocked " + cmd.Domain + "\n"
	case "lb":
		return listOrEmpty(runtime.ListBlocks(), "no blocked domains")
	case "lr":
		return listOrEmpty(runtime.ListRecords(), "cache is empty")
	case "q":
		out, err := runtime.Query(ctx, cmd.Domain, cmd.QType)
		if err != nil {
			return "ERR " + err.Error() + "\n"
		}
		return out
	case "mode":
		if cmd.Mode == "" {
			return runtime.Mode() + "\n"
		}
		if err := runtime.SetMode(cmd.Mode); err != nil {
			return "ERR " + err.Error() + "\n"
		}
		return "OK mode " + cmd.Mode + "\n"
	case "stats":
		return runtime.Stats() + "\n"
	case "clearcache":
		runtime.ClearCache()
		return "OK cache cleared\n"
	case "help":
		return protocol.Help() + "\n"
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
