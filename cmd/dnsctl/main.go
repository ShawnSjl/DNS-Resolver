package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/ShawnSjl/DNS-Resolver/internal/cli"
	"github.com/ShawnSjl/DNS-Resolver/internal/protocol"
)

func main() {
	// Setup flags
	addrFlag := flag.String("addr", "127.0.0.1", "address of the DNS resolver")
	portFlag := flag.Int("port", 7878, "port of the DNS resolver")
	flag.Parse()

	// validate port
	port := *portFlag
	if port < 0 || port > 65535 {
		flag.Usage()
		log.Fatal("Invalid port number")
	}

	// Resolve address
	addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", *addrFlag, port))
	if err != nil {
		log.Fatal("Fail to resolve address: ", err)
	}

	// Connect to the DNS resolver
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		log.Fatal("Fail to dial address: ", err)
	}
	defer func(conn *net.TCPConn) {
		_ = conn.Close()
	}(conn)

	// Start REPL
	cli.REPL()
	os.Exit(0)
}

type commandKind int

const (
	commandRemote commandKind = iota
	commandConnect
	commandDisconnect
	commandHelp
	commandExit
)

type controllerCommand struct {
	kind commandKind
	addr string
	line string
}

func parseControllerCommand(line string, defaultAddr string) (controllerCommand, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return controllerCommand{}, fmt.Errorf("empty command")
	}

	switch strings.ToLower(fields[0]) {
	case "exit", "quit":
		if len(fields) != 1 {
			return controllerCommand{}, fmt.Errorf("usage: %s", fields[0])
		}
		return controllerCommand{kind: commandExit}, nil
	case "c":
		if len(fields) > 2 {
			return controllerCommand{}, fmt.Errorf("usage: c [ADDR]")
		}
		addr := defaultAddr
		if len(fields) == 2 {
			addr = fields[1]
		}
		return controllerCommand{kind: commandConnect, addr: addr}, nil
	case "d":
		if len(fields) != 1 {
			return controllerCommand{}, fmt.Errorf("usage: d")
		}
		return controllerCommand{kind: commandDisconnect}, nil
	case "help":
		if len(fields) != 1 {
			return controllerCommand{}, fmt.Errorf("usage: help")
		}
		return controllerCommand{kind: commandHelp}, nil
	default:
		if _, err := protocol.ParseCommand(line); err != nil {
			return controllerCommand{}, err
		}
		return controllerCommand{kind: commandRemote, line: line}, nil
	}
}

type controllerClient struct {
	addr      string
	conn      net.Conn
	reader    *bufio.Reader
	connected bool
}

func (c *controllerClient) Connect(addr string) error {
	c.Close()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	c.addr = addr
	c.conn = conn
	c.reader = bufio.NewReader(conn)
	c.connected = true
	return nil
}

func (c *controllerClient) Close() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.conn = nil
	c.reader = nil
	c.connected = false
}

func (c *controllerClient) Connected() bool {
	return c.connected
}

func (c *controllerClient) Send(line string) (string, error) {
	if !c.connected || c.conn == nil || c.reader == nil {
		return "", fmt.Errorf("not connected")
	}

	if _, err := fmt.Fprintln(c.conn, line); err != nil {
		c.Close()
		return "", err
	}

	var lines []string
	for {
		// END means the response is complete.
		resp, err := c.reader.ReadString('\n')
		if err != nil {
			c.Close()
			return "", err
		}
		resp = strings.TrimRight(resp, "\r\n")
		if resp == "END" {
			return strings.Join(lines, "\n"), nil
		}
		lines = append(lines, resp)
	}
}

func printResponse(resp string, err error) {
	if err != nil {
		fmt.Println("ERR", err)
		return
	}
	if strings.TrimSpace(resp) != "" {
		fmt.Println(resp)
	}
}

func localHelp() string {
	return strings.Join([]string{
		"c 127.0.0.1:7878",
		"d",
		protocol.Help(),
		"help",
		"exit",
		"quit",
	}, "\n")
}
