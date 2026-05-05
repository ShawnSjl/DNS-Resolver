package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/brown-cs1680-s26/final-jiale-xinran/internal/protocol"
	"github.com/chzyer/readline"
)

func main() {
	defaultAddr := flag.String("addr", "127.0.0.1:7878", "control server address")
	flag.Parse()

	// readline just makes the local prompt nicer.
	rl, err := readline.New("dnsctl> ")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer rl.Close()

	client := &controllerClient{}
	_ = client.Connect(*defaultAddr)

	for {
		// Ignore blank lines like a normal shell.
		line, err := rl.Readline()
		if err == readline.ErrInterrupt {
			continue
		}
		if err == io.EOF {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		switch strings.ToLower(fields[0]) {
		case "exit", "quit":
			return
		case "c":
			// Use the default address if none is given.
			addr := *defaultAddr
			if len(fields) > 1 {
				addr = fields[1]
			}
			if err := client.Connect(addr); err != nil {
				fmt.Println("ERR", err)
			} else {
				fmt.Println("OK connected", addr)
			}
		case "d":
			client.Close()
			fmt.Println("OK disconnected")
		case "help":
			if client.Connected() {
				printResponse(client.Send(line))
			} else {
				fmt.Println(localHelp())
			}
		default:
			if !client.Connected() {
				if err := client.Connect(*defaultAddr); err != nil {
					fmt.Println("ERR not connected; use c 127.0.0.1:7878")
					continue
				}
			}
			printResponse(client.Send(line))
		}
	}
}

type controllerClient struct {
	addr      string
	connected bool
}

func (c *controllerClient) Connect(addr string) error {
	// Check the address before saving it.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	_ = conn.Close()
	c.addr = addr
	c.connected = true
	return nil
}

func (c *controllerClient) Close() {
	// No open socket here, just mark it disconnected.
	c.connected = false
}

func (c *controllerClient) Connected() bool {
	return c.connected
}

func (c *controllerClient) Send(line string) (string, error) {
	if !c.connected || c.addr == "" {
		return "", fmt.Errorf("not connected")
	}
	// Match the server's one-command-per-connection style.
	conn, err := net.Dial("tcp", c.addr)
	if err != nil {
		c.connected = false
		return "", err
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	if _, err := fmt.Fprintln(conn, line); err != nil {
		return "", err
	}

	var lines []string
	for {
		// END means the response is complete.
		resp, err := reader.ReadString('\n')
		if err != nil {
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
		"exit",
		"quit",
	}, "\n")
}
