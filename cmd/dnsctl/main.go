package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/ShawnSjl/DNS-Resolver/internal/cli"
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
