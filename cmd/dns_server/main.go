package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/brown-cs1680-s26/final-jiale-xinran/internal/server/dns"
)

func main() {
	// setup flags
	dnsPortFlag := flag.String("port", "53", "port to listen DNS messages")
	controllerPortFlag := flag.String("controller-port", "7878", "port to listen controller messages")
	flag.Parse()

	// validate port
	dnsPort, err := strconv.Atoi(*dnsPortFlag)
	if err != nil {
		flag.Usage()
		fmt.Printf("Error: port number is not valid\n")
		os.Exit(1)
	}
	controllerPort, err := strconv.Atoi(*controllerPortFlag)
	if err != nil {
		flag.Usage()
		fmt.Printf("Error: controller port number is not valid\n")
		os.Exit(1)
	}

	// create root context
	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// create DNS server
	dnsServer := dns.NewDNSServer(rootCtx)
	dnsServer.RunIPv4(uint16(dnsPort)) // run DNS server in IPv4
	dnsServer.RunIPv6(uint16(dnsPort)) // run DNS server in IPv6

	// TODO: handle message from controller interface
	log.Printf("Controller port: %d", controllerPort)
	select {
	case <-rootCtx.Done(): // wait for interrupt signal
	}
}
