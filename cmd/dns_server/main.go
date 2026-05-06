package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
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
	if err != nil || dnsPort < 0 || dnsPort > 65535 {
		flag.Usage()
		log.Fatal("Port number must be a number, e.g. 53")
	}
	controllerPort, err := strconv.Atoi(*controllerPortFlag)
	if err != nil || controllerPort < 0 || controllerPort > 65535 {
		flag.Usage()
		log.Fatal("Port number must be a number, e.g. 7878")
	}

	// create root context
	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	handler := slog.NewTextHandler(os.Stdout, opts)
	logger := slog.New(handler)

	// create DNS server
	dnsServer := dns.NewDNSServer(rootCtx, logger)
	dnsServer.RunIPv4(uint16(dnsPort)) // run DNS server in IPv4
	dnsServer.RunIPv6(uint16(dnsPort)) // run DNS server in IPv6

	// TODO: handle message from controller interface
	logger.Info("DNS server is running",
		"dnsPort", dnsPort,
		"controllerPort", controllerPort,
	)
	select {
	case <-rootCtx.Done(): // wait for interrupt signal
	}
}
