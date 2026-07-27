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
	"time"

	"github.com/ShawnSjl/DNS-Resolver/internal/capability"
	"github.com/ShawnSjl/DNS-Resolver/internal/server"
	_interface "github.com/ShawnSjl/DNS-Resolver/internal/server/interface"
)

func main() {
	// setup flags
	logFlag := flag.String("log", "info", "log level")
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

	// create logger
	var level slog.Level
	switch *logFlag {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{
		Level: level,
	}
	handler := slog.NewTextHandler(os.Stdout, opts)
	logger := slog.New(handler)

	// start network capability service
	capability.Start(rootCtx, logger, 30*time.Second)

	// create DNS server
	dnsServer := server.NewDNSServer(rootCtx, logger)
	dnsServer.RunIPv4(uint16(dnsPort)) // run DNS server in IPv4
	if capability.HasIPv6Stack() {
		dnsServer.RunIPv6(uint16(dnsPort)) // run DNS server in IPv6
	}

	// handle message from controller interface
	logger.Info("DNS server is running",
		"dnsPort", dnsPort,
		"controllerPort", controllerPort,
	)
	go _interface.Serve(rootCtx, logger, dnsServer, controllerPort)

	select {
	case <-rootCtx.Done(): // wait for interrupt signal
	}
}
