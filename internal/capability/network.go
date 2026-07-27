package capability

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const defaultRefreshInterval = 30 * time.Second

var (
	defaultCapabilities NetworkCapabilities
	startOnce           sync.Once
)

type NetworkCapabilities struct {
	ipv6StackAvailable   atomic.Bool
	ipv6AddressAvailable atomic.Bool
}

func Start(
	ctx context.Context,
	logger *slog.Logger,
	refreshInterval time.Duration,
) {
	startOnce.Do(func() {
		if logger == nil {
			logger = slog.Default()
		}

		if refreshInterval <= 0 {
			refreshInterval = defaultRefreshInterval
		}

		refresh := func() {
			stackAvailable := detectIPv6Stack()

			addressAvailable, err := detectIPv6Address()
			if err != nil {
				logger.Warn(
					"failed to detect IPv6 address",
					"error", err,
				)
				return
			}

			oldStack := defaultCapabilities.ipv6StackAvailable.Swap(
				stackAvailable,
			)
			oldAddress := defaultCapabilities.ipv6AddressAvailable.Swap(
				addressAvailable,
			)

			if oldStack != stackAvailable {
				logger.Info(
					"IPv6 stack availability changed",
					"available", stackAvailable,
				)
			}

			if oldAddress != addressAvailable {
				logger.Info(
					"IPv6 address availability changed",
					"available", addressAvailable,
				)
			}
		}

		refresh()

		go func() {
			ticker := time.NewTicker(refreshInterval)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return

				case <-ticker.C:
					refresh()
				}
			}
		}()
	})
}

func SupportsIPv6() bool {
	return defaultCapabilities.ipv6AddressAvailable.Load()
}

func HasIPv6Address() bool {
	return SupportsIPv6()
}

func HasIPv6Stack() bool {
	return defaultCapabilities.ipv6StackAvailable.Load()
}

func detectIPv6Stack() bool {
	conn, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		return false
	}

	_ = conn.Close()
	return true
}

func detectIPv6Address() (bool, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false, err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, address := range addresses {
			ip := ipFromAddr(address)
			if ip == nil {
				continue
			}

			if ip.To4() != nil {
				continue
			}

			if ip.To16() == nil {
				continue
			}

			if ip.IsLoopback() {
				continue
			}

			return true, nil
		}
	}

	return false, nil
}

func ipFromAddr(address net.Addr) net.IP {
	switch value := address.(type) {
	case *net.IPNet:
		return value.IP
	case *net.IPAddr:
		return value.IP
	default:
		return nil
	}
}
