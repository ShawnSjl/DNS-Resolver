package resolver

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type zone struct {
	logger *slog.Logger

	name  string     // i.e. ".", "com.", "example.com."
	mutex sync.Mutex // lock of nodes

	// local cache with TTL countdown
	ns       []dns.RR
	glueA    []dns.RR
	glueAAAA []dns.RR

	searchedNS []string
}

func (z *zone) addNS(rr dns.RR) {
	z.mutex.Lock()
	defer z.mutex.Unlock()

	for i, ns := range z.ns {
		if dns.IsDuplicate(rr, ns) {
			z.ns[i] = rr
			return
		}
	}

	z.ns = append(z.ns, rr)
}

func (z *zone) addGlue(rr dns.RR) {
	z.mutex.Lock()
	defer z.mutex.Unlock()

	switch rr.Header().Rrtype {
	case dns.TypeA:
		z.glueA = append(z.glueA, rr)
	case dns.TypeAAAA:
		z.glueAAAA = append(z.glueAAAA, rr)
	default:
		z.logger.Warn("Unsupported record type during glue record addition",
			"zone", z.name,
			"type", rr.Header().Rrtype,
		)
	}
}

// Get a random unsearched NS from the zone
func (z *zone) getRandomNS() (*dns.NS, error) {
	z.mutex.Lock()
	defer z.mutex.Unlock()

	// Shuffle the NS records
	shuffled := make([]dns.RR, len(z.ns))
	copy(shuffled, z.ns)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

	// Get a non-searched NS
	for _, rr := range shuffled {
		switch ns := rr.(type) {
		case *dns.NS:
			if !slices.Contains(z.searchedNS, ns.Ns) {
				nsCopy := dns.Copy(ns) // use copy to avoid modifying the original RR
				return nsCopy.(*dns.NS), nil
			}
		default:
			return nil, fmt.Errorf("Non-NS record during random NS: %d", rr.Header().Rrtype)
		}
	}
	return nil, nil
}

func (z *zone) getGlue(domain string, supportIPv6 bool) ([]dns.RR, error) {
	z.mutex.Lock()
	defer z.mutex.Unlock()

	result := make([]dns.RR, 0)

	for _, glue := range z.glueA {
		if dns.Fqdn(glue.Header().Name) == dns.Fqdn(domain) {
			glueCopy := dns.Copy(glue) // use copy to avoid modifying the original RR
			result = append(result, glueCopy)
		}
	}

	if supportIPv6 {
		for _, glue := range z.glueAAAA {
			if dns.Fqdn(glue.Header().Name) == dns.Fqdn(domain) {
				glueCopy := dns.Copy(glue) // use copy to avoid modifying the original RR
				result = append(result, glueCopy)
			}
		}
	}

	return result, nil
}

func (z *zone) ttlCountdown(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Second)

		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return

			case <-ticker.C:
				z.logger.Debug("TTL timer fired")
				z.mutex.Lock()

				z.ns = handleTTLCountdown(z.ns)
				z.glueA = handleTTLCountdown(z.glueA)
				z.glueAAAA = handleTTLCountdown(z.glueAAAA)

				z.mutex.Unlock()
			}
		}
	}()
}

func handleTTLCountdown(rrSet []dns.RR) []dns.RR {
	n := 0
	for _, rr := range rrSet {
		rr.Header().Ttl--
		if rr.Header().Ttl > 0 {
			rrSet[n] = rr
			n++
		}
	}
	return rrSet[:n]
}

func (z *zone) markSearchedNS(ns string) {
	z.mutex.Lock()
	defer z.mutex.Unlock()
	z.searchedNS = append(z.searchedNS, ns)
}

func (z *zone) dump() {
	fmt.Println("Zone: ", z.name)

	fmt.Println("  NS:")
	for _, ns := range z.ns {
		fmt.Println("    ", ns.String())
	}

	fmt.Println("  Glue A:")
	for _, glue := range z.glueA {
		fmt.Println("    ", glue.String())
	}

	fmt.Println("  Glue AAAA:")
	for _, glue := range z.glueAAAA {
		fmt.Println("    ", glue.String())
	}
}
