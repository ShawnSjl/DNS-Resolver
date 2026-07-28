package root_hints

import (
	"context"
	"log/slog"
	"time"

	"github.com/ShawnSjl/DNS-Resolver/internal/server/rr_cache"
	"github.com/miekg/dns"
)

// Load root hints from the internet or use hard coded root hints
func Load(parent context.Context, logger *slog.Logger, cache *rr_cache.Cache) {
	if parent == nil {
		parent = context.Background()
	}
	if logger == nil {
		logger = slog.Default()
	}
	defer logger.Info("Root hints loaded")

	var (
		ns, a, aaaa []dns.RR
		err         error
	)

	// Try to fetch root hints from the internet
	ns, a, aaaa, err = fetchRootHints(parent)

	// If failed, use hard coded root hints
	if err != nil {
		logger.Warn("Failed to load root hints, change to hard coded root hints", "error", err)

		// Get hard coded root hints
		var hcTime time.Time
		hcNs, hcA, hcAaaa, hcTime := getHardCodedRootHints()
		logger.Info("Hard Coded Root Hints Time: ", hcTime.String())

		ns, a, aaaa = hcNs, hcA, hcAaaa
	}

	// Add root hints to cache
	addRootHintsToCache(cache, ns)
	addRootHintsToCache(cache, a)
	addRootHintsToCache(cache, aaaa)
}

func addRootHintsToCache(cache *rr_cache.Cache, rrs []dns.RR) {
	for _, rr := range rrs {
		cache.AddRR(rr, false)
	}
}
