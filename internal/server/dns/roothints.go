package dns

import (
	"context"
	"time"

	"github.com/ShawnSjl/DNS-Resolver/internal/server/root_hints"
	"github.com/miekg/dns"
)

func (s *Server) loadRootHints(ctx context.Context) {
	defer s.logger.Info("Root hints loaded")

	var (
		ns, a, aaaa []dns.RR
		err         error
	)

	// Try to fetch root hints from the internet
	ns, a, aaaa, err = root_hints.FetchRootHints(ctx)

	// If failed, use hard coded root hints
	if err != nil {
		s.logger.Warn("Failed to load root hints, change to hard coded root hints", "error", err)

		// Get hard coded root hints
		var hcTime time.Time
		hcNs, hcA, hcAaaa, hcTime := root_hints.GetHardCodedRootHints()
		s.logger.Info("Hard Coded Root Hints Time: ", hcTime.String())

		ns, a, aaaa = hcNs, hcA, hcAaaa
	}

	// Add root hints to cache
	s.addRootHintsToCache(ns)
	s.addRootHintsToCache(a)
	s.addRootHintsToCache(aaaa)
}

func (s *Server) addRootHintsToCache(rrs []dns.RR) {
	for _, rr := range rrs {
		s.cache.AddRR(rr, false)
	}
}
