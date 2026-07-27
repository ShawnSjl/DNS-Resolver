package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ShawnSjl/DNS-Resolver/internal/server/rr_cache"
	"github.com/miekg/dns"
)

const (
	maxDepth        = 5
	timeoutInterval = 1 * time.Second
)

type Resolver struct {
	ctx    context.Context
	cancel context.CancelFunc
	logger *slog.Logger

	server      *Server
	globalCache *rr_cache.Cache // cache for DNS records

	domain  string
	qType   uint16
	answers []dns.RR

	queriesCount atomic.Int32 // number of queries in progress
	readySignal  chan bool    // signal to tell the resolver that all queries are finished

	currentZoneIdx int        // index of zone in the stack
	mutex          sync.Mutex // lock of stack
	stack          []*Zone
}

type Zone struct {
	logger *slog.Logger

	name  string     // i.e. ".", "com.", "example.com."
	mutex sync.Mutex // lock of nodes

	// local cache with TTL countdown
	ns       []dns.RR
	glueA    []dns.RR
	glueAAAA []dns.RR

	searchedNS []string
}

// ******************** Initialization Interface **********************

func NewResolver(server *Server, domain string, qType uint16) *Resolver {
	ctx, cancel := context.WithCancel(server.ctx)

	// Add the root zone to the stack
	resolver := &Resolver{
		ctx:    ctx,
		cancel: cancel,
		logger: server.rootLogger.WithGroup("resolver").With("domain", domain, "qType", qType),

		server:      server,
		globalCache: server.cache,

		domain:  domain,
		qType:   qType,
		answers: []dns.RR{},

		queriesCount: atomic.Int32{},
		readySignal:  make(chan bool, 1),

		mutex:          sync.Mutex{},
		currentZoneIdx: 0,
		stack:          []*Zone{},
	}

	// Create the root zone, no need to countdown root zone's TTL, it should never expire'
	rootZone := resolver.createRootZone(resolver.logger)
	resolver.stack = append(resolver.stack, rootZone)

	// start the resolver
	resolver.signalReady()
	return resolver
}

func (r *Resolver) createRootZone(logger *slog.Logger) *Zone {
	logger = logger.With("zone", ".")
	rootZone := &Zone{
		name:       ".",
		ns:         []dns.RR{},
		glueA:      []dns.RR{},
		glueAAAA:   []dns.RR{},
		searchedNS: []string{},
	}

	// Get NS record of root from cache
	rootNsKey := rr_cache.SetKey{
		Domain: ".",
		QType:  dns.TypeNS,
		QClass: dns.ClassINET,
	}
	if rootNsSet, ok := r.globalCache.GetWeightedRRSet(rootNsKey); ok {
		rootZone.ns = append(rootZone.ns, rootNsSet.RRs()...)
	}

	// Get glue records of root from cache
	for _, rootNS := range rootZone.ns {
		switch ns := rootNS.(type) {
		case *dns.NS:
			// Get A record of root-servers.net from cache
			rootAKey := rr_cache.SetKey{
				Domain: ns.Ns,
				QType:  dns.TypeA,
				QClass: dns.ClassINET,
			}
			if rootA, ok := r.globalCache.GetWeightedRRSet(rootAKey); ok {
				rootZone.glueA = append(rootZone.glueA, rootA.RRs()...)
			}

			// Get AAAA record of root-servers.net from cache
			rootAAAAKey := rr_cache.SetKey{
				Domain: ns.Ns,
				QType:  dns.TypeA,
				QClass: dns.ClassINET,
			}
			if rootAAAA, ok := r.globalCache.GetWeightedRRSet(rootAAAAKey); ok {
				rootZone.glueAAAA = append(rootZone.glueAAAA, rootAAAA.RRs()...)
			}
		default:
			r.logger.Warn("Get non-NS record in NS RRSet during Root zone initialization", "type", ns.Header().Rrtype)
		}
	}

	return rootZone
}

// ******************** Resolve Interface **********************

func (r *Resolver) resolve(depth int, seen map[string]bool) ([]dns.RR, error) {
	defer r.cancel()

	resolverStarted := time.Now()
	defer func() {
		r.logger.Debug("resolver duration", "duration", time.Since(resolverStarted), "domain", r.domain)
	}()

	if depth > maxDepth {
		return nil, fmt.Errorf("resolver query depth is too deep")
	}
	if seen[r.domain] {
		return nil, fmt.Errorf("resolver query loop detected")
	}
	seen[r.domain] = true

ResolveLoop:
	for {
		select {
		case <-r.ctx.Done():
			return nil, fmt.Errorf("resolver context is done")

		case <-r.readySignal:
			r.logger.Debug("resolver phase", "phase", "ready", "duration", time.Since(resolverStarted))
			t0 := time.Now()

			// Check if global cache has answers
			if rrSet, ok := r.globalCache.GetWeightedRRSet(rr_cache.SetKey{
				Domain: r.domain,
				QType:  r.qType,
				QClass: dns.ClassINET,
			}); ok {
				return rrSet.RRs(), nil
			}

			// Check if global cache has CNAME record, do subquery to get the answer
			if rrSet, ok := r.globalCache.GetWeightedRRSet(rr_cache.SetKey{
				Domain: r.domain,
				QType:  dns.TypeCNAME,
				QClass: dns.ClassINET,
			}); ok {
				var result []dns.RR
				for _, rr := range rrSet.RRs() {
					subResolver := NewResolver(r.server, rr.(*dns.CNAME).Target, r.qType)
					resolveResults, subErr := subResolver.resolve(depth+1, seen)
					if subErr != nil {
						return nil, fmt.Errorf("fail to do subquery for %s: %e", rr.(*dns.CNAME).Target, subErr)
					}
					result = append(result, rr)                // add CNAME record to result
					result = append(result, resolveResults...) // add subquery result to result
				}
				return result, nil
			}
			r.logger.Debug("resolver phase", "phase", "check_cache", "duration", time.Since(t0))

			// Check if the resolver has the answer
			if len(r.answers) > 0 {
				return r.answers, nil
			}

			// Get current zone
			currentZone := r.stack[r.currentZoneIdx]

			// Get random unsearched NS record from current zone
			t1 := time.Now()
			ns, getErr := currentZone.getRandomNS()
			if getErr != nil {
				return nil, fmt.Errorf("fail to get random NS record: %e", getErr)
			}

			// If there is no NS unsearched record in current zone, fallback to the previous zone
			if ns == nil {
				// If there is only one zone left, there is no need to fallback
				if len(r.stack) == 1 || r.currentZoneIdx == 0 {
					r.logger.Info("All root NS has been queried, and there is no answer")
					// return nil, nil to indicate that there is no answer
					return nil, nil
				}

				// Fallback to the previous zone
				r.logger.Info("All root NS has been queried, fallback to the previous zone")
				r.currentZoneIdx--
				r.signalReady()
				continue ResolveLoop
			}

			r.logger.Debug("resolver phase", "phase", "get_random_ns", "duration", time.Since(t1))
			r.logger.Debug("Get random NS record", "zone", currentZone.name, "ns", ns.Ns)

			// Get glue records of the NS record
			glues, glueErr := currentZone.getGlue(ns.Ns, r.server.supportIPv6.Load())
			if glueErr != nil {
				return nil, fmt.Errorf("fail to get glue records of NS record: %e", glueErr)
			}

			// If there is available glue record, handle the query directly
			if len(glues) != 0 {
				r.handleRRSetQuery(currentZone, ns.Ns, glues)
			} else if cachedAGlue, ok := r.globalCache.GetWeightedRRSet(rr_cache.SetKey{
				Domain: ns.Ns,
				QType:  dns.TypeA,
				QClass: dns.ClassINET}); ok {
				// If there is no available glue record, try to get the A glue record from global cache
				r.handleWeightRRSetQuery(currentZone, ns.Ns, cachedAGlue)
			} else if r.server.supportIPv6.Load() {
				if cachedAAAAGlue, ok := r.globalCache.GetWeightedRRSet(rr_cache.SetKey{
					Domain: ns.Ns,
					QType:  dns.TypeAAAA,
					QClass: dns.ClassINET}); ok {
					// If there is no available glue record, try to get the AAAA glue record from global cache
					r.handleWeightRRSetQuery(currentZone, ns.Ns, cachedAAAAGlue)
				}
			} else {
				r.logger.Info("No glue record available for NS record, query for it", "ns", ns.Ns)

				// use sub resolver to get the glue record
				subResolver := NewResolver(r.server, ns.Ns, dns.TypeA)
				subResults, subErr := subResolver.resolve(depth+1, seen)
				if subErr != nil {
					return nil, fmt.Errorf("fail to do subquery for %s: %e", ns.Ns, subErr)
				}

				// If subquery get no answer, continue to the next NS record
				if len(subResults) == 0 {
					r.logger.Warn("Subquery for NS record get no answer, continue to the next NS record", "ns", ns.Ns)
					r.signalReady()
					continue ResolveLoop
				}

				// Store the subquery result to local cache and global cache
				for _, glue := range subResults {
					currentZone.addGlue(glue)
					r.globalCache.AddRR(glue, true)
				}

				r.handleRRSetQuery(currentZone, ns.Ns, subResults)
			}
		}
	}
}

func (r *Resolver) handleWeightRRSetQuery(zone *Zone, ns string, wSet *rr_cache.WeightedRRSet) {
	// Pick a glue record from weighted RR set
	glue, picked := wSet.Pick()
	if !picked {
		r.logger.Error("Fail to pick glue record from weighted RR set")
	}

	go func() {
		if rtt, err := r.handleQuery(zone, ns, glue); err != nil {
			wSet.ReportRTT(glue, false, rtt)
			r.logger.Error("Fail to handle query", "err", err)
		} else {
			wSet.ReportRTT(glue, true, rtt)
		}
	}()
}

func (r *Resolver) handleRRSetQuery(zone *Zone, ns string, rrSet []dns.RR) {
	go func() {
		_, err := r.handleQuery(zone, ns, rrSet[rand.IntN(len(rrSet))])
		if err != nil {
			r.logger.Error("Fail to handle query", "err", err)
		}
	}()
}

// Usually query the target NS with the current zone's glue record
func (r *Resolver) handleQuery(currentZone *Zone, ns string, rr dns.RR) (time.Duration, error) {
	// Get the remote address of the glue record
	var remoteIP string
	switch rr := rr.(type) {
	case *dns.A:
		remoteIP = rr.A.String()
	case *dns.AAAA:
		remoteIP = rr.AAAA.String()
	default:
		return 0, fmt.Errorf("unsupported glue record type during query: %d", rr.Header().Rrtype)
	}

	if rtt, err := r.sendQuery(remoteIP); err != nil {
		return 0, err
	} else {
		currentZone.markSearchedNS(ns)
		return rtt, nil
	}
}

func (r *Resolver) sendQuery(remoteIP string) (time.Duration, error) {
	queryStarted := time.Now()
	defer func() {
		r.logger.Debug("resolver query duration", "duration", time.Since(queryStarted), "domain", r.domain)
	}()

	// Manage the number of queries
	r.queriesCount.Add(1)
	defer func() {
		r.queriesCount.Add(-1)
		// if the count is 0, signal the resolver that it is ready
		if r.queriesCount.Load() == 0 {
			r.signalReady()
		}
	}()

	// Get the remote address
	addrStr := net.JoinHostPort(remoteIP, "53")
	remoteAddr, resolveErr := net.ResolveUDPAddr("udp", addrStr)
	if resolveErr != nil {
		return 0, fmt.Errorf("fail to resolve UDP address %s: %e", addrStr, resolveErr)
	}

	// Wait for the query signal
	t0 := time.Now()
	r.server.throttle.Wait(remoteIP)
	if r.ctx.Err() != nil {
		return 0, fmt.Errorf("resolver context is done")
	}
	r.logger.Debug("resolver phase", "phase", "wait_timer", "duration", time.Since(t0))

	// Create a UDP connection
	conn, connErr := net.DialUDP("udp", nil, remoteAddr)
	if connErr != nil {
		return 0, fmt.Errorf("fail to dial UDP: %e", connErr)
	}
	defer func(conn *net.UDPConn) {
		err := conn.Close()
		if err != nil {
			r.logger.Error("Fail to close UDP connection", "err", err)
		}
	}(conn)

	// Set the deadline for the connection
	setErr := conn.SetDeadline(time.Now().Add(timeoutInterval))
	if setErr != nil {
		return 0, fmt.Errorf("fail to set UDP connection deadline: %e", setErr)
	}

	// Generate a new DNS query message
	req := newDnsQueryMsg(r.domain, r.qType)
	currentTransactionID := req.MsgHdr.Id

	// Pack the DNS query
	payload, packErr := req.Pack()
	if packErr != nil {
		return 0, fmt.Errorf("fail to pack DNS query: %e", packErr)
	}

	t1 := time.Now()
	// Send the DNS query
	if _, sendErr := conn.Write(payload); sendErr != nil {
		return 0, fmt.Errorf("fail to send DNS query: %e", sendErr)
	}

	// Get the buffer size based on the remote address
	var size int
	if remoteAddr.IP.To4() != nil {
		size = UDP4MTU
	} else {
		size = UDP6MTU
	}
	buf := make([]byte, size)

	// Read the DNS response from the socket
	var nByte int
	for {
		n, addr, readErr := conn.ReadFrom(buf)
		if readErr != nil {
			// Check if the error is a timeout
			var ne net.Error
			if errors.As(readErr, &ne) && ne.Timeout() {
				return 0, fmt.Errorf("UDP connection timeout: %e", readErr)
			}

			return 0, fmt.Errorf("fail to read from UDP connection: %e", readErr)
		}

		// Check the source address of the response
		if addr.String() != remoteAddr.String() {
			r.logger.Warn("Received DNS response from unexpected address",
				"addr", addr,
				"expected", remoteAddr,
			)
			continue
		}

		// record the number of bytes read
		nByte = n
		break
	}
	r.logger.Debug("resolver phase", "phase", "get_response", "duration", time.Since(t1), "domain", r.domain)
	rtt := time.Since(t1)

	// Unpack the DNS response
	var resp dns.Msg
	if unpackErr := resp.Unpack(buf[:nByte]); unpackErr != nil {
		return rtt, fmt.Errorf("fail to unpack DNS response: %e", unpackErr)
	}

	// If the response is not a DNS response
	if !resp.Response {
		return rtt, fmt.Errorf("received non-response DNS message")
	}

	// Check if the response has the correct transaction ID
	if resp.MsgHdr.Id != currentTransactionID {
		r.logger.Debug("Received DNS response with wrong transaction ID",
			"expected", currentTransactionID,
			"actual", resp.MsgHdr.Id,
		)
		return rtt, fmt.Errorf("received DNS response with wrong transaction ID")
	}

	// Check if the response has no answer
	if len(resp.Answer) == 0 && len(resp.Ns) == 0 {
		r.logger.Warn("Received DNS response with no answer")
		return rtt, nil
	}

	r.logger.Debug("Received DNS response",
		"id", resp.MsgHdr.Id,
		"answer", len(resp.Answer),
		"ns", len(resp.Ns),
		"additional", len(resp.Extra),
	)

	// Handle the Answers in the response
	var getAnswer bool
	for _, rr := range resp.Answer {
		// If this is the final answer, add it to the local cache and global cache
		if rr.Header().Rrtype == r.qType && rr.Header().Name == r.domain {
			r.answers = append(r.answers, rr) // Add answer to local cache
			r.globalCache.AddRR(rr, true)     // Add answer to global cache
			getAnswer = true
			r.logger.Info("Get answer during query", "answer", rr.String())
			continue
		}

		// If this is a CNAME record, do subquery to get the answer
		if cname, ok := rr.(*dns.CNAME); ok && rr.Header().Name == r.domain {
			r.logger.Info("Get CNAME record during query", "cname", cname.Target)
			getAnswer = true
			r.globalCache.AddRR(rr, true)
			continue
		}

		// Add answer to local cache of glue
		zone := r.findZone(rr.Header().Name)
		if zone == nil {
			continue
		}
		// Check if glue record is in bailiwick
		if dns.IsSubDomain(zone.name, dns.Fqdn(rr.Header().Name)) {
			r.globalCache.AddRR(rr, true)
		}
		zone.addGlue(rr)
	}
	if getAnswer {
		return rtt, nil // return nil if there is an answer
	}

	// Handle Authoritative RRs
	for _, rr := range resp.Ns {
		if rr.Header().Rrtype != dns.TypeNS {
			// TODO: new feature: resolver not support DNSSEC yet
			//r.logger.Warn("Resolver not support DNSSEC yet, ignore non-NS record in Authoritative RRs", "rr-type",
			//	rr.Header().Rrtype)
			continue
		}
		zone := r.getZone(rr.Header().Name)
		zone.addNS(rr)
	}

	// Handle Additional RRs
	for _, rr := range resp.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			//r.logger.Info("Ignore OPT record")
			continue
		}
		zone := r.findZone(rr.Header().Name)
		if zone == nil {
			continue
		}
		// Check if glue record is in bailiwick
		if dns.IsSubDomain(zone.name, dns.Fqdn(rr.Header().Name)) {
			r.globalCache.AddRR(rr, true)
		}
		zone.addGlue(rr)
	}

	// Check if resolver needs to go into next zone
	if r.queriesCount.Load() == 1 { // 1 is this query
		if (r.currentZoneIdx + 1) < len(r.stack) {
			r.currentZoneIdx++
		}
	}
	return rtt, nil
}

func (r *Resolver) getZone(name string) *Zone {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	for _, zone := range r.stack {
		if zone.name == name {
			return zone
		}
	}

	zone := &Zone{
		logger:     r.logger.With("zone", name),
		name:       name,
		mutex:      sync.Mutex{},
		ns:         []dns.RR{},
		glueA:      []dns.RR{},
		glueAAAA:   []dns.RR{},
		searchedNS: []string{},
	}
	zone.ttlCountdown(r.ctx)
	r.stack = append(r.stack, zone)
	return zone
}

func (r *Resolver) findZone(name string) *Zone {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	for _, zone := range r.stack {
		for _, ns := range zone.ns {
			if ns.(*dns.NS).Ns == name {
				return zone
			}
		}
	}
	return nil
}

func (z *Zone) addNS(rr dns.RR) {
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

func (z *Zone) addGlue(rr dns.RR) {
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
func (z *Zone) getRandomNS() (*dns.NS, error) {
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

func (z *Zone) getGlue(domain string, supportIPv6 bool) ([]dns.RR, error) {
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

func (z *Zone) ttlCountdown(ctx context.Context) {
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

func (z *Zone) markSearchedNS(ns string) {
	z.mutex.Lock()
	defer z.mutex.Unlock()
	z.searchedNS = append(z.searchedNS, ns)
}

func (r *Resolver) signalReady() {
	select {
	case r.readySignal <- true:
	default:
	}
}

// ******************** Helper Method **********************

func newDnsQueryMsg(name string, t uint16) *dns.Msg {
	// Create a new DNS request
	dnsReqHdr := dns.MsgHdr{
		Id:                uint16(rand.Uint32()),
		Response:          false,
		Opcode:            0,
		Truncated:         false,
		RecursionDesired:  false,
		Zero:              false,
		AuthenticatedData: true,
		CheckingDisabled:  false,
	}

	dnsReq := &dns.Msg{
		MsgHdr:   dnsReqHdr,
		Compress: false,
	}

	// Set the question
	dnsReq.SetQuestion(name, t)
	dnsReq.RecursionDesired = false

	opt := &dns.OPT{}
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)
	opt.SetDo(true)
	dnsReq.Extra = append(dnsReq.Extra, opt)

	return dnsReq
}

func (r *Resolver) dump() {
	for _, zone := range r.stack {
		zone.dump()
	}
}

func (z *Zone) dump() {
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
