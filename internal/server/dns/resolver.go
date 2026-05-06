package dns

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	timeoutInterval = 1 * time.Second
)

var rootDNS = []string{
	"a.root-servers.net.",
	"b.root-servers.net.",
	"c.root-servers.net.",
	"d.root-servers.net.",
	"e.root-servers.net.",
	"f.root-servers.net.",
	"g.root-servers.net.",
	"h.root-servers.net.",
	"i.root-servers.net.",
	"j.root-servers.net.",
	"k.root-servers.net.",
	"l.root-servers.net.",
	"m.root-servers.net.",
}

type Resolver struct {
	ctx    context.Context
	cancel context.CancelFunc

	server      *Server
	globalCache *RecordCache // cache for DNS records

	// variables for the original query
	entry    Entry // entry to store the original query request and address
	goal     string
	goalType uint16

	currTransactionID uint16 // current transaction ID

	queriesCount atomic.Int32 // number of queries in progress
	readySignal  chan bool    // signal to tell the resolver that all queries are finished

	currentZoneIdx int        // index of zone in the stack
	mutex          sync.Mutex // lock of stack
	stack          []*Zone
}

type Zone struct {
	name  string     // i.e. ".", "com.", "example.com."
	mutex sync.Mutex // lock of nodes

	ns       []dns.RR
	glueA    []dns.RR
	glueAAAA []dns.RR

	searchedNS []string
}

// ******************** Initialization Interface **********************

func NewResolver(server *Server, entry Entry) *Resolver {
	ctx, cancel := context.WithCancel(server.ctx)

	// Add the root zone to the stack
	resolver := &Resolver{
		ctx:    ctx,
		cancel: cancel,

		server:      server,
		globalCache: server.cache,

		entry:    entry,
		goal:     entry.msg.Question[0].Name,
		goalType: entry.msg.Question[0].Qtype,

		queriesCount: atomic.Int32{},
		readySignal:  make(chan bool, 1),

		mutex:          sync.Mutex{},
		currentZoneIdx: 0,
		stack:          []*Zone{},
	}

	// Create the root zone
	rootZone := resolver.createRootZone()
	resolver.stack = append(resolver.stack, rootZone)

	resolver.signalReady()

	return resolver
}

func (r *Resolver) createRootZone() *Zone {
	rootZone := &Zone{
		name:       ".",
		ns:         []dns.RR{},
		glueA:      []dns.RR{},
		glueAAAA:   []dns.RR{},
		searchedNS: []string{},
	}

	// Get NS record of root from cache
	if rootNS, ok := r.globalCache.get(".", dns.TypeNS, dns.ClassINET); ok {
		rootZone.ns = append(rootZone.ns, rootNS...)
	}

	// Get glue records of root from cache
	for _, rootNS := range rootZone.ns {
		switch ns := rootNS.(type) {
		case *dns.NS:
			// Get A record of root-servers.net from cache
			if rootA, ok := r.globalCache.get(ns.Ns, dns.TypeA, dns.ClassINET); ok {
				rootZone.glueA = append(rootZone.glueA, rootA...)
			}

			// Get AAAA record of root-servers.net from cache
			if rootAAAA, ok := r.globalCache.get(ns.Ns, dns.TypeAAAA, dns.ClassINET); ok {
				rootZone.glueAAAA = append(rootZone.glueAAAA, rootAAAA...)
			}
		default:
			log.Printf("Get non-NS record in NS RRSet during Root zone initialization: %d\n", ns.Header().Rrtype)
		}
	}

	return rootZone
}

// ******************** Resolve Interface **********************

func (r *Resolver) resolve() {
	go func() {
	ResolveLoop:
		for {
			select {
			case <-r.ctx.Done():
				return

			case <-r.readySignal:
				// Recycle old one and get new transaction ID for the current query
				r.server.idPool.recycleTransactionID(r.currTransactionID)
				r.currTransactionID = r.server.idPool.getNewTransactionID()

				// Get current zone
				currentZone := r.stack[r.currentZoneIdx]

				// Get random unsearched NS record from current zone
				ns, getErr := currentZone.getRandomNS()
				if getErr != nil {
					log.Println("Fail to get random NS record: ", getErr)
					r.terminate()
					continue ResolveLoop
				}

				// If there is no NS unsearched record in current zone, fallback to the previous zone
				if ns == nil {
					// If there is only one zone left, there is no need to fallback
					if len(r.stack) == 1 || r.currentZoneIdx == 0 {
						log.Println("All root NS has been queried, and there is no answer")

						// send failure response to the client
						resp := dns.Msg{}
						resp.SetReply(r.entry.msg)
						resp.Rcode = dns.RcodeNameError
						entry := Entry{
							msg:  &resp,
							addr: r.entry.addr,
						}
						r.server.insideSendQueue <- entry

						// exit the resolver
						r.terminate()
						continue ResolveLoop
					}

					// Fallback to the previous zone
					log.Println("No NS record in current zone, fallback to the previous zone")
					r.currentZoneIdx--
					r.signalReady()
					continue ResolveLoop
				}

				log.Printf("[debug] current zone: %s, NS record: %s\n", currentZone.name, ns.String())

				// Get glue records of the NS record
				glues, glueErr := currentZone.getGlue(ns.Ns, r.server.supportIPv6.Load())
				if glueErr != nil {
					log.Println("Fail to get glue records of NS record: ", glueErr)
					r.terminate()
					continue ResolveLoop
				}

				// TODO: If there is no available glue record, query for it
				if len(glues) == 0 {
					log.Println("No glue record available for NS record: ", ns.Ns)
					log.Println("Not implemented yet")
					r.terminate()
					continue ResolveLoop
				}

				// Choose a glue record randomly and get its IP address
				glue := glues[rand.IntN(len(glues))]
				var remoteIP string
				switch rr := glue.(type) {
				case *dns.A:
					remoteIP = rr.A.String()
				case *dns.AAAA:
					remoteIP = rr.AAAA.String()
				default:
					log.Println("Unsupported glue record type during query: ", ns.Ns)
					r.terminate()
					continue ResolveLoop
				}

				// Send the query to the chosen glue server
				go func() {
					r.queriesCount.Add(1)
					sendErr := r.sendQuery(remoteIP)
					if sendErr != nil {
						log.Println("Fail to send query: ", sendErr)
					} else {
						currentZone.searchedNS = append(currentZone.searchedNS, ns.Ns)
					}
				}()
			}
		}
	}()
}

func (r *Resolver) sendQuery(remoteIP string) error {
	// Minus 1 to indicate the query is finished, if the count is 0, signal the resolver that it is ready
	defer func() {
		r.queriesCount.Add(-1)
		if r.queriesCount.Load() == 0 {
			r.signalReady()
		}
	}()

	// Get the remote address
	addrStr := net.JoinHostPort(remoteIP, "53")
	remoteAddr, resolveErr := net.ResolveUDPAddr("udp", addrStr)
	if resolveErr != nil {
		return fmt.Errorf("fail to resolve UDP address %s: %e", addrStr, resolveErr)
	}

	// Wait for the query signal
	select {
	case <-r.ctx.Done():
		return fmt.Errorf("resolver context is done")
	case <-r.server.querySignal:
		r.server.resetTimer()
	}

	// Create a UDP connection
	conn, connErr := net.DialUDP("udp", nil, remoteAddr)
	if connErr != nil {
		return fmt.Errorf("fail to dial UDP: %e", connErr)
	}
	defer func(conn *net.UDPConn) {
		err := conn.Close()
		if err != nil {
			log.Println("Fail to close UDP connection: ", err)
		}
	}(conn)

	// Set the deadline for the connection
	setErr := conn.SetDeadline(time.Now().Add(timeoutInterval))
	if setErr != nil {
		return fmt.Errorf("fail to set UDP connection deadline: %e", setErr)
	}

	// Generate a new DNS query message
	req := newDnsQueryMsg(r.currTransactionID, r.goal, r.goalType)

	// Pack the DNS query
	payload, packErr := req.Pack()
	if packErr != nil {
		return fmt.Errorf("fail to pack DNS query: %e", packErr)
	}

	// Send the DNS query
	if _, sendErr := conn.Write(payload); sendErr != nil {
		return fmt.Errorf("fail to send DNS query: %e", sendErr)
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
				return fmt.Errorf("UDP connection timeout: %e", readErr)
			}

			return fmt.Errorf("fail to read from UDP connection: %e", readErr)
		}

		// Check the source address of the response
		if addr.String() != remoteAddr.String() {
			log.Println("Received DNS response from unexpected address: ", addr)
			continue
		}

		// record the number of bytes read
		nByte = n
		break
	}

	// Unpack the DNS response
	var resp dns.Msg
	if unpackErr := resp.Unpack(buf[:nByte]); unpackErr != nil {
		return fmt.Errorf("fail to unpack DNS response: %e", unpackErr)
	}

	// If the response is not a DNS response
	if !resp.Response {
		return fmt.Errorf("received non-response DNS message")
	}

	// Check if the response has no answer
	if len(resp.Answer) == 0 && len(resp.Ns) == 0 {
		log.Println("Received DNS response with no answer")
		return nil
	}

	log.Printf("[debug] received %d answers, %d NS records, %d additional records\n", len(resp.Answer), len(resp.Ns), len(resp.Extra))

	// Handle the Answers in the response
	for _, rr := range resp.Answer {
		// If this is the final answer
		if rr.Header().Rrtype == r.goalType && rr.Header().Name == r.goal {
			// return the answer to the client
			answerResp := dns.Msg{}
			answerResp.SetReply(r.entry.msg)
			answerResp.Authoritative = true
			answerResp.Answer = append(answerResp.Answer, rr)
			entry := Entry{
				msg:  &answerResp,
				addr: r.entry.addr,
			}
			r.server.insideSendQueue <- entry

			// Add answer to global cache
			r.globalCache.add(rr, true)

			log.Println("Get answer during query: ", rr.String())
			r.terminate()
			return nil
		}

		// Add answer to local cache of glue
		zone := r.findZone(rr.Header().Name)
		if zone == nil {
			continue
		}
		zone.addGlue(rr, true)
	}

	// Handle Authoritative RRs
	for _, rr := range resp.Ns {
		if rr.Header().Rrtype != dns.TypeNS {
			log.Printf("Ignore non-NS record in Authoritative RRs: %d\n", rr.Header().Rrtype)
			continue
		}
		zone := r.getZone(rr.Header().Name)
		zone.addNS(rr)
	}

	// Handle Additional RRs
	for _, rr := range resp.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			log.Println("Ignore OPT record")
			continue
		}
		zone := r.findZone(rr.Header().Name)
		if zone == nil {
			continue
		}
		zone.addGlue(rr, true)
	}

	r.dump()
	log.Println("----------------------------------------")

	// Check if resolver needs to go into next zone
	if r.queriesCount.Load() == 1 { // 1 is this query
		if (r.currentZoneIdx + 1) < len(r.stack) {
			r.currentZoneIdx++
		}
	}
	return nil
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
		name:       name,
		mutex:      sync.Mutex{},
		ns:         []dns.RR{},
		glueA:      []dns.RR{},
		glueAAAA:   []dns.RR{},
		searchedNS: []string{},
	}
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

func (z *Zone) addGlue(rr dns.RR, trust bool) {
	z.mutex.Lock()
	defer z.mutex.Unlock()

	if !trust {
		// TODO: check if glue record is in bailiwick
		log.Printf("Check if glue record is in bailiwick, not implement yet\n")
	}

	switch rr.Header().Rrtype {
	case dns.TypeA:
		z.glueA = append(z.glueA, rr)
	case dns.TypeAAAA:
		z.glueAAAA = append(z.glueAAAA, rr)
	default:
		log.Printf("Cannot add unsupported record type %d to Zone %s\n", rr.Header().Rrtype, z.name)
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
				return ns, nil
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
			result = append(result, glue)
		}
	}

	if supportIPv6 {
		for _, glue := range z.glueAAAA {
			if dns.Fqdn(glue.Header().Name) == dns.Fqdn(domain) {
				result = append(result, glue)
			}
		}
	}

	return result, nil
}

func (r *Resolver) signalReady() {
	select {
	case r.readySignal <- true:
	default:
	}
}

func (r *Resolver) terminate() {
	r.server.idPool.recycleTransactionID(r.currTransactionID)
	r.cancel()
}

// ******************** Helper Method **********************

func newDnsQueryMsg(id uint16, name string, t uint16) *dns.Msg {
	// Create a new DNS request
	dnsReqHdr := dns.MsgHdr{
		Id:                id,
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
