package dns

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
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
	server *Server
	table  *RequestTable
	cache  *RecordCache // cache for DNS records

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
	nodes []*Node
}

type Node struct {
	rr    dns.RR
	getAt time.Time

	state        QueryState
	errorCount   int // number of times the node has error during the query
	timeoutCount int // number of times the node has timed out during the query
}

type QueryState int

const (
	StateUnknown       QueryState = iota
	StateHasAddress               // already has A or AAAA record
	StateAddressNeeded            // no A or AAAA record, need to query
	StateSuccess                  // the query succeeded
	StateZeroAnswer               // the query returned no answer
	StateError                    // the query failed
	StateTimeout                  // the query timed out
)

// ******************** Initialization Interface **********************

func NewResolver(server *Server, entry Entry) *Resolver {
	ctx := context.WithoutCancel(server.ctx)

	// Add the root zone to the stack
	resolver := &Resolver{
		ctx:    ctx,
		server: server,
		table:  server.requestTable,
		cache:  server.cache,

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
		name:  ".",
		nodes: []*Node{},
	}

	for _, dnsServer := range rootDNS {
		// Get A record of root-servers.net from cache
		if v4RootRR, ok := r.cache.get(CacheKey{
			domain: dnsServer,
			qType:  dns.TypeA,
			qClass: dns.ClassINET,
		}); ok {
			// Create node of RR with type A root-servers.net
			v4Node := &Node{
				rr:           v4RootRR,
				getAt:        time.Now(),
				state:        StateHasAddress,
				errorCount:   0,
				timeoutCount: 0,
			}
			rootZone.nodes = append(rootZone.nodes, v4Node)
		}

		// Get AAAA record of root-servers.net from cache
		if v6RootRR, ok := r.cache.get(CacheKey{
			domain: dnsServer,
			qType:  dns.TypeAAAA,
			qClass: dns.ClassINET,
		}); ok {
			// Create node of RR with type AAAA root-servers.net
			v6Node := &Node{
				rr:           v6RootRR,
				getAt:        time.Now(),
				state:        StateHasAddress,
				errorCount:   0,
				timeoutCount: 0,
			}
			rootZone.nodes = append(rootZone.nodes, v6Node)
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
				r.table.recycleTransactionID(r.currTransactionID)
				r.currTransactionID = r.table.getNewTransactionID()

				// Get current zone
				currentZone := r.stack[r.currentZoneIdx]

				/* Iterate through all nodes in the current zone, query the node if it needs an address */
				// Check if there is a node that needs an address
				var node *Node
				for _, n := range currentZone.nodes {
					if n.state == StateAddressNeeded {
						node = n
						break
					}
				}
				// If there is a node that needs an address, query it
				if node != nil {
					// TODO: need to resolve this domain name to an IP address
					log.Printf("Node %s needs an address, not implement yet\n", node.rr.String())
					continue ResolveLoop
				}

				/* Randomly choose a node to query */
				// Now all nodes should have a valid record, shuffle them
				shuffled := make([]*Node, len(currentZone.nodes))
				copy(shuffled, currentZone.nodes)
				rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

				// Check if there is a node that has not queried yet
				for _, n := range shuffled {
					// skip the node that has already queried
					if n.state == StateZeroAnswer || n.state == StateSuccess ||
						(n.state == StateError && n.errorCount >= 2) ||
						(n.state == StateTimeout && n.timeoutCount >= 3) {
						continue
					}

					// Generate a new DNS query message
					msg := newDnsQueryMsg(r.currTransactionID, r.goal, r.goalType)

					// Send the query based on the record type
					switch n.rr.Header().Rrtype {
					case dns.TypeA:
						r.queriesCount.Add(1)
						go r.sendQuery(n, msg, n.rr.(*dns.A).A.String())
						continue ResolveLoop
					case dns.TypeAAAA:
						r.queriesCount.Add(1)
						go r.sendQuery(n, msg, n.rr.(*dns.AAAA).AAAA.String())
						continue ResolveLoop
					default:
						log.Println("Unsupported record type during query: ", n.rr.Header().Rrtype)
						n.state = StateAddressNeeded
					}
				}

				/* Fallback to the previous zone */
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

					// recycle the transaction ID
					r.table.recycleTransactionID(r.currTransactionID)
					return
				}

				// If all nodes have been queried, return to the previous zone
				log.Println("All nodes have been queried, return to the previous zone")
				r.currentZoneIdx--
				r.signalReady()
				continue ResolveLoop
			}
		}
	}()
}

func (r *Resolver) sendQuery(node *Node, req *dns.Msg, remoteIP string) {
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
		log.Printf("Fail to resolve UDP address %s: %e\n", addrStr, resolveErr)
		node.state = StateError
		node.errorCount++
		return
	}

	// Wait for the query signal
	select {
	case <-r.ctx.Done():
		return
	case <-r.table.querySignal:
		r.table.resetTimer()
	}

	// Create a UDP connection
	conn, connErr := net.DialUDP("udp", nil, remoteAddr)
	if connErr != nil {
		log.Println("Fail to dial UDP: ", connErr)
		node.state = StateError
		node.errorCount++
		return
	}
	defer func(conn *net.UDPConn) {
		err := conn.Close()
		if err != nil {
			log.Println("Fail to close UDP connection: ", err)
		}
	}(conn)

	setErr := conn.SetDeadline(time.Now().Add(timeoutInterval))
	if setErr != nil {
		log.Println("Fail to set write deadline: ", setErr)
		node.state = StateError
		node.errorCount++
		return
	}

	// Pack the DNS query
	payload, packErr := req.Pack()
	if packErr != nil {
		log.Println("Fail to pack DNS query: ", packErr)
		node.state = StateError
		node.errorCount++
		return
	}

	// Send the DNS query
	if _, sendErr := conn.Write(payload); sendErr != nil {
		log.Println("Fail to send DNS query: ", sendErr)
		node.state = StateError
		node.errorCount++
		return
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
				node.state = StateTimeout
				node.timeoutCount++
				return
			}

			log.Println("Fail to read from UDP connection: ", readErr)
			node.state = StateError
			node.errorCount++
			return
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
		log.Println("Fail to unpack DNS response: ", unpackErr)
		node.state = StateError
		node.errorCount++
		return
	}

	// If the response is not a DNS response
	if !resp.Response {
		node.state = StateError
		node.errorCount++
		return
	}

	// Handle the Answers in the response
	isAuthoritative := resp.Authoritative
	for _, rr := range resp.Answer {
		switch rr.Header().Rrtype {
		case dns.TypeA:
			zone := r.getZone(rr.Header().Name)
			zone.addRecord(rr)

			// Add to cache if RR is authoritative
			if isAuthoritative {
				r.cache.add(rr)
			}

		case dns.TypeAAAA:
			zone := r.getZone(rr.Header().Name)
			zone.addRecord(rr)

			// Add to cache if RR is authoritative
			if isAuthoritative {
				r.cache.add(rr)
			}

		case dns.TypeNS:
			zone := r.getZone(rr.Header().Name)
			zone.addRecord(rr)

			// Add to cache if RR is authoritative
			if isAuthoritative {
				r.cache.add(rr)
			}

		default:
			// Ignore other type of RR for now
			log.Println("Unsupported record type during query: ", rr.Header().Rrtype)
		}
	}

	// Handle Authoritative RRs
	for _, rr := range resp.Ns {
		switch rr.Header().Rrtype {
		case dns.TypeA:
			zone := r.getZone(rr.Header().Name)
			zone.addRecord(rr)

			// Add to cache if RR is authoritative
			if isAuthoritative {
				r.cache.add(rr)
			}

		case dns.TypeAAAA:
			zone := r.getZone(rr.Header().Name)
			zone.addRecord(rr)

			// Add to cache if RR is authoritative
			if isAuthoritative {
				r.cache.add(rr)
			}

		case dns.TypeNS:
			zone := r.getZone(rr.Header().Name)
			zone.addRecord(rr)

			// Add to cache if RR is authoritative
			if isAuthoritative {
				r.cache.add(rr)
			}

		default:
			// Ignore other type of RR for now
			log.Println("Unsupported record type during query: ", rr.Header().Rrtype)
		}
	}

	// Handle Additional RRs
	for _, rr := range resp.Extra {
		switch rr.Header().Rrtype {
		case dns.TypeA, dns.TypeAAAA:
			log.Println("Get glue record during query: ", rr.String())

		default:
			// Ignore other type of RR for now
			log.Println("Unsupported record type during query: ", rr.Header().Rrtype)
		}
	}

	log.Printf("One query finished, current zone: %s, queries count: %d\n", r.stack[r.currentZoneIdx].name, r.queriesCount.Load())
	r.dump()
	log.Println("Cache")
	fmt.Println(r.cache.list())
	log.Println("----------------------------------------")

	// Check if resolver needs to go into next zone
	if r.queriesCount.Load() == 1 { // 1 is this query
		if (r.currentZoneIdx + 1) < len(r.stack) {
			r.currentZoneIdx++
		}
	}
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
		name:  name,
		mutex: sync.Mutex{},
		nodes: make([]*Node, 0),
	}
	r.stack = append(r.stack, zone)
	return zone
}

func (z *Zone) addRecord(rr dns.RR) {
	z.mutex.Lock()
	defer z.mutex.Unlock()

	// Iterate through current node to check duplicate
	for _, node := range z.nodes {
		// TODO: handle the timeout case

		// Check if there is a same RR in the node
		if dns.IsDuplicate(node.rr, rr) {
			node.rr = rr
			node.getAt = time.Now()
			return
		}
	}

	// Create a new node for this RR
	z.nodes = append(z.nodes, &Node{
		rr:           rr,
		getAt:        time.Now(),
		state:        StateAddressNeeded,
		errorCount:   0,
		timeoutCount: 0,
	})
}

func (z *Zone) handleGlue(rr dns.RR) {
	// TODO: Check if record is in bailiwick
	if rr.Header().Name == "glue" {
		// Glue this RR into Node
	}
}

func (r *Resolver) signalReady() {
	select {
	case r.readySignal <- true:
	default:
	}
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
		fmt.Println("Zone: ", zone.name)
		for _, node := range zone.nodes {
			fmt.Println("  Node: ", node.rr.String())
		}
	}
}
