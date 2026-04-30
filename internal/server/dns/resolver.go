package dns

import (
	"context"
	"errors"
	"log"
	"math/rand/v2"
	"net"
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
	ctx   context.Context
	table *RequestTable
	cache *RecordCache // cache for DNS records

	// variables for the original query
	entry    Entry // entry to store the original query request and address
	goal     string
	goalType uint16

	currTransactionID uint16 // current transaction ID

	queriesCount atomic.Int32 // number of queries in progress
	readySignal  chan bool    // signal to tell the resolver that all queries are finished

	stack []*Zone
}

type Zone struct {
	zone  string // i.e. ".", "com.", "example.com."
	nodes []*Node
}

type Node struct {
	name   string // domain name
	qType  uint16 // query type
	qClass uint16 // query class
	rr     dns.RR

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

func NewResolver(table *RequestTable, entry Entry) *Resolver {
	// Create the root zone
	rootZone := createRootZone()

	ctx := context.WithoutCancel(table.ctx)

	// Add the root zone to the stack
	resolver := &Resolver{
		ctx:   ctx,
		table: table,
		cache: table.server.cache,

		entry:    entry,
		goal:     entry.msg.Question[0].Name,
		goalType: entry.msg.Question[0].Qtype,

		queriesCount: atomic.Int32{},
		readySignal:  make(chan bool, 1),

		stack: []*Zone{rootZone},
	}

	resolver.signalReady()

	return resolver
}

func createRootZone() *Zone {
	rootZone := &Zone{
		zone:  ".",
		nodes: []*Node{},
	}

	for _, dnsServer := range rootDNS {
		// Set A node with root-servers.net, address is in the cache
		v4Node := &Node{
			name:   dnsServer,
			qType:  dns.TypeA,
			qClass: dns.ClassINET,
			state:  StateHasAddress,
		}
		rootZone.nodes = append(rootZone.nodes, v4Node)

		// Set AAAA node with root-servers.net, address is in the cache
		v6Node := &Node{
			name:   dnsServer,
			qType:  dns.TypeAAAA,
			qClass: dns.ClassINET,
			state:  StateHasAddress,
		}
		rootZone.nodes = append(rootZone.nodes, v6Node)
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
				// Get new transaction ID for the current query
				currentTransactionID := r.table.getNewTransactionID()

				// Get current zone
				currentZone := r.stack[len(r.stack)-1]

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
					log.Printf("Node %s needs an address, not implement yet\n", node.name)
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
					msg := newDnsQueryMsg(currentTransactionID, r.goal, r.goalType)

					// Get the record
					rr := r.getRR(n)
					if rr == nil {
						n.state = StateAddressNeeded
						continue
					}

					// Send the query based on the record type
					switch rr.Header().Rrtype {
					case dns.TypeA:
						r.queriesCount.Add(1)
						go r.sendQuery(n, msg, rr.(*dns.A).A.String())
						continue ResolveLoop
					case dns.TypeAAAA:
						r.queriesCount.Add(1)
						go r.sendQuery(n, msg, rr.(*dns.AAAA).AAAA.String())
						continue ResolveLoop
					default:
						log.Println("Unsupported record type during query: ", rr.Header().Rrtype)
						n.state = StateAddressNeeded
					}
				}

				/* Fallback to the previous zone */
				// If there is only one zone left, there is no need to fallback
				if len(r.stack) == 1 {
					// TODO: send failure response to the client
					log.Println("All root NS has been queried, and there is no answer")
					return
				}

				// If all nodes have been queried, return to the previous zone
				log.Println("All nodes have been queried, return to the previous zone")
				r.stack = r.stack[:len(r.stack)-1]
				r.signalReady()
				continue ResolveLoop
			}
		}
	}()
}

func (r *Resolver) sendQuery(node *Node, req *dns.Msg, remoteIP string) {
	// Minus 1 to indicate the query is finished, if the count is 0, signal the resolver that it is ready
	//defer func() {
	//	r.queriesCount.Add(-1)
	//	if r.queriesCount.Load() == 0 {
	//		r.signalReady()
	//	}
	//}()

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

	// TODO: handle the response
	log.Printf("%s\n", resp.String())
}

func (r *Resolver) getRR(n *Node) dns.RR {
	if n.rr == nil {
		cacheKey := CacheKey{
			domain: n.name,
			qType:  n.qType,
			qClass: n.qClass,
		}
		rr, ok := r.cache.get(cacheKey)
		if !ok {
			log.Println("Failed to get record from cache")
			return nil
		}
		n.rr = rr
	}
	return n.rr
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
