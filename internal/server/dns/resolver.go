package dns

import (
	"log"
	"math/rand/v2"

	"github.com/miekg/dns"
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
	goal     string
	goalType uint16

	stack []*Zone
	cache *RecordCache // cache for DNS records
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

	state        ResolveState
	timeoutCount int // number of times the node has timed out
}

type ResolveState int

const (
	StateUnknown       ResolveState = iota
	StateHasAddress                 // already has A or AAAA record
	StateAddressNeeded              // no A or AAAA record, need to query
	StateSuccess                    // the query succeeded
	StateZeroAnswer                 // the query returned no answer
	StateTimeout                    // the query timed out
)

// ******************** Initialization Interface **********************

func NewResolver(cache *RecordCache, goal string, goalType uint16) *Resolver {
	// Create the root zone
	rootZone := createRootZone()

	// Add the root zone to the stack
	resolver := &Resolver{
		goal:     goal,
		goalType: goalType,
		stack:    []*Zone{rootZone},
		cache:    cache,
	}

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

// ******************** Interface **********************

func (r *Resolver) getNextQueries(transactionID uint16) ([]*dns.Msg, []string) {
	currentZone := r.stack[len(r.stack)-1]

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
		return nil, nil
	}

	// Now all nodes should have a valid record, shuffle them
	shuffled := make([]*Node, len(currentZone.nodes))
	copy(shuffled, currentZone.nodes)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

	// Check if there is a node that has not queried yet
	for _, n := range shuffled {
		log.Println("Querying node: ", n.name)
		// skip the node that has already queried
		if n.state == StateZeroAnswer || n.state == StateSuccess || (n.state == StateTimeout && n.timeoutCount >= 3) {
			continue
		}

		// If there is a node that has not queried yet, query it
		messages := make([]*dns.Msg, 0)
		msg := newDnsQueryMsg(transactionID, r.goal, r.goalType)
		messages = append(messages, msg)

		ips := make([]string, 0)
		rr := r.getRR(n)
		if rr == nil {
			n.state = StateAddressNeeded
			continue
		}
		switch rr.Header().Rrtype {
		case dns.TypeA:
			ips = append(ips, rr.(*dns.A).A.String())
		case dns.TypeAAAA:
			ips = append(ips, rr.(*dns.AAAA).AAAA.String())
		default:
			log.Println("Unsupported record type during query: ", rr.Header().Rrtype)
			n.state = StateAddressNeeded
			continue
		}
		return messages, ips
	}

	// If all nodes have been queried, return to the previous zone
	log.Println("All nodes have been queried, return to the previous zone")
	r.stack = r.stack[:len(r.stack)-1]
	return r.getNextQueries(transactionID)
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
