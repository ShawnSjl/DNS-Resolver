package dns

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/brown-cs1680-s26/final-jiale-xinran/internal/server/dns/graph"
	"github.com/miekg/dns"
)

const (
	timeoutInterval = 1 * time.Second
)

type Request struct {
	ctx   context.Context
	table *RequestTable

	entry             Entry           // entry to store the original query request and address
	currTransactionID uint16          // current transaction ID
	queries           []*Query        // queries to the outside
	resolver          *graph.Resolver // resolver for the query
}

type Query struct {
	ctx context.Context

	req    *dns.Msg // query request
	isIPv6 bool
	state  QueryState  // state of the query request
	timer  *time.Timer // timer for resending the query
}

type QueryState uint8

const (
	QueryStateSent QueryState = iota
	QueryStateSuccess
	QueryStateTimeout
	QueryStateError
)

// ******************** Initialization Interface **********************

func NewRequest(table *RequestTable, entry Entry) (*Request, error) {
	ctx := context.WithoutCancel(table.ctx)

	request := &Request{
		ctx:      ctx,
		table:    table,
		entry:    entry,
		queries:  []*Query{},
		resolver: graph.NewResolver("."),
	}

	return request, nil
}

// ******************** Send Interface **********************

func (r *Request) GenerateAndSendNewQueries() error {
	// Return if there are queries
	if len(r.queries) != 0 {
		return fmt.Errorf("queries not empty")
	}

	// If the resolver stack is empty, query the ROOT NS
	if len(r.resolver.Stack) == 0 {
		r.currTransactionID = r.table.getNewTransactionID()

		// Create query message for root dns
		dnsQueryReq := newDnsQueryMsg(r.currTransactionID, ".", dns.TypeNS)

		// Send the query message
		r.sendQuery(dnsQueryReq, false)
		//r.sendQuery(dnsQueryReq, true)

		return nil
	}

	log.Printf("Resolver stack is not empty, rest logic not implemented yet")

	return nil
}

func (r *Request) sendQuery(req *dns.Msg, isIPv6 bool) {
	// Create a new query record for the DNS message
	query := &Query{
		ctx:    r.ctx,
		req:    req,
		isIPv6: isIPv6,
		state:  QueryStateSent,
	}
	r.queries = append(r.queries, query)

	go func(r *Request, query *Query) {
		// Determine the network type
		var netType string
		var bufSize int
		if query.isIPv6 {
			netType = "udp6"
			bufSize = UDP6MTU
		} else {
			netType = "udp4"
			bufSize = UDP4MTU
		}

		// Get the remote address
		remoteAddr, _ := net.ResolveUDPAddr(netType, "127.0.0.11:40120")

		// Create a UDP connection
		conn, connErr := net.DialUDP(netType, nil, remoteAddr)
		if connErr != nil {
			log.Println("Fail to dial UDP: ", connErr)
			query.state = QueryStateError
			return
		}
		defer func(conn *net.UDPConn) {
			err := conn.Close()
			if err != nil {
				log.Println("Fail to close UDP connection: ", err)
			}
		}(conn)

		// Pack the DNS query
		payload, packErr := query.req.Pack()
		if packErr != nil {
			log.Println("Fail to pack DNS query: ", packErr)
			query.state = QueryStateError
			return
		}

		// Send the DNS query
		select {
		case <-query.ctx.Done():
			return
		case <-r.table.sendSignal:
			r.table.ResetTimer()
		}
		if _, sendErr := conn.Write(payload); sendErr != nil {
			log.Println("Fail to send DNS query: ", sendErr)
			query.state = QueryStateError
			return
		}

		log.Println(query.req.String())

		// Read the DNS response
		buf := make([]byte, bufSize)
		n, addr, readErr := conn.ReadFrom(buf)
		if readErr != nil {
			log.Println("Fail to read from UDP connection: ", readErr)
			query.state = QueryStateError
			return
		}

		// Unpack the DNS response
		var resp dns.Msg
		if unpackErr := resp.Unpack(buf[:n]); unpackErr != nil {
			log.Println("Fail to unpack DNS response: ", unpackErr)
			query.state = QueryStateError
			return
		}

		log.Printf("Received DNS response from %s: \n", addr)
		log.Printf("%s\n", resp.String())
	}(r, query)
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

// ******************** Receive Interface **********************
