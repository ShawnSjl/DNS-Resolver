package dns

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/miekg/dns"
)

const (
	timeoutInterval = 1 * time.Second
)

type Request struct {
	ctx   context.Context
	table *RequestTable

	entry             Entry     // entry to store the original query request and address
	currTransactionID uint16    // current transaction ID
	queries           []*Query  // queries to the outside
	resolver          *Resolver // resolver for the query
}

type Query struct {
	ctx context.Context

	req   *dns.Msg     // query request
	addr  *net.UDPAddr // address of the remote server
	state QueryState   // state of the query request
	timer *time.Timer  // timer for resending the query
}

type QueryState uint8

const (
	QueryStateSent QueryState = iota
	QueryStateSuccess
	QueryStateTimeout
	QueryStateError
)

// ******************** Initialization Interface **********************

func newRequest(table *RequestTable, entry Entry) (*Request, error) {
	ctx := context.WithoutCancel(table.ctx)

	request := &Request{
		ctx:      ctx,
		table:    table,
		entry:    entry,
		queries:  []*Query{},
		resolver: NewResolver(table.server.cache, entry.msg.Question[0].Name, entry.msg.Question[0].Qtype),
	}

	return request, nil
}

// ******************** Send Interface **********************

func (r *Request) resolve() error {
	// Return if there are queries
	if len(r.queries) != 0 {
		return fmt.Errorf("queries not empty")
	}

	// Register the request in the request table
	r.currTransactionID = r.table.getNewTransactionID()
	r.table.list[r.currTransactionID] = r

	// Generate queries and send them to the outside
	messages, remoteIPs := r.resolver.getNextQueries(r.currTransactionID)
	for i, msg := range messages {
		r.sendQuery(msg, remoteIPs[i])
	}

	return nil
}

func (r *Request) sendQuery(req *dns.Msg, remoteIP string) {
	// Get the remote address
	addrStr := net.JoinHostPort(remoteIP, "53")
	remoteAddr, resolveErr := net.ResolveUDPAddr("udp", addrStr)
	if resolveErr != nil {
		log.Printf("Fail to resolve UDP address %s: %e\n", addrStr, resolveErr)
		return
	}

	// Create a new query record for the DNS message
	query := &Query{
		ctx:   r.ctx,
		req:   req,
		addr:  remoteAddr,
		state: QueryStateSent,
	}
	r.queries = append(r.queries, query)

	go func(r *Request, query *Query) {
		log.Println("Sending DNS query to ", query.addr)
		// Create a UDP connection
		conn, connErr := net.DialUDP("udp", nil, query.addr)
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
			r.table.resetTimer()
		}
		if _, sendErr := conn.Write(payload); sendErr != nil {
			log.Println("Fail to send DNS query: ", sendErr)
			query.state = QueryStateError
			return
		}

		log.Println(query.req.String())

		// Read the DNS response
		var size int
		if query.addr.IP.To4() != nil {
			size = UDP4MTU
		} else {
			size = UDP6MTU
		}
		buf := make([]byte, size)
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

		// TODO: handle the response
		log.Printf("Received DNS response from %s: \n", addr)
		log.Printf("%s\n", resp.String())
	}(r, query)
}
