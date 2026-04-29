package dns

import (
	"context"
	"time"

	"github.com/brown-cs1680-s26/final-jiale-xinran/internal/server/dns/graph"
	"github.com/miekg/dns"
)

const (
	resendInterval = 1 * time.Second
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

	req   *dns.Msg    // query request
	state QueryState  // state of the query request
	timer *time.Timer // timer for resending the query
}

type QueryState uint8

const (
	QueryStateSent QueryState = iota
	QueryStateSuccess
	QueryStateTimeout
)

// ******************** Initialization Interface **********************

func NewRequest(table *RequestTable, entry Entry) (*Request, error) {
	ctx := context.WithoutCancel(table.ctx)

	query := &Request{
		ctx:      ctx,
		entry:    entry,
		queries:  []*Query{},
		resolver: graph.NewResolver("."),
	}

	return query, nil
}

// ******************** Interface **********************

func (r *Request) GenerateNewRequests() error {
	// Return if there are queries that have already been sent and are not yet timed out
	if len(r.queries) != 0 {
		for _, query := range r.queries {
			if query.state == QueryStateSent {
				return nil
			}
		}
	}

	// If the resolver stack is empty, query the ROOT NS
	if len(r.resolver.Stack) == 0 {
		r.currTransactionID = r.table.getNewTransactionID()

		// Create a new DNS request
		dnsReqHdr := dns.MsgHdr{
			Id:                r.currTransactionID,
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
		dnsReq.SetQuestion("<ROOT>", dns.TypeNS)
		dnsReq.RecursionDesired = false

		return nil
	}

	return nil
}

// ******************** Resend Timer **********************

func (r *Request) resendTimer() {
	/* TODO: not implemented yet
	1. create a new goroutine
	2. wait for the timer to expire or the context to be canceled
	3. forward the query request to the outside
	*/
}
