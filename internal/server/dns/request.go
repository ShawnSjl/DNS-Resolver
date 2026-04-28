package dns

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

const (
	resendInterval = 1 * time.Second
)

type Request struct {
	ctx context.Context

	entry             Entry    // entry to store the original query request and address
	currTransactionID uint16   // current transaction ID
	queries           []*Query // queries to the outside
	// TODO: add direct graph
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

// ******************** Resend Timer **********************

func (r *Request) resendTimer() {
	/* TODO: not implemented yet
	1. create a new goroutine
	2. wait for the timer to expire or the context to be canceled
	3. forward the query request to the outside
	*/
}
