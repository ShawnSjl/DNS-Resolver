package dns

import (
	"context"

	"github.com/miekg/dns"
)

type ReceiveInside struct {
	ctx context.Context

	queue chan *dns.Msg
}

// ******************** Initialization Interface **********************

func NewReceiveInside(parent context.Context) *ReceiveInside {
	ctx := context.WithoutCancel(parent) // cancel with parent context
	return &ReceiveInside{
		ctx:   ctx,
		queue: make(chan *dns.Msg),
	}
}

// ******************** Handler **********************

func (ro *ReceiveInside) Handler() {
	// TODO: not implemented yet
	// goroutine to handle the outgoing DNS requests
}
