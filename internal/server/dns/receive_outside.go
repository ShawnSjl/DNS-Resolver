package dns

import (
	"context"

	"github.com/miekg/dns"
)

type ReceiveOutside struct {
	ctx context.Context

	queue chan *dns.Msg
}

// ******************** Initialization Interface **********************

func NewReceiveOutside(parent context.Context) *ReceiveOutside {
	ctx := context.WithoutCancel(parent) // cancel with parent context
	return &ReceiveOutside{
		ctx:   ctx,
		queue: make(chan *dns.Msg),
	}
}

// ******************** Handler **********************

func (ro *ReceiveOutside) Handler() {
	// TODO: not implemented yet
	// goroutine to handle the outgoing DNS requests
}
