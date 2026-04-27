package dns

import (
	"context"

	"github.com/miekg/dns"
)

type SendInside struct {
	ctx context.Context

	queue chan *dns.Msg
}

// ******************** Initialization Interface **********************

func NewSendInside(parent context.Context) *SendInside {
	ctx := context.WithoutCancel(parent) // cancel with parent context
	return &SendInside{
		ctx:   ctx,
		queue: make(chan *dns.Msg),
	}
}

// ******************** Handler **********************

func (si *SendInside) Handler() {
	// TODO: not implemented yet
	// goroutine to handle the outgoing DNS requests
}
