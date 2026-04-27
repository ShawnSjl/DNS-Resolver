package dns

import (
	"context"

	"github.com/miekg/dns"
)

type SendOutside struct {
	ctx context.Context

	queue chan *dns.Msg
}

// ******************** Initialization Interface **********************

func NewSendOutside(parent context.Context) *SendOutside {
	ctx := context.WithoutCancel(parent) // cancel with parent context
	return &SendOutside{
		ctx:   ctx,
		queue: make(chan *dns.Msg),
	}
}

// ******************** Handler **********************

func (so *SendOutside) Handler() {
	// TODO: not implemented yet
	// goroutine to handle the outgoing DNS requests
}
