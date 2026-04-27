package dns

import (
	"context"

	"github.com/brown-cs1680-s26/final-jiale-xinran/internal/server/cache"
	"github.com/miekg/dns"
)

type DNS struct {
	ctx    context.Context
	cancel context.CancelFunc

	// inside
	sendInsideQueue     chan *dns.Msg
	receivedInsideQueue chan *dns.Msg

	// outside
	sendOutsideQueue     chan *dns.Msg
	receivedOutsideQueue chan *dns.Msg

	// cache
	cache *cache.RecordCache

	// question table
	questionTable *QuestionTable

	// blocked domains
	blocked *Blacklist
}
