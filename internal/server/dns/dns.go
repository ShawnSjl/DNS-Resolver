package dns

import (
	"context"

	"github.com/brown-cs1680-s26/final-jiale-xinran/internal/server/cache"
)

type DNS struct {
	ctx    context.Context
	cancel context.CancelFunc

	// inside
	sendInsideQueue     *SendInside
	receivedInsideQueue *ReceiveInside

	// outside
	sendOutsideQueue     *SendOutside
	receivedOutsideQueue *ReceiveOutside

	// cache
	cache *cache.RecordCache

	// question table
	questionTable *QuestionTable

	// blocked domains
	blocked *Blacklist
}
