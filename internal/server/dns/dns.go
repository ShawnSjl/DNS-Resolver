package dns

import (
	"context"
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
	cache *RecordCache

	// question table
	questionTable *QuestionTable

	// blocked domains
	blocked *Blacklist
}
