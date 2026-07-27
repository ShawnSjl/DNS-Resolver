package capability

import (
	"context"
	"log"
	"testing"
)

func TestHasIPv6Stack(t *testing.T) {
	ctx := context.Background()
	Start(ctx, nil, 0)

	got := HasIPv6Stack()
	log.Println("IPv6 stack:", got)
}
