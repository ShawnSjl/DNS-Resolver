package dns

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"
)

const (
	queryInterval = 100 * time.Millisecond
)

type RequestTable struct {
	ctx context.Context

	list  map[uint16]struct{} // use Transcation ID as the key
	mutex sync.Mutex

	timer       *time.Timer
	querySignal chan bool // signal to tell the request to send a query to the remote server
}

// ******************** Initialization Interface **********************

func newRequestTable(server *Server) *RequestTable {
	ctx := context.WithoutCancel(server.ctx)

	table := &RequestTable{
		ctx:         ctx,
		list:        make(map[uint16]struct{}),
		mutex:       sync.Mutex{},
		querySignal: make(chan bool, 1),
	}
	table.sendIntervalTimer()

	return table
}

// ******************** Interface **********************

func (rt *RequestTable) getNewTransactionID() uint16 {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	for {
		id := uint16(rand.Uint32())

		// avoid collision
		if _, ok := rt.list[id]; !ok {
			rt.list[id] = struct{}{}
			return id
		}
	}
}

func (rt *RequestTable) recycleTransactionID(id uint16) {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	delete(rt.list, id)
}

// ******************** Outside DNS Request Timer **********************

func (rt *RequestTable) sendIntervalTimer() {
	go func() {
		rt.timer = time.NewTimer(0 * time.Second)

		for {
			select {
			case <-rt.ctx.Done():
				if rt.timer != nil && !rt.timer.Stop() {
					select {
					case <-rt.timer.C:
					default:
					}
				}
				return

			case <-rt.timer.C:
				// Send a query to the remote server must wait for the timer.
				// signal the request in a non-blocking way
				select {
				case rt.querySignal <- true:
				default:
				}
			}
		}
	}()
}

func (rt *RequestTable) resetTimer() {
	rt.timer.Reset(queryInterval)
}
