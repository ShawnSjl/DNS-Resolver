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
	ctx    context.Context
	server *Server

	list  map[uint16]*Request // use Transcation ID as the key
	mutex sync.Mutex

	timer      *time.Timer
	sendSignal chan bool // signal to tell the request to send a query to the remote server
}

// ******************** Initialization Interface **********************

func newRequestTable(server *Server) *RequestTable {
	ctx := context.WithoutCancel(server.ctx)

	table := &RequestTable{
		ctx:        ctx,
		server:     server,
		list:       make(map[uint16]*Request),
		mutex:      sync.Mutex{},
		sendSignal: make(chan bool, 1),
	}
	table.sendIntervalTimer()

	return table
}

// ******************** Interface **********************

func (rt *RequestTable) add(entry Entry) error {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	// create a new request based on the entry
	request, err := newRequest(rt, entry)
	if err != nil {
		return err
	}

	// resolve the request by sending queries
	return request.resolve()
}

func (rt *RequestTable) get(transactionID uint16) (*Request, error) {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	// find the query in the table
	query, ok := rt.list[transactionID]
	if !ok {
		return nil, nil
	}

	// remove the question from the table and return it
	delete(rt.list, transactionID)
	return query, nil
}

func (rt *RequestTable) update(question *Request) error {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	rt.list[question.currTransactionID] = question
	return nil
}

func (rt *RequestTable) getNewTransactionID() uint16 {
	for {
		id := uint16(rand.Uint32())

		// avoid collision
		if _, ok := rt.list[id]; !ok {
			return id
		}
	}
}

// ******************** Outside DNS Request Handler **********************

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
				case rt.sendSignal <- true:
				default:
				}
			}
		}
	}()
}

func (rt *RequestTable) resetTimer() {
	rt.timer.Reset(queryInterval)
}
