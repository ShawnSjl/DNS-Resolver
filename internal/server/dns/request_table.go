package dns

import (
	"context"
	"math/rand/v2"
	"sync"
)

type RequestTable struct {
	ctx context.Context

	list  map[uint16]*Request // use Transcation ID as the key
	mutex sync.Mutex
}

// ******************** Initialization Interface **********************

func NewRequestTable(parent context.Context) *RequestTable {
	ctx := context.WithoutCancel(parent)
	return &RequestTable{
		ctx:   ctx,
		list:  make(map[uint16]*Request),
		mutex: sync.Mutex{},
	}
}

// ******************** Interface **********************

func (rt *RequestTable) Add(entry Entry) error {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	// create a new request based on the entry
	request, err := NewRequest(rt, entry)
	if err != nil {
		return err
	}

	// generate query request based on the direct graph
	err = request.GenerateNewRequests()
	if err != nil {
		return err
	}

	// add the request to the table
	rt.list[request.currTransactionID] = request

	return nil
}

func (rt *RequestTable) Get(transactionID uint16) (*Request, error) {
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

func (rt *RequestTable) Update(question *Request) error {
	rt.mutex.Lock()
	defer rt.mutex.Unlock()

	rt.list[question.currTransactionID] = question
	return nil
}

// ******************** Private Interface **********************

func (rt *RequestTable) getNewTransactionID() uint16 {
	for {
		id := uint16(rand.Uint32())

		// avoid collision
		if _, ok := rt.list[id]; !ok {
			return id
		}
	}
}
