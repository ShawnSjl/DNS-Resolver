package dns

import (
	"math/rand/v2"
	"sync"
)

type TransactionIDPool struct {
	mutex sync.Mutex
	list  map[uint16]struct{} // use Transcation ID as the key
}

// ******************** Initialization Interface **********************

func newTransactionIDPool() *TransactionIDPool {
	return &TransactionIDPool{
		list:  make(map[uint16]struct{}),
		mutex: sync.Mutex{},
	}
}

// ******************** Interface **********************

func (t *TransactionIDPool) getNewTransactionID() uint16 {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	for {
		id := uint16(rand.Uint32())

		// avoid collision
		if _, ok := t.list[id]; !ok {
			t.list[id] = struct{}{}
			return id
		}
	}
}

func (t *TransactionIDPool) recycleTransactionID(id uint16) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	delete(t.list, id)
}
