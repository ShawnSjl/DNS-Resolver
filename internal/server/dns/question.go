package dns

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	resendInterval = 1 * time.Second
)

type QuestionTable struct {
	ctx context.Context

	list  map[uint16]Question // use Transcation ID as the key
	mutex sync.Mutex
}

type Question struct {
	ctx    context.Context
	cancel context.CancelFunc

	port     uint16   // port number of incoming query request
	original *dns.Msg // original query request (from the client)
	current  *dns.Msg // current query request (to be sent to the outside)

	// TODO: add direct graph

	timer *time.Timer // timer for resending the query
}

// ******************** Initialization Interface **********************

func NewQuestionTable(parent context.Context) *QuestionTable {
	ctx := context.WithoutCancel(parent)
	return &QuestionTable{
		ctx:  ctx,
		list: make(map[uint16]Question),
	}
}

// ******************** Resend Timer **********************

func (q *Question) resendTimer() {
	/* TODO: not implemented yet
	1. create a new goroutine
	2. wait for the timer to expire or the context to be canceled
	3. forward the query request to the outside
	*/
}

func (q *Question) restartTimer() {
	// TODO: not implemented yet
}

func (q *Question) stopTimer() {
	// TODO: not implemented yet
}

// ******************** Interface **********************

func (qt *QuestionTable) Add(msg *dns.Msg, port uint16) error {
	/* TODO: not implemented yet
	1. assign new transaction ID
	2. add the question to the table
	3. form a new query request and forward it to the outside sending queue
	4. start a timer for 1 second, if the timer expires, resend the query
	*/
	return nil
}

func (qt *QuestionTable) Get(transactionID uint16) (*Question, error) {
	/* TODO: not implemented yet
	1. find the question in the table
	2. remove the question from the table
	3. stop the timer
	4. return the question
	*/
	return nil, nil
}

func (qt *QuestionTable) Update(question *Question) error {
	/* TODO: not implemented yet
	1. add the question to the table
	2. send the query request to the outside
	3. restart the timer
	*/
	return nil
}

// ******************** Private Interface **********************

func (qt *QuestionTable) getNewTransactionID() uint16 {
	/* TODO: not implemented yet
	1. get random transaction ID
	2. check if the transaction ID is already in the table
	*/
	return 0
}
