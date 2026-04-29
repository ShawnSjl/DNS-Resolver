package graph

type Resolver struct {
	Zone  string
	Stack []*Node
}

type Node struct {
	Name         string // domain name
	Type         uint16 // query type
	Class        uint16 // query class
	Children     []*Node
	ResolveState ResolveState
}

type ResolveState int

const (
	StateUnknown       ResolveState = iota
	StateHasAddress                 // already has A or AAAA record
	StateAddressNeeded              // no A or AAAA record, need to query
	StateZeroAnswer                 // the query returned no answer
	StateTimeout                    // the query timed out
)

// ******************** Initialization Interface **********************

func NewResolver(zone string) *Resolver {
	return &Resolver{
		Zone:  zone,
		Stack: []*Node{},
	}
}

// ******************** Public Interface **********************
