package cache

import (
	"fmt"

	"github.com/miekg/dns"
)

// Record is a DNS resource record.
type Record struct {
	Name    dns.Name
	Type    dns.Type
	Class   dns.Class
	TTL     uint32
	DataLen uint16
	Address string
}

// ******************** Interface **********************

func (r *Record) String() string {
	return fmt.Sprintf("%5s %6s %2s %6d %10s",
		r.Name.String(),
		r.Type.String(),
		r.Class.String(),
		r.TTL,
		r.Address,
	)
}
