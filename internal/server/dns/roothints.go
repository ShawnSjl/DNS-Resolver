package dns

import (
	"math"
	"net"

	"github.com/miekg/dns"
)

var rootHintsA = []dns.A{
	{Hdr: dns.RR_Header{Name: "a.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: math.MaxUint32}, A: net.ParseIP("198.41.0.4")},
	{Hdr: dns.RR_Header{Name: "b.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: math.MaxUint32}, A: net.ParseIP("170.247.170.2")},
	{Hdr: dns.RR_Header{Name: "c.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: math.MaxUint32}, A: net.ParseIP("192.33.4.12")},
	{Hdr: dns.RR_Header{Name: "d.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: math.MaxUint32}, A: net.ParseIP("199.7.91.13")},
	{Hdr: dns.RR_Header{Name: "e.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: math.MaxUint32}, A: net.ParseIP("192.203.230.10")},
	{Hdr: dns.RR_Header{Name: "f.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: math.MaxUint32}, A: net.ParseIP("192.5.5.241")},
	{Hdr: dns.RR_Header{Name: "g.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: math.MaxUint32}, A: net.ParseIP("192.112.36.4")},
	{Hdr: dns.RR_Header{Name: "h.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: math.MaxUint32}, A: net.ParseIP("198.97.190.53")},
	{Hdr: dns.RR_Header{Name: "i.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: math.MaxUint32}, A: net.ParseIP("192.36.148.17")},
	{Hdr: dns.RR_Header{Name: "j.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: math.MaxUint32}, A: net.ParseIP("192.58.128.30")},
	{Hdr: dns.RR_Header{Name: "k.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: math.MaxUint32}, A: net.ParseIP("193.0.14.129")},
	{Hdr: dns.RR_Header{Name: "l.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: math.MaxUint32}, A: net.ParseIP("199.7.83.42")},
	{Hdr: dns.RR_Header{Name: "m.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: math.MaxUint32}, A: net.ParseIP("202.12.27.33")},
}

var rootHintsAAAA = []dns.AAAA{
	{Hdr: dns.RR_Header{Name: "a.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: math.MaxUint32}, AAAA: net.ParseIP("2001:503:ba3e::2:30")},
	{Hdr: dns.RR_Header{Name: "b.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: math.MaxUint32}, AAAA: net.ParseIP("2801:1b8:10::b")},
	{Hdr: dns.RR_Header{Name: "c.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: math.MaxUint32}, AAAA: net.ParseIP("2001:500:2::c")},
	{Hdr: dns.RR_Header{Name: "d.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: math.MaxUint32}, AAAA: net.ParseIP("2001:500:2d::d")},
	{Hdr: dns.RR_Header{Name: "e.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: math.MaxUint32}, AAAA: net.ParseIP("2001:500:a8::e")},
	{Hdr: dns.RR_Header{Name: "f.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: math.MaxUint32}, AAAA: net.ParseIP("2001:500:2f::f")},
	{Hdr: dns.RR_Header{Name: "g.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: math.MaxUint32}, AAAA: net.ParseIP("2001:500:12::d0d")},
	{Hdr: dns.RR_Header{Name: "h.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: math.MaxUint32}, AAAA: net.ParseIP("2001:500:1::53")},
	{Hdr: dns.RR_Header{Name: "i.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: math.MaxUint32}, AAAA: net.ParseIP("2001:7fe::53")},
	{Hdr: dns.RR_Header{Name: "j.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: math.MaxUint32}, AAAA: net.ParseIP("2001:503:c27::2:30")},
	{Hdr: dns.RR_Header{Name: "k.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: math.MaxUint32}, AAAA: net.ParseIP("2001:7fd::1")},
	{Hdr: dns.RR_Header{Name: "l.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: math.MaxUint32}, AAAA: net.ParseIP("2001:500:9f::42")},
	{Hdr: dns.RR_Header{Name: "m.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: math.MaxUint32}, AAAA: net.ParseIP("2001:dc3::35")},
}

func (s *Server) loadRootHints() {
	for _, rr := range rootHintsA {
		s.cache.add(&rr)
	}
	for _, rr := range rootHintsAAAA {
		s.cache.add(&rr)
	}
}
