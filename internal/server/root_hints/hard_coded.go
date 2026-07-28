package root_hints

import (
	"net"
	"time"

	"github.com/miekg/dns"
)

var hardCodedTime = time.Date(2026, time.July, 4, 0, 0, 0, 0, time.UTC)

var rootHintsNS = []dns.NS{
	{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: rootTTL}, Ns: "a.root-servers.net."},
	{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: rootTTL}, Ns: "b.root-servers.net."},
	{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: rootTTL}, Ns: "c.root-servers.net."},
	{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: rootTTL}, Ns: "d.root-servers.net."},
	{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: rootTTL}, Ns: "e.root-servers.net."},
	{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: rootTTL}, Ns: "f.root-servers.net."},
	{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: rootTTL}, Ns: "g.root-servers.net."},
	{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: rootTTL}, Ns: "h.root-servers.net."},
	{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: rootTTL}, Ns: "i.root-servers.net."},
	{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: rootTTL}, Ns: "j.root-servers.net."},
	{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: rootTTL}, Ns: "k.root-servers.net."},
	{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: rootTTL}, Ns: "l.root-servers.net."},
	{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: rootTTL}, Ns: "m.root-servers.net."},
}

var rootHintsA = []dns.A{
	{Hdr: dns.RR_Header{Name: "a.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rootTTL}, A: net.ParseIP("198.41.0.4")},
	{Hdr: dns.RR_Header{Name: "b.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rootTTL}, A: net.ParseIP("170.247.170.2")},
	{Hdr: dns.RR_Header{Name: "c.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rootTTL}, A: net.ParseIP("192.33.4.12")},
	{Hdr: dns.RR_Header{Name: "d.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rootTTL}, A: net.ParseIP("199.7.91.13")},
	{Hdr: dns.RR_Header{Name: "e.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rootTTL}, A: net.ParseIP("192.203.230.10")},
	{Hdr: dns.RR_Header{Name: "f.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rootTTL}, A: net.ParseIP("192.5.5.241")},
	{Hdr: dns.RR_Header{Name: "g.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rootTTL}, A: net.ParseIP("192.112.36.4")},
	{Hdr: dns.RR_Header{Name: "h.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rootTTL}, A: net.ParseIP("198.97.190.53")},
	{Hdr: dns.RR_Header{Name: "i.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rootTTL}, A: net.ParseIP("192.36.148.17")},
	{Hdr: dns.RR_Header{Name: "j.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rootTTL}, A: net.ParseIP("192.58.128.30")},
	{Hdr: dns.RR_Header{Name: "k.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rootTTL}, A: net.ParseIP("193.0.14.129")},
	{Hdr: dns.RR_Header{Name: "l.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rootTTL}, A: net.ParseIP("199.7.83.42")},
	{Hdr: dns.RR_Header{Name: "m.root-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rootTTL}, A: net.ParseIP("202.12.27.33")},
}

var rootHintsAAAA = []dns.AAAA{
	{Hdr: dns.RR_Header{Name: "a.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rootTTL}, AAAA: net.ParseIP("2001:503:ba3e::2:30")},
	{Hdr: dns.RR_Header{Name: "b.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rootTTL}, AAAA: net.ParseIP("2801:1b8:10::b")},
	{Hdr: dns.RR_Header{Name: "c.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rootTTL}, AAAA: net.ParseIP("2001:500:2::c")},
	{Hdr: dns.RR_Header{Name: "d.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rootTTL}, AAAA: net.ParseIP("2001:500:2d::d")},
	{Hdr: dns.RR_Header{Name: "e.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rootTTL}, AAAA: net.ParseIP("2001:500:a8::e")},
	{Hdr: dns.RR_Header{Name: "f.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rootTTL}, AAAA: net.ParseIP("2001:500:2f::f")},
	{Hdr: dns.RR_Header{Name: "g.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rootTTL}, AAAA: net.ParseIP("2001:500:12::d0d")},
	{Hdr: dns.RR_Header{Name: "h.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rootTTL}, AAAA: net.ParseIP("2001:500:1::53")},
	{Hdr: dns.RR_Header{Name: "i.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rootTTL}, AAAA: net.ParseIP("2001:7fe::53")},
	{Hdr: dns.RR_Header{Name: "j.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rootTTL}, AAAA: net.ParseIP("2001:503:c27::2:30")},
	{Hdr: dns.RR_Header{Name: "k.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rootTTL}, AAAA: net.ParseIP("2001:7fd::1")},
	{Hdr: dns.RR_Header{Name: "l.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rootTTL}, AAAA: net.ParseIP("2001:500:9f::42")},
	{Hdr: dns.RR_Header{Name: "m.root-servers.net.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rootTTL}, AAAA: net.ParseIP("2001:dc3::35")},
}

func getHardCodedRootHints() (ns []dns.RR, a []dns.RR, aaaa []dns.RR, time time.Time) {
	return nsToRRSlice(rootHintsNS), aToRRSlice(rootHintsA), aaaaToRRSlice(rootHintsAAAA), hardCodedTime
}

func nsToRRSlice(nsList []dns.NS) []dns.RR {
	rrList := make([]dns.RR, len(nsList))
	for i := range nsList {
		rrList[i] = &nsList[i]
	}
	return rrList
}

func aToRRSlice(aList []dns.A) []dns.RR {
	rrList := make([]dns.RR, len(aList))
	for i := range aList {
		rrList[i] = &aList[i]
	}
	return rrList
}

func aaaaToRRSlice(aaaaList []dns.AAAA) []dns.RR {
	rrList := make([]dns.RR, len(aaaaList))
	for i := range aaaaList {
		rrList[i] = &aaaaList[i]
	}
	return rrList
}
