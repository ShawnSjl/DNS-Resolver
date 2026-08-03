package rr_cache

import (
	"context"
	"io"
	"log/slog"
	"math"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCache_AddRR(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache := NewCache(ctx, logger)

	var fakeRR = dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A: net.ParseIP("0.0.0.0")}

	// Add a RR
	if ok := cache.AddRR(&fakeRR, false); !ok {
		t.Error("Failed to add RR")
	}

	// Wait 1 second
	timer := time.Tick(1 * time.Second)
	<-timer

	wSet, ok := cache.GetWeightedRRSet("example.com.", dns.TypeA, dns.ClassINET)
	if !ok {
		t.Error("Cache miss")
	}

	wRR, ok := wSet.rrs[rrDataKey(&fakeRR)]
	if !ok {
		t.Error("RR not found in cache")
	}

	if wRR.rr.Header().Ttl >= 300 {
		t.Error("TTL incorrect")
	}

	print(wRR.rr.String())
}

func TestCache_AddRR_LimitTTL(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache := NewCache(ctx, logger)

	var fakeRR = dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: math.MaxUint32},
		A: net.ParseIP("0.0.0.0")}
	var fakeRR2 = dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET,
		Ttl: math.MaxUint32},
		A: net.ParseIP("0.0.0.1")}

	// Add a RR
	if ok := cache.AddRR(&fakeRR, true); !ok {
		t.Error("Failed to add RR")
	}
	if ok := cache.AddRR(&fakeRR2, false); !ok {
		t.Error("Failed to add RR")
	}

	wSet, ok := cache.GetWeightedRRSet("example.com.", dns.TypeA, dns.ClassINET)
	if !ok {
		t.Error("Cache miss")
	}

	// RR1 should not be limited
	wRR1, ok := wSet.rrs[rrDataKey(&fakeRR)]
	if !ok {
		t.Error("RR not found in cache")
	}
	if wRR1.rr.Header().Ttl > 60*60*24*7 {
		t.Error("TTL not limit")
	}

	// RR2 should be limited to 7 days
	wRR2, ok := wSet.rrs[rrDataKey(&fakeRR2)]
	if !ok {
		t.Error("RR not found in cache")
	}
	if wRR2.rr.Header().Ttl <= 60*60*24*7 {
		t.Error("TTL limited")
	}
}

func TestCache_AddRR_TTL_Zero(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache := NewCache(ctx, logger)

	var fakeRR = dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
		A: net.ParseIP("0.0.0.0")}

	// Add a RR
	if ok := cache.AddRR(&fakeRR, true); !ok {
		t.Error("Failed to add RR")
	}

	// Wait 1 second
	timer := time.Tick(2 * time.Second)
	<-timer

	_, ok := cache.GetWeightedRRSet("example.com.", dns.TypeA, dns.ClassINET)
	if ok {
		t.Error("RR set should be expired, but not")
	}
}

func TestCache_PicksCorrectRR(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache := NewCache(ctx, logger)

	var fakeRR = dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A: net.ParseIP("0.0.0.0")}
	var fakeRR2 = dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A: net.ParseIP("0.0.0.1")}

	// Add a RR
	if ok := cache.AddRR(&fakeRR, true); !ok {
		t.Error("Failed to add RR")
	}
	if ok := cache.AddRR(&fakeRR2, true); !ok {
		t.Error("Failed to add RR")
	}

	wSet, ok := cache.GetWeightedRRSet("example.com.", dns.TypeA, dns.ClassINET)
	if !ok {
		t.Error("Cache miss")
	}

	// Pick an RR
	wRR, ok := wSet.Pick()
	if !ok {
		t.Error("RR not found in cache")
	}

	// Report a failure
	wSet.ReportRTT(wRR, false, 1000*time.Millisecond)

	// Pick an RR, should be different
	wRR2, ok := wSet.Pick()
	if !ok {
		t.Error("RR not found in cache")
	}
	if wRR == wRR2 {
		t.Error("RRs should not be the same")
	}
}

func TestCache_CNAME_1(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()
	cache := NewCache(ctx, logger)

	var fakeRR = dns.A{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A: net.ParseIP("0.0.0.0")}
	var fakeCNAME = dns.CNAME{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET,
		Ttl: 300}, Target: "example.com."}

	// Add a RR
	if ok := cache.AddRR(&fakeRR, true); !ok {
		t.Error("Failed to add RR")
	}
	if ok := cache.AddRR(&fakeCNAME, true); ok {
		t.Error("CNAME should not be added to cache")
	}
}

func TestCache_CNAME_2(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()
	cache := NewCache(ctx, logger)

	var fakeRR = dns.A{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A: net.ParseIP("0.0.0.0")}
	var fakeCNAME = dns.CNAME{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET,
		Ttl: 300}, Target: "example.com."}

	// Add a RR
	if ok := cache.AddRR(&fakeCNAME, true); !ok {
		t.Error("Failed to add CNAME")
	}
	if ok := cache.AddRR(&fakeRR, true); ok {
		t.Error("RR should not be added to cache")
	}
}

func TestCache_CNAME_3(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()
	cache := NewCache(ctx, logger)

	var fakeCNAME = dns.CNAME{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET,
		Ttl: 300}, Target: "example.com."}
	var fakeCNAME2 = dns.CNAME{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET,
		Ttl: 300}, Target: "example.com."}

	// Add a RR
	if ok := cache.AddRR(&fakeCNAME, true); !ok {
		t.Error("Failed to add CNAME")
	}
	if ok := cache.AddRR(&fakeCNAME2, true); !ok {
		t.Error("Failed to add CNAME")
	}
}

func TestCache_CNAME_4(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()
	cache := NewCache(ctx, logger)

	var fakeRR = dns.A{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
		A: net.ParseIP("0.0.0.0")}
	var fakeCNAME = dns.CNAME{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET,
		Ttl: 1}, Target: "example.com."}

	// Add a RR
	if ok := cache.AddRR(&fakeRR, true); !ok {
		t.Error("Failed to add RR")
	}

	// Wait 2 seconds
	timer := time.Tick(2 * time.Second)
	<-timer

	// Add a CNAME when RR is expired
	if ok := cache.AddRR(&fakeCNAME, true); !ok {
		t.Error("Failed to add CNAME")
	}

	// Wait 2 seconds
	timer = time.Tick(2 * time.Second)
	<-timer

	// Add a RR when CNAME is expired
	if ok := cache.AddRR(&fakeRR, true); !ok {
		t.Error("Failed to add RR")
	}
}
