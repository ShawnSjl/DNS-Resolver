package rr_cache

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultRtt          = 100 * time.Millisecond
	rttAlpha            = 0.125
	rttBeta             = 0.25
	failurePenalty      = 30 * time.Second
	recentFailureFactor = 0.2
	minWeight           = 0.01
)

type WeightedRRSet struct {
	mutex sync.RWMutex

	rrs map[string]*weightedRR
}

type weightedRR struct {
	rr dns.RR

	// RTT stats
	sRtt   time.Duration // smoothed round trip time
	rttvar time.Duration

	accessCnt   uint64
	successCnt  uint64
	failureCnt  uint64
	lastAccess  time.Time
	lastFailure time.Time
}

func (wSet *WeightedRRSet) addRR(rr dns.RR) {
	wSet.mutex.Lock()
	defer wSet.mutex.Unlock()

	wSet.rrs[rrDataKey(rr)] = &weightedRR{
		rr:     rr,
		sRtt:   defaultRtt,
		rttvar: defaultRtt / 2,
	}
}

func rrDataKey(rr dns.RR) string {
	switch r := rr.(type) {
	case *dns.A:
		return r.A.String()
	case *dns.AAAA:
		return r.AAAA.String()
	case *dns.NS:
		return dns.Fqdn(strings.ToLower(r.Ns))
	case *dns.CNAME:
		return dns.Fqdn(strings.ToLower(r.Target))
	case *dns.MX:
		return fmt.Sprintf("%s %d", dns.Fqdn(strings.ToLower(r.Mx)), r.Preference)
	default:
		return rr.String()
	}
}

func (wSet *WeightedRRSet) RRs() []dns.RR {
	wSet.mutex.RLock()
	defer wSet.mutex.RUnlock()

	rrs := make([]dns.RR, 0, len(wSet.rrs))
	for _, wRR := range wSet.rrs {
		rrCopy := dns.Copy(wRR.rr)
		rrCopy.Header().Ttl = min(rrCopy.Header().Ttl, MaxTTL)
		rrs = append(rrs, rrCopy)
	}

	return rrs
}

func (wSet *WeightedRRSet) Pick() (dns.RR, bool) {
	wSet.mutex.Lock()
	defer wSet.mutex.Unlock()

	// If the RRSet is empty, return nil
	if len(wSet.rrs) == 0 {
		return nil, false
	}

	now := time.Now()

	// Calculate the total weight of all RRs in the RRSet
	totalWeight := 0.0
	for _, wRR := range wSet.rrs {
		totalWeight += wRR.weight(now)
	}

	if totalWeight <= 0 {
		return nil, false
	}

	target := rand.Float64() * totalWeight

	for _, wRR := range wSet.rrs {
		target -= wRR.weight(now)
		if target <= 0 {
			wRR.accessCnt++
			wRR.lastAccess = now
			return wRR.rr, true
		}
	}

	for _, wRR := range wSet.rrs {
		wRR.accessCnt++
		wRR.lastAccess = now
		return wRR.rr, true
	}

	return nil, false
}

func (wRR *weightedRR) weight(now time.Time) float64 {
	// Get the RTT score, lower sRtt is better
	rttScore := float64(defaultRtt) / float64(wRR.sRtt)

	// Get the success rate
	successRate := float64(wRR.successCnt+1) / float64(wRR.successCnt+wRR.failureCnt+2)

	// Get the failure factor, if the last failure happened recently, use a lower factor
	failureFactor := 1.0
	if !wRR.lastFailure.IsZero() && now.Sub(wRR.lastFailure) < failurePenalty {
		failureFactor = recentFailureFactor
	}

	// Get the access factor
	accessFactor := 1.0 / (1.0 + 0.02*float64(wRR.accessCnt))

	weight := rttScore * successRate * failureFactor * (0.8 + 0.2*accessFactor)
	return max(weight, minWeight)
}

func (wSet *WeightedRRSet) ReportRTT(rr dns.RR, success bool, rtt time.Duration) {
	wSet.mutex.Lock()
	defer wSet.mutex.Unlock()

	// Get that RR from the RRSet
	wRR, ok := wSet.rrs[rrDataKey(rr)]
	if !ok {
		return
	}

	// Update RRSet stats
	if success {
		wRR.successCnt++
	} else {
		wRR.failureCnt++
		wRR.lastFailure = time.Now()
	}
	wRR.updateRTTStats(rtt)
}

func (wRR *weightedRR) updateRTTStats(rtt time.Duration) {
	if rtt < 0 {
		return
	}

	diff := wRR.sRtt - rtt
	if diff < 0 {
		diff = -diff
	}

	// update the variance
	wRR.rttvar = time.Duration(rttBeta*float64(diff) + (1-rttBeta)*float64(wRR.rttvar))

	// update the smoothed RTT
	wRR.sRtt = time.Duration(rttAlpha*float64(rtt) + (1-rttAlpha)*float64(wRR.sRtt))
}
