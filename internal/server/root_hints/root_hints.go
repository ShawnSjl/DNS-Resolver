package root_hints

import (
	"context"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

const rootHintsURL = "https://www.internic.net/domain/named.root"
const rootTTL = math.MaxUint32

func FetchRootHints(ctx context.Context) (ns []dns.RR, a []dns.RR, aaaa []dns.RR, err error) {
	// set timeout for request
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// create request
	req, reqErr := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		rootHintsURL,
		nil,
	)
	if reqErr != nil {
		return nil, nil, nil, reqErr
	}

	// send request and get response
	resp, respErr := http.DefaultClient.Do(req)
	if respErr != nil {
		return nil, nil, nil, respErr
	}
	defer func(Body io.ReadCloser) {
		if closeErr := Body.Close(); closeErr != nil {
			log.Printf("Fail to close root hints response body: %s\n", closeErr)
		}
	}(resp.Body)

	// check response status
	if resp.StatusCode != http.StatusOK {
		return nil, nil, nil, fmt.Errorf("fetch root hints failed: %s", resp.Status)
	}

	// create zone parser
	zp := dns.NewZoneParser(resp.Body, ".", "")

	// parse zone
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		rr.Header().Ttl = rootTTL // set TTL to max
		switch rr.Header().Rrtype {
		case dns.TypeNS:
			ns = append(ns, rr)
		case dns.TypeA:

			a = append(a, rr)
		case dns.TypeAAAA:
			aaaa = append(aaaa, rr)
		}
	}

	// return error if failed to parse
	if err = zp.Err(); err != nil {
		return nil, nil, nil, err
	}
	if len(ns) == 0 || len(a) == 0 || len(aaaa) == 0 {
		return nil, nil, nil, fmt.Errorf("no root hints found")
	}

	// return result
	return ns, a, aaaa, nil
}
