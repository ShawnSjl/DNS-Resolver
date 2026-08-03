package rr_cache

type nameKey struct {
	domain string
	qClass uint16
}

type setKey struct {
	domain string
	qType  uint16
	qClass uint16
}
