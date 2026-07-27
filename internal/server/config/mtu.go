package config

const (
	MTU            = 1500
	UDPHeaderSize  = 8
	IPv4HeaderSize = 20
	IPv6HeaderSize = 40
	UDP4MTU        = MTU - IPv4HeaderSize - UDPHeaderSize
	UDP6MTU        = MTU - IPv6HeaderSize - UDPHeaderSize
)
