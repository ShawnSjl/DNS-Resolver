package blocklist

import (
	"sort"
	"strings"
	"sync"
)

type Blocklist struct {
	mu       sync.RWMutex
	patterns map[string]struct{}
}

func New(domains []string) *Blocklist {
	b := &Blocklist{patterns: make(map[string]struct{})}
	for _, domain := range domains {
		b.Add(domain)
	}
	return b
}

func (b *Blocklist) Add(domain string) {
	// Normalize once before storing.
	normalized := normalizePattern(domain)
	if normalized == "" {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.patterns[normalized] = struct{}{}
}

func (b *Blocklist) Remove(domain string) {
	normalized := normalizePattern(domain)
	if normalized == "" {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.patterns, normalized)
}

func (b *Blocklist) Contains(domain string) bool {
	// Queries may include the final DNS dot.
	name := normalizeName(domain)
	if name == "" {
		return false
	}

	b.mu.RLock()
	defer b.mu.RUnlock()
	for pattern := range b.patterns {
		if matches(pattern, name) {
			return true
		}
	}
	return false
}

func (b *Blocklist) List() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	out := make([]string, 0, len(b.patterns))
	for pattern := range b.patterns {
		out = append(out, pattern)
	}
	// Keep output stable for humans and tests.
	sort.Strings(out)
	return out
}

func normalizeName(domain string) string {
	// Drop case and the final DNS root dot.
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimSuffix(domain, ".")
	return domain
}

func normalizePattern(pattern string) string {
	return normalizeName(pattern)
}

func matches(pattern, domain string) bool {
	if pattern == domain {
		return true
	}
	// Wildcard blocks subdomains, not the bare domain.
	if strings.HasPrefix(pattern, "*.") {
		base := strings.TrimPrefix(pattern, "*.")
		return domain != base && strings.HasSuffix(domain, "."+base)
	}
	// Suffix rule still keeps the label boundary.
	if strings.HasPrefix(pattern, ".") {
		return strings.HasSuffix(domain, pattern)
	}
	return false
}
