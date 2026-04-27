package dns

import (
	"fmt"
	"strings"
	"sync"
)

type Blacklist struct {
	domains map[string]struct{} // domains in the blacklist, use map for O(1) lookup
	mutex   sync.RWMutex
}

// ******************** Initialization Interface **********************

func NewBlacklist() *Blacklist {
	return &Blacklist{
		domains: make(map[string]struct{}),
		mutex:   sync.RWMutex{},
	}
}

// ******************** Interface **********************

func (b *Blacklist) Add(domain string) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	b.domains[domain] = struct{}{}
}

func (b *Blacklist) Contains(domain string) bool {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	_, ok := b.domains[domain]
	return ok
}

func (b *Blacklist) Remove(domain string) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	delete(b.domains, domain)
}

func (b *Blacklist) List() string {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	var list []string
	list = append(list, "Idx  Domain")

	// Get list of domains
	var index int
	for domain := range b.domains {
		list = append(list, fmt.Sprintf("%3d: %10s", index, domain))
		index++
	}

	return strings.Join(list, "\n")
}
