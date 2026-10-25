// Package keystash holds private keys for unmanaged certificates in memory only,
// long enough for the issuance to finish and the user to download them.
package keystash

import (
	"crypto"
	"sync"
	"time"
)

type entry struct {
	key     crypto.Signer
	expires time.Time
}

type Stash struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]entry
	now func() time.Time
}

func New(ttl time.Duration) *Stash {
	return &Stash{ttl: ttl, m: map[string]entry{}, now: time.Now}
}

func (s *Stash) Put(id string, key crypto.Signer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[id] = entry{key, s.now().Add(s.ttl)}
}

// Get returns the key and when it will be forgotten.
func (s *Stash) Get(id string) (crypto.Signer, time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[id]
	if !ok || s.now().After(e.expires) {
		delete(s.m, id)
		return nil, time.Time{}, false
	}
	return e.key, e.expires, true
}

func (s *Stash) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
}

// Sweep drops expired keys; call it periodically.
func (s *Stash) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, e := range s.m {
		if s.now().After(e.expires) {
			delete(s.m, id)
		}
	}
}
