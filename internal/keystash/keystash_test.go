package keystash

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

func TestExpiry(t *testing.T) {
	now := time.Now()
	s := New(time.Minute)
	s.now = func() time.Time { return now }
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s.Put("a", k)
	if _, _, ok := s.Get("a"); !ok {
		t.Fatal("missing key")
	}
	now = now.Add(2 * time.Minute)
	if _, _, ok := s.Get("a"); ok {
		t.Fatal("expired key returned")
	}
}
