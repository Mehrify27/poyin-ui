package service

import (
	"sync"
	"testing"
)

func TestParseXrayKeyPairRejectsMalformedOutput(t *testing.T) {
	priv, pub, err := parseXrayKeyPair("PrivateKey: abc123\nPassword: def456\n")
	if err != nil {
		t.Fatalf("valid key pair failed: %v", err)
	}
	if priv != "abc123" || pub != "def456" {
		t.Fatalf("got (%q, %q), want (%q, %q)", priv, pub, "abc123", "def456")
	}

	for _, bad := range []string{"", "single line only", "no-colon-first\nsecond: ok"} {
		if _, _, err := parseXrayKeyPair(bad); err == nil {
			t.Fatalf("expected parseXrayKeyPair(%q) to return error", bad)
		}
	}
}

func TestServerServiceCachedHostInfoConcurrentReads(t *testing.T) {
	svc := &ServerService{
		cachedIPv4: "127.0.0.1",
		cachedIPv6: "::1",
	}
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = svc.GetStatus(nil)
			}
		}()
	}
	wg.Wait()
}
