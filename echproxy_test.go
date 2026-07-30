package echproxy

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPublicECHCacheRoundTripAndExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache", "ech.json")
	config := []byte{1, 2, 3, 4}
	storePublicECHCache(path, "archiveofourown.org", config)
	got, ok := loadPublicECHCache(path, "ARCHIVEOFOUROWN.ORG")
	if !ok || string(got) != string(config) {
		t.Fatalf("cache = %x, %v; want %x, true", got, ok, config)
	}
	data, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	if string(data) == string(config) { t.Fatal("cache must encode the public config rather than write raw bytes") }
	if err := os.WriteFile(path, []byte(`{"host":"archiveofourown.org","config_b64":"`+base64.StdEncoding.EncodeToString(config)+`","expires_at":`+"1"+`}`), 0600); err != nil { t.Fatal(err) }
	if _, ok := loadPublicECHCache(path, "archiveofourown.org"); ok { t.Fatal("expired cache was accepted") }
}

func TestPublicECHCacheRejectsWrongHostAndMalformedData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ech.json")
	storePublicECHCache(path, "archiveofourown.org", []byte{1})
	if _, ok := loadPublicECHCache(path, "example.org"); ok { t.Fatal("cache accepted another host") }
	if err := os.WriteFile(path, []byte("not json"), 0600); err != nil { t.Fatal(err) }
	if _, ok := loadPublicECHCache(path, "archiveofourown.org"); ok { t.Fatal("malformed cache was accepted") }
}

func TestTargetHostValidation(t *testing.T) {
	for _, host := range []string{"archiveofourown.org", "www.archiveofourown.org", "api-1.example.org"} {
		if !isTargetHost(host) { t.Errorf("valid host rejected: %q", host) }
	}
	for _, host := range []string{"", "archiveofourown.org:443", "https://archiveofourown.org", "127.0.0.1", "[::1]", "-bad.example", "bad_.example", "user@host"} {
		if isTargetHost(host) { t.Errorf("invalid host accepted: %q", host) }
	}
}

func TestPublicECHCacheTTLIsBounded(t *testing.T) {
	if publicECHCacheTTL <= 0 || publicECHCacheTTL > 24*time.Hour { t.Fatalf("unexpected cache ttl: %s", publicECHCacheTTL) }
}

func TestCloudflareAS13335CIDRs(t *testing.T) {
	for _, ip := range []string{"104.18.47.94", "162.159.27.168", "172.64.144.100", "2606:4700::1111"} {
		if !isCloudflareAS13335(ip) {
			t.Errorf("AS13335 address rejected: %s", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "not-an-ip"} {
		if isCloudflareAS13335(ip) {
			t.Errorf("non-AS13335 address accepted: %s", ip)
		}
	}
}

func TestAllCloudflareAS13335(t *testing.T) {
	if !allCloudflareAS13335([]string{"104.18.47.94", "162.159.27.168"}) {
		t.Fatal("all Cloudflare AS13335 addresses should qualify")
	}
	if allCloudflareAS13335([]string{"104.18.47.94", "8.8.8.8"}) {
		t.Fatal("mixed address set must not qualify")
	}
	if allCloudflareAS13335(nil) {
		t.Fatal("empty address set must not qualify")
	}
}

func TestEchPolicyIsSeparatedFromDirectDoH(t *testing.T) {
	if HasECH("", "archiveofourown.org") {
		t.Fatal("missing DoH endpoint must not claim ECH support")
	}
	if _, err := Resolve("", "archiveofourown.org"); err == nil {
		t.Fatal("Resolve must not fall back to system DNS")
	}
	if _, err := Resolve("https://example.invalid/dns-query", "bad_.example"); err == nil {
		t.Fatal("Resolve accepted an invalid host")
	}
}
