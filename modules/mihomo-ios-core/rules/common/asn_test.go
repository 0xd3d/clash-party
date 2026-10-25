package common

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/Dreamacro/clash/component/mmdb"
	C "github.com/Dreamacro/clash/constant"
)

func TestNewIPASNAcceptsNumericAndPrefixedPayload(t *testing.T) {
	tests := []string{"15169", "AS15169", "as15169"}
	for _, tt := range tests {
		rule, err := NewIPASN(tt, "PROXY", true)
		if err != nil {
			t.Fatalf("expected %q to parse as IP-ASN payload: %v", tt, err)
		}
		if rule.Payload() != "15169" {
			t.Fatalf("expected payload to normalize to 15169, got %q", rule.Payload())
		}
		if rule.ShouldResolveIP() {
			t.Fatal("expected IP-ASN rule to rely on existing IP metadata instead of requesting DNS resolution")
		}
	}
}

func TestNewIPASNRejectsInvalidPayload(t *testing.T) {
	for _, tt := range []string{"", "AS", "google", "0"} {
		if _, err := NewIPASN(tt, "PROXY", false); err == nil {
			t.Fatalf("expected invalid IP-ASN payload %q to fail", tt)
		}
	}
}

func TestIPASNMatchMissingASNMMDBNoMatch(t *testing.T) {
	originalHomeDir := C.Path.HomeDir()
	originalGOOS := ipASNGOOS
	t.Cleanup(func() {
		C.SetHomeDir(originalHomeDir)
		mmdb.ClearASNCache()
		ipASNGOOS = originalGOOS
	})

	homeDir := filepath.Join(t.TempDir(), "mihomo-home")
	if err := os.MkdirAll(homeDir, 0o755); err != nil {
		t.Fatalf("mkdir temp home: %v", err)
	}
	C.SetHomeDir(homeDir)
	ipASNGOOS = "darwin"

	rule := &IPASN{
		Base:    &Base{},
		asn:     15169,
		adapter: "PROXY",
	}
	matched, adapter := rule.Match(&C.Metadata{DstIP: netip.MustParseAddr("8.8.8.8")})
	if matched || adapter != "" {
		t.Fatalf("expected missing ASN MMDB to no-match, got matched=%v adapter=%q", matched, adapter)
	}
}

func TestIPASNMatchSkipsColdASNLookupOnIOSTunHotPath(t *testing.T) {
	originalHomeDir := C.Path.HomeDir()
	originalGOOS := ipASNGOOS
	t.Cleanup(func() {
		C.SetHomeDir(originalHomeDir)
		mmdb.ClearASNCache()
		ipASNGOOS = originalGOOS
	})

	homeDir := filepath.Join(t.TempDir(), "mihomo-home")
	if err := os.MkdirAll(homeDir, 0o755); err != nil {
		t.Fatalf("mkdir temp home: %v", err)
	}
	C.SetHomeDir(homeDir)
	ipASNGOOS = "ios"
	mmdb.ClearASNCache()

	rule := &IPASN{
		Base:    &Base{},
		asn:     15169,
		adapter: "PROXY",
	}
	metadata := &C.Metadata{
		Type:  C.TUN,
		DstIP: netip.MustParseAddr("8.8.8.8"),
	}

	matched, adapter := rule.Match(metadata)
	if matched || adapter != "" {
		t.Fatalf("expected cold iOS TUN ASN lookup to no-match, got matched=%v adapter=%q", matched, adapter)
	}
	if !metadata.DstASNFailed {
		t.Fatal("expected metadata to remember that cold ASN lookup was skipped for this connection")
	}
}

func TestIPASNMatchSkipsPrivateAddresses(t *testing.T) {
	rule := &IPASN{
		Base:    &Base{},
		asn:     15169,
		adapter: "PROXY",
	}
	metadata := &C.Metadata{
		DstIP: netip.MustParseAddr("172.31.255.2"),
	}

	matched, adapter := rule.Match(metadata)
	if matched || adapter != "" {
		t.Fatalf("expected private-range ASN lookup to no-match, got matched=%v adapter=%q", matched, adapter)
	}
	if !metadata.DstASNFailed {
		t.Fatal("expected private-range ASN lookup to be short-circuited")
	}
}

func TestIPASNMatchUsesConnectionASNCache(t *testing.T) {
	rule := &IPASN{
		Base:    &Base{},
		asn:     15169,
		adapter: "PROXY",
	}
	metadata := &C.Metadata{
		DstIP:       netip.MustParseAddr("8.8.8.8"),
		DstASN:      15169,
		DstASNReady: true,
	}

	matched, adapter := rule.Match(metadata)
	if !matched || adapter != "PROXY" {
		t.Fatalf("expected cached ASN to match without opening MMDB, got matched=%v adapter=%q", matched, adapter)
	}

	secondRule := &IPASN{
		Base:    &Base{},
		asn:     8075,
		adapter: "PROXY",
	}
	matched, adapter = secondRule.Match(metadata)
	if matched || adapter != "PROXY" {
		t.Fatalf("expected cached ASN mismatch without overwriting adapter, got matched=%v adapter=%q", matched, adapter)
	}
}
