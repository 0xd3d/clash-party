package resolver

import (
	"context"
	"net/netip"
	"testing"

	"github.com/Dreamacro/clash/component/trie"
)

func TestIOSProxyEndpointDNSDoesNotFallBack(t *testing.T) {
	oldStrict, oldProxy, oldHosts, oldIPv6 := RequireEncryptedProxyServerDNS, ProxyServerHostResolver, DefaultHosts, DisableIPv6
	defer func() {
		RequireEncryptedProxyServerDNS = oldStrict
		ProxyServerHostResolver = oldProxy
		DefaultHosts = oldHosts
		DisableIPv6 = oldIPv6
	}()
	RequireEncryptedProxyServerDNS = true
	DefaultHosts = NewHosts(trie.New[HostValue]())
	DisableIPv6 = false
	for _, test := range []struct {
		name  string
		proxy Resolver
	}{
		{"missing", nil},
		{"failure", staticProxyServerResolver{err: ErrIPNotFound}},
		{"empty", staticProxyServerResolver{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ProxyServerHostResolver = test.proxy
			defaultCalls := 0
			for _, lookup := range []func(context.Context, string, Resolver) ([]netip.Addr, error){LookupIPWithResolver, LookupIPv4WithResolver, LookupIPv6WithResolver} {
				ips, err := lookupProxyServerHost(context.Background(), "unused-node.example.org", lookup, func(context.Context, string) ([]netip.Addr, error) {
					defaultCalls++
					return []netip.Addr{netip.MustParseAddr("192.0.2.9")}, nil
				})
				if err == nil || len(ips) != 0 || defaultCalls != 0 {
					t.Fatalf("unsafe fallback: ips=%v err=%v defaultCalls=%d", ips, err, defaultCalls)
				}
			}
		})
	}
	ProxyServerHostResolver = nil
	for _, literal := range []string{"198.51.100.10", "2001:db8::10"} {
		ips, err := LookupIPProxyServerHost(context.Background(), literal)
		if err != nil || len(ips) != 1 || ips[0].String() != literal {
			t.Fatalf("literal endpoint must not require DNS: %v %v", ips, err)
		}
	}
	value, _ := NewHostValueByIPs([]netip.Addr{netip.MustParseAddr("192.0.2.10")})
	if err := DefaultHosts.Insert("pinned-node.example.org", value); err != nil {
		t.Fatal(err)
	}
	ips, err := LookupIPv4ProxyServerHost(context.Background(), "pinned-node.example.org")
	if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.10" {
		t.Fatalf("static endpoint was lost: %v %v", ips, err)
	}
}
