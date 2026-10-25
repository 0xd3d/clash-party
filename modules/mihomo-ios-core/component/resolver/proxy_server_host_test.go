package resolver

import (
	"context"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

type staticProxyServerResolver struct {
	ips []netip.Addr
	err error
}

func (s staticProxyServerResolver) ExchangeContext(context.Context, *dns.Msg) (*dns.Msg, error) {
	return nil, nil
}

func (s staticProxyServerResolver) ResolveIP(context.Context, string) (netip.Addr, error) {
	if s.err != nil {
		return netip.Addr{}, s.err
	}
	if len(s.ips) == 0 {
		return netip.Addr{}, ErrIPNotFound
	}
	return s.ips[0], nil
}

func (s staticProxyServerResolver) ResolveIPv4(context.Context, string) (netip.Addr, error) {
	return s.ResolveIP(context.Background(), "")
}

func (s staticProxyServerResolver) ResolveIPv6(context.Context, string) (netip.Addr, error) {
	return s.ResolveIP(context.Background(), "")
}

func (s staticProxyServerResolver) LookupIP(context.Context, string) ([]netip.Addr, error) {
	if s.err != nil {
		return nil, s.err
	}
	return append([]netip.Addr(nil), s.ips...), nil
}

func (s staticProxyServerResolver) LookupIPv4(context.Context, string) ([]netip.Addr, error) {
	return s.LookupIP(context.Background(), "")
}

func (s staticProxyServerResolver) LookupIPv6(context.Context, string) ([]netip.Addr, error) {
	return s.LookupIP(context.Background(), "")
}

type fakeIPOnlyMapper struct {
	fake netip.Addr
}

func (m fakeIPOnlyMapper) FakeIPEnabled() bool                    { return true }
func (m fakeIPOnlyMapper) MappingEnabled() bool                   { return true }
func (m fakeIPOnlyMapper) IsFakeIP(ip netip.Addr) bool            { return ip == m.fake }
func (m fakeIPOnlyMapper) IsFakeBroadcastIP(netip.Addr) bool      { return false }
func (m fakeIPOnlyMapper) IsExistFakeIP(ip netip.Addr) bool       { return ip == m.fake }
func (m fakeIPOnlyMapper) FindHostByIP(netip.Addr) (string, bool) { return "", false }
func (m fakeIPOnlyMapper) FlushFakeIP() error                     { return nil }
func (m fakeIPOnlyMapper) InsertHostByIP(netip.Addr, string)      {}
func (m fakeIPOnlyMapper) StoreFakePoolState()                    {}

type fakeRangeMapper struct {
	prefix   netip.Prefix
	existing map[netip.Addr]struct{}
}

func (m fakeRangeMapper) FakeIPEnabled() bool               { return true }
func (m fakeRangeMapper) MappingEnabled() bool              { return true }
func (m fakeRangeMapper) IsFakeIP(ip netip.Addr) bool       { return m.prefix.Contains(ip) }
func (m fakeRangeMapper) IsFakeBroadcastIP(netip.Addr) bool { return false }
func (m fakeRangeMapper) IsExistFakeIP(ip netip.Addr) bool {
	_, ok := m.existing[ip]
	return ok
}
func (m fakeRangeMapper) FindHostByIP(netip.Addr) (string, bool) { return "", false }
func (m fakeRangeMapper) FlushFakeIP() error                     { return nil }
func (m fakeRangeMapper) InsertHostByIP(netip.Addr, string)      {}
func (m fakeRangeMapper) StoreFakePoolState()                    {}

func TestLookupIPProxyServerHostRejectsFakeIPAnswers(t *testing.T) {
	oldProxyResolver := ProxyServerHostResolver
	oldDefaultResolver := DefaultResolver
	oldMapper := DefaultHostMapper
	defer func() {
		ProxyServerHostResolver = oldProxyResolver
		DefaultResolver = oldDefaultResolver
		DefaultHostMapper = oldMapper
	}()

	fakeIP := netip.MustParseAddr("198.18.0.6")
	ProxyServerHostResolver = staticProxyServerResolver{ips: []netip.Addr{fakeIP}}
	DefaultResolver = staticProxyServerResolver{err: ErrIPNotFound}
	DefaultHostMapper = fakeIPOnlyMapper{fake: fakeIP}

	ips, err := LookupIPProxyServerHost(context.Background(), "proxy.example.test")
	if err == nil {
		t.Fatalf("expected fake proxy-server DNS answers to be rejected, got ips=%v", ips)
	}
	if len(ips) != 0 {
		t.Fatalf("expected fake proxy-server DNS answers to be removed, got %v", ips)
	}
}

func TestLookupIPProxyServerHostKeepsUnallocatedAddressInsideFakeRange(t *testing.T) {
	oldProxyResolver := ProxyServerHostResolver
	oldDefaultResolver := DefaultResolver
	oldMapper := DefaultHostMapper
	defer func() {
		ProxyServerHostResolver = oldProxyResolver
		DefaultResolver = oldDefaultResolver
		DefaultHostMapper = oldMapper
	}()

	realIPInsideFakeRange := netip.MustParseAddr("198.18.28.14")
	ProxyServerHostResolver = staticProxyServerResolver{ips: []netip.Addr{realIPInsideFakeRange}}
	DefaultResolver = staticProxyServerResolver{err: ErrIPNotFound}
	DefaultHostMapper = fakeRangeMapper{
		prefix:   netip.MustParsePrefix("198.18.0.0/16"),
		existing: map[netip.Addr]struct{}{},
	}

	ips, err := LookupIPProxyServerHost(context.Background(), "proxy.example.test")
	if err != nil {
		t.Fatalf("expected unallocated proxy-server answer inside fake range to remain usable, got error %v", err)
	}
	if len(ips) != 1 || ips[0] != realIPInsideFakeRange {
		t.Fatalf("expected proxy-server answer inside fake range to remain usable, got %v", ips)
	}
}

func TestLookupIPProxyServerHostKeepsOnlyRealAnswers(t *testing.T) {
	oldProxyResolver := ProxyServerHostResolver
	oldDefaultResolver := DefaultResolver
	oldMapper := DefaultHostMapper
	defer func() {
		ProxyServerHostResolver = oldProxyResolver
		DefaultResolver = oldDefaultResolver
		DefaultHostMapper = oldMapper
	}()

	fakeIP := netip.MustParseAddr("198.18.0.9")
	realIP := netip.MustParseAddr("203.0.113.9")
	ProxyServerHostResolver = staticProxyServerResolver{ips: []netip.Addr{fakeIP, realIP}}
	DefaultResolver = nil
	DefaultHostMapper = fakeIPOnlyMapper{fake: fakeIP}

	ips, err := LookupIPProxyServerHost(context.Background(), "proxy.example.test")
	if err != nil {
		t.Fatalf("expected real proxy-server DNS answer to remain usable, got error %v", err)
	}
	if len(ips) != 1 || ips[0] != realIP {
		t.Fatalf("expected only the real proxy-server DNS answer to remain, got %v", ips)
	}
}

func TestLookupIPProxyServerHostFallsBackWhenProxyResolverReturnsOnlyFakeIP(t *testing.T) {
	oldProxyResolver := ProxyServerHostResolver
	oldDefaultResolver := DefaultResolver
	oldMapper := DefaultHostMapper
	defer func() {
		ProxyServerHostResolver = oldProxyResolver
		DefaultResolver = oldDefaultResolver
		DefaultHostMapper = oldMapper
	}()

	fakeIP := netip.MustParseAddr("198.18.0.11")
	realIP := netip.MustParseAddr("203.0.113.11")
	ProxyServerHostResolver = staticProxyServerResolver{ips: []netip.Addr{fakeIP}}
	DefaultResolver = staticProxyServerResolver{ips: []netip.Addr{realIP}}
	DefaultHostMapper = fakeIPOnlyMapper{fake: fakeIP}

	ips, err := LookupIPProxyServerHost(context.Background(), "proxy.example.test")
	if err != nil {
		t.Fatalf("expected default resolver fallback after fake proxy-server answer, got error %v", err)
	}
	if len(ips) != 1 || ips[0] != realIP {
		t.Fatalf("expected real default resolver answer to remain usable, got %v", ips)
	}
}

func TestLookupIPProxyServerHostFiltersFallbackResolverAnswers(t *testing.T) {
	oldProxyResolver := ProxyServerHostResolver
	oldDefaultResolver := DefaultResolver
	oldMapper := DefaultHostMapper
	defer func() {
		ProxyServerHostResolver = oldProxyResolver
		DefaultResolver = oldDefaultResolver
		DefaultHostMapper = oldMapper
	}()

	fakeIP := netip.MustParseAddr("198.18.0.10")
	ProxyServerHostResolver = staticProxyServerResolver{err: ErrIPNotFound}
	DefaultResolver = staticProxyServerResolver{ips: []netip.Addr{fakeIP}}
	DefaultHostMapper = fakeIPOnlyMapper{fake: fakeIP}

	ips, err := LookupIPProxyServerHost(context.Background(), "proxy.example.test")
	if err == nil {
		t.Fatalf("expected fallback fake proxy-server DNS answers to be rejected, got ips=%v", ips)
	}
	if len(ips) != 0 {
		t.Fatalf("expected fallback fake proxy-server DNS answers to be removed, got %v", ips)
	}
}
