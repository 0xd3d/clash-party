package resolver

import (
	"context"
	"errors"
	"net/netip"

	D "github.com/miekg/dns"
)

var errIndependentProxyDNSUnavailable = errors.New("no independent literal-IP HTTPS DNS endpoint is configured")

// Static hosts remain usable when the iOS encrypted resolver is absent; a lookup
// requiring network DNS returns an error instead of falling through to the OS.
type unavailableProxyServerResolver struct{}

func (unavailableProxyServerResolver) LookupIP(context.Context, string) ([]netip.Addr, error) {
	return nil, errIndependentProxyDNSUnavailable
}
func (r unavailableProxyServerResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.LookupIP(ctx, host)
}
func (r unavailableProxyServerResolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.LookupIP(ctx, host)
}
func (unavailableProxyServerResolver) ResolveIP(context.Context, string) (netip.Addr, error) {
	return netip.Addr{}, errIndependentProxyDNSUnavailable
}
func (r unavailableProxyServerResolver) ResolveIPv4(ctx context.Context, host string) (netip.Addr, error) {
	return r.ResolveIP(ctx, host)
}
func (r unavailableProxyServerResolver) ResolveIPv6(ctx context.Context, host string) (netip.Addr, error) {
	return r.ResolveIP(ctx, host)
}
func (unavailableProxyServerResolver) ExchangeContext(context.Context, *D.Msg) (*D.Msg, error) {
	return nil, errIndependentProxyDNSUnavailable
}
