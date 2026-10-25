package dns

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// NewIndependentProxyServerHostResolver is the iOS endpoint-bootstrap boundary.
// Application main/policy/fallback resolvers are left untouched. An empty safe
// set yields an empty resolver; the strict component then reports lookup failure.
func NewIndependentProxyServerHostResolver(old *Resolver, candidates []NameServer) *Resolver {
	r := NewProxyServerHostResolver(old)
	r.main = nil
	for _, server := range candidates {
		if !independentHTTPSNameServer(server) {
			continue
		}
		client := newDoHClient(server.Addr, nil, server.PreferH3, server.Params, "").(*dnsOverHTTPS)
		client.independentProxyBootstrap = true
		r.main = append(r.main, client)
	}
	return r
}

func independentHTTPSNameServer(server NameServer) bool {
	if server.Net != "https" || (server.ProxyAdapter != "" && !strings.EqualFold(server.ProxyAdapter, "DIRECT")) {
		return false
	}
	endpoint, err := url.Parse(server.Addr)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Opaque != "" || endpoint.Fragment != "" || endpoint.Path == "" {
		return false
	}
	if _, err := netip.ParseAddr(endpoint.Hostname()); err != nil {
		return false
	}
	if port := endpoint.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return false
		}
	}
	return true
}
