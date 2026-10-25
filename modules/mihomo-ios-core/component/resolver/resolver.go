package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"time"

	"github.com/Dreamacro/clash/common/mobilelog"
	"github.com/Dreamacro/clash/common/utils"
	"github.com/Dreamacro/clash/component/trie"

	"github.com/miekg/dns"
	"github.com/zhangyunhao116/fastrand"
)

var (
	// DefaultResolver aim to resolve ip
	DefaultResolver Resolver

	// ProxyServerHostResolver resolve ip to proxies server host
	ProxyServerHostResolver Resolver

	// iOS endpoint lookups never fall back to application DNS or the OS.
	// This is a source-build safety baseline, not a YAML option.
	RequireEncryptedProxyServerDNS = runtime.GOOS == "ios"

	// DisableIPv6 means don't resolve ipv6 host
	// default value is true
	DisableIPv6 = true

	// DefaultHosts aim to resolve hosts
	DefaultHosts = NewHosts(trie.New[HostValue]())

	// DefaultDNSTimeout defined the default dns request timeout
	DefaultDNSTimeout = time.Second * 5
)

var (
	ErrIPNotFound   = errors.New("couldn't find ip")
	ErrIPVersion    = errors.New("ip version error")
	ErrIPv6Disabled = errors.New("ipv6 disabled")
)

type Resolver interface {
	LookupIP(ctx context.Context, host string) (ips []netip.Addr, err error)
	LookupIPv4(ctx context.Context, host string) (ips []netip.Addr, err error)
	LookupIPv6(ctx context.Context, host string) (ips []netip.Addr, err error)
	ResolveIP(ctx context.Context, host string) (ip netip.Addr, err error)
	ResolveIPv4(ctx context.Context, host string) (ip netip.Addr, err error)
	ResolveIPv6(ctx context.Context, host string) (ip netip.Addr, err error)
	ExchangeContext(ctx context.Context, m *dns.Msg) (msg *dns.Msg, err error)
}

// LookupIPv4WithResolver same as LookupIPv4, but with a resolver
func LookupIPv4WithResolver(ctx context.Context, host string, r Resolver) ([]netip.Addr, error) {
	if node, ok := DefaultHosts.Search(host, false); ok {
		if addrs := utils.Filter(node.IPs, func(ip netip.Addr) bool {
			return ip.Is4()
		}); len(addrs) > 0 {
			return addrs, nil
		}
	}

	ip, err := netip.ParseAddr(host)
	if err == nil {
		if ip.Is4() || ip.Is4In6() {
			return []netip.Addr{ip}, nil
		}
		return []netip.Addr{}, ErrIPVersion
	}

	if r != nil {
		return r.LookupIPv4(ctx, host)
	}

	ipAddrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	} else if len(ipAddrs) == 0 {
		return nil, ErrIPNotFound
	}

	return ipAddrs, nil
}

// LookupIPv4 with a host, return ipv4 list
func LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return LookupIPv4WithResolver(ctx, host, DefaultResolver)
}

// ResolveIPv4WithResolver same as ResolveIPv4, but with a resolver
func ResolveIPv4WithResolver(ctx context.Context, host string, r Resolver) (netip.Addr, error) {
	ips, err := LookupIPv4WithResolver(ctx, host, r)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}
	return ips[fastrand.Intn(len(ips))], nil
}

// ResolveIPv4 with a host, return ipv4
func ResolveIPv4(ctx context.Context, host string) (netip.Addr, error) {
	return ResolveIPv4WithResolver(ctx, host, DefaultResolver)
}

// LookupIPv6WithResolver same as LookupIPv6, but with a resolver
func LookupIPv6WithResolver(ctx context.Context, host string, r Resolver) ([]netip.Addr, error) {
	if DisableIPv6 {
		return nil, ErrIPv6Disabled
	}

	if node, ok := DefaultHosts.Search(host, false); ok {
		if addrs := utils.Filter(node.IPs, func(ip netip.Addr) bool {
			return ip.Is6()
		}); len(addrs) > 0 {
			return addrs, nil
		}
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		if strings.Contains(host, ":") {
			return []netip.Addr{ip}, nil
		}
		return nil, ErrIPVersion
	}

	if r != nil {
		return r.LookupIPv6(ctx, host)
	}

	ipAddrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip6", host)
	if err != nil {
		return nil, err
	} else if len(ipAddrs) == 0 {
		return nil, ErrIPNotFound
	}

	return ipAddrs, nil
}

// LookupIPv6 with a host, return ipv6 list
func LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return LookupIPv6WithResolver(ctx, host, DefaultResolver)
}

// ResolveIPv6WithResolver same as ResolveIPv6, but with a resolver
func ResolveIPv6WithResolver(ctx context.Context, host string, r Resolver) (netip.Addr, error) {
	ips, err := LookupIPv6WithResolver(ctx, host, r)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}
	return ips[fastrand.Intn(len(ips))], nil
}

func ResolveIPv6(ctx context.Context, host string) (netip.Addr, error) {
	return ResolveIPv6WithResolver(ctx, host, DefaultResolver)
}

// LookupIPWithResolver same as LookupIP, but with a resolver
func LookupIPWithResolver(ctx context.Context, host string, r Resolver) ([]netip.Addr, error) {
	if node, ok := DefaultHosts.Search(host, false); ok {
		return node.IPs, nil
	}

	if r != nil {
		if DisableIPv6 {
			return r.LookupIPv4(ctx, host)
		}
		return r.LookupIP(ctx, host)
	} else if DisableIPv6 {
		return LookupIPv4WithResolver(ctx, host, r)
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}

	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	} else if len(ips) == 0 {
		return nil, ErrIPNotFound
	}

	return ips, nil
}

// LookupIP with a host, return ip
func LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return LookupIPWithResolver(ctx, host, DefaultResolver)
}

// ResolveIPWithResolver same as ResolveIP, but with a resolver
func ResolveIPWithResolver(ctx context.Context, host string, r Resolver) (netip.Addr, error) {
	ips, err := LookupIPWithResolver(ctx, host, r)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}
	return ips[fastrand.Intn(len(ips))], nil
}

// ResolveIP with a host, return ip
func ResolveIP(ctx context.Context, host string) (netip.Addr, error) {
	return ResolveIPWithResolver(ctx, host, DefaultResolver)
}

// ResolveIPv4ProxyServerHost proxies server host only
func ResolveIPv4ProxyServerHost(ctx context.Context, host string) (netip.Addr, error) {
	ips, err := LookupIPv4ProxyServerHost(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}
	return ips[fastrand.Intn(len(ips))], nil
}

// ResolveIPv6ProxyServerHost proxies server host only
func ResolveIPv6ProxyServerHost(ctx context.Context, host string) (netip.Addr, error) {
	ips, err := LookupIPv6ProxyServerHost(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}
	return ips[fastrand.Intn(len(ips))], nil
}

// ResolveProxyServerHost proxies server host only
func ResolveProxyServerHost(ctx context.Context, host string) (netip.Addr, error) {
	ips, err := LookupIPProxyServerHost(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}
	return ips[fastrand.Intn(len(ips))], nil
}

func LookupIPv6ProxyServerHost(ctx context.Context, host string) ([]netip.Addr, error) {
	return lookupProxyServerHost(ctx, host, LookupIPv6WithResolver, LookupIPv6)
}

func LookupIPv4ProxyServerHost(ctx context.Context, host string) ([]netip.Addr, error) {
	return lookupProxyServerHost(ctx, host, LookupIPv4WithResolver, LookupIPv4)
}

func LookupIPProxyServerHost(ctx context.Context, host string) ([]netip.Addr, error) {
	return lookupProxyServerHost(ctx, host, LookupIPWithResolver, LookupIP)
}

func lookupProxyServerHost(
	ctx context.Context,
	host string,
	lookupWithResolver func(context.Context, string, Resolver) ([]netip.Addr, error),
	lookupDefault func(context.Context, string) ([]netip.Addr, error),
) ([]netip.Addr, error) {
	if RequireEncryptedProxyServerDNS {
		// Literal addresses need no DNS. Existing family/IPv6 checks still apply.
		if _, err := netip.ParseAddr(host); err == nil {
			return lookupWithResolver(ctx, host, nil)
		}
	}
	proxyDNS := ProxyServerHostResolver
	if RequireEncryptedProxyServerDNS && proxyDNS == nil {
		// lookupWithResolver checks static hosts before this error-only resolver.
		proxyDNS = unavailableProxyServerResolver{}
	}
	var proxyFilterErr error
	if proxyDNS != nil {
		if ips, err := lookupWithResolver(ctx, host, proxyDNS); err == nil {
			logProxyServerHostLookup(host, "proxy-resolver raw", ips, nil)
			if filtered, filterErr := filterProxyServerHostIPs(host, ips); filterErr == nil && len(filtered) > 0 {
				logProxyServerHostLookup(host, "proxy-resolver filtered", filtered, nil)
				return filtered, nil
			} else if filterErr != nil {
				logProxyServerHostLookup(host, "proxy-resolver filtered", nil, filterErr)
				proxyFilterErr = filterErr
			} else {
				logProxyServerHostLookup(host, "proxy-resolver filtered", filtered, nil)
			}
		} else {
			logProxyServerHostLookup(host, "proxy-resolver raw", nil, err)
			proxyFilterErr = err
		}
	}
	if RequireEncryptedProxyServerDNS {
		if proxyFilterErr == nil {
			proxyFilterErr = ErrIPNotFound
		}
		return nil, fmt.Errorf("encrypted proxy endpoint DNS failed: %w", proxyFilterErr)
	}

	ips, err := lookupDefault(ctx, host)
	if err != nil {
		logProxyServerHostLookup(host, "default-resolver raw", nil, err)
		if proxyFilterErr != nil {
			return nil, proxyFilterErr
		}
		return nil, err
	}
	logProxyServerHostLookup(host, "default-resolver raw", ips, nil)
	filtered, filterErr := filterProxyServerHostIPs(host, ips)
	logProxyServerHostLookup(host, "default-resolver filtered", filtered, filterErr)
	return filtered, filterErr
}

func filterProxyServerHostIPs(host string, ips []netip.Addr) ([]netip.Addr, error) {
	filtered := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if IsExistFakeIP(ip) {
			continue
		}
		filtered = append(filtered, ip)
	}

	if len(filtered) == 0 && len(ips) > 0 {
		return nil, fmt.Errorf("%w: %s resolved to fake-ip only", ErrIPNotFound, host)
	}

	return filtered, nil
}

func logProxyServerHostLookup(host string, stage string, ips []netip.Addr, err error) {
	if host == "" || !mobilelog.ShouldEmit("debug") {
		return
	}
	if err != nil {
		mobilelog.Native("debug", fmt.Sprintf("proxy-server host lookup stage=%s host=%s err=%v", stage, host, err))
		return
	}

	values := make([]string, 0, len(ips))
	for _, ip := range ips {
		values = append(values, fmt.Sprintf("%s(fakeRange=%t allocated=%t)", ip, IsFakeIP(ip), IsExistFakeIP(ip)))
	}
	if len(values) == 0 {
		values = append(values, "none")
	}
	mobilelog.Native("debug", fmt.Sprintf("proxy-server host lookup stage=%s host=%s ips=%s", stage, host, strings.Join(values, ",")))
}
