package outboundgroup

import (
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Dreamacro/clash/common/mobilelog"
	C "github.com/Dreamacro/clash/constant"
)

var (
	outboundGroupGOOS          = runtime.GOOS
	outboundGroupNow           = time.Now
	proxyLeafReachabilityCache sync.Map
	proxyLeafDialFailureCache  sync.Map
)

type proxyLeafReachability struct {
	resolvable bool
	expiresAt  time.Time
}

func addrToMetadata(rawAddress string) (addr *C.Metadata, err error) {
	host, port, err := net.SplitHostPort(rawAddress)
	if err != nil {
		err = fmt.Errorf("addrToMetadata failed: %w", err)
		return
	}

	if ip, err := netip.ParseAddr(host); err != nil {
		addr = &C.Metadata{
			Host:    host,
			DstPort: port,
		}
	} else {
		addr = &C.Metadata{
			Host:    "",
			DstIP:   ip.Unmap(),
			DstPort: port,
		}
	}

	return
}

func tcpKeepAlive(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}
}

func firstAliveReachableProxy(proxies []C.Proxy) C.Proxy {
	return firstAliveReachableProxyExcept(proxies, nil)
}

func fastestAliveProxy(proxies []C.Proxy) C.Proxy {
	return fastestAliveProxyExcept(proxies, nil)
}

func firstAliveReachableProxyExcept(proxies []C.Proxy, excluded map[string]struct{}) C.Proxy {
	for _, proxy := range proxies {
		if proxyExcluded(proxy, excluded) {
			continue
		}
		if proxy.Alive() && proxyLeafReachable(proxy) {
			return proxy
		}
	}

	return nil
}

func fastestAliveProxyExcept(proxies []C.Proxy, excluded map[string]struct{}) C.Proxy {
	var fast C.Proxy
	min := ^uint16(0)
	for _, proxy := range proxies {
		if proxyExcluded(proxy, excluded) {
			continue
		}
		if !proxy.Alive() {
			continue
		}

		delay := proxy.LastDelay()
		if fast == nil || delay < min {
			fast = proxy
			min = delay
		}
	}

	return fast
}

func firstProxyExcept(proxies []C.Proxy, excluded map[string]struct{}) C.Proxy {
	for _, proxy := range proxies {
		if !proxyExcluded(proxy, excluded) {
			return proxy
		}
	}
	if len(proxies) == 0 {
		return nil
	}
	return proxies[0]
}

func proxyExcluded(proxy C.Proxy, excluded map[string]struct{}) bool {
	if len(excluded) == 0 {
		return false
	}
	if key, ok := proxyLeafFailureKey(proxyLeaf(proxy)); ok {
		if _, exists := excluded[key]; exists {
			return true
		}
	}
	return false
}

func rememberProxyAttempt(excluded map[string]struct{}, proxy C.Proxy) {
	if len(excluded) == 0 || proxy == nil {
		return
	}
	if key, ok := proxyLeafFailureKey(proxyLeaf(proxy)); ok {
		excluded[key] = struct{}{}
	}
}

func groupDialAttemptExclusions(attempts int) map[string]struct{} {
	if outboundGroupGOOS != "ios" || attempts <= 1 {
		return nil
	}
	return make(map[string]struct{}, attempts)
}

func groupDialAttempts(proxyCount int) int {
	if outboundGroupGOOS != "ios" || proxyCount < 2 {
		return 1
	}
	if proxyCount > 3 {
		return 3
	}
	return proxyCount
}

func shouldRetryGroupDialOnIOS(err error) bool {
	return outboundGroupGOOS == "ios" && err != nil && isProxyLeafDialFailure(err.Error())
}

func shouldUseSelectedProxy(proxy C.Proxy) bool {
	if outboundGroupGOOS != "ios" || proxy == nil {
		return true
	}
	return proxyLeafReachable(proxy)
}

func proxyLeafReachable(proxy C.Proxy) bool {
	if outboundGroupGOOS != "ios" || proxy == nil {
		return true
	}

	leaf := proxyLeaf(proxy)
	if proxyLeafDialFailureActive(leaf) {
		return false
	}

	host, ok := proxyLeafHost(leaf)
	if !ok {
		return true
	}

	now := outboundGroupNow()
	if cached, ok := proxyLeafReachabilityCache.Load(host); ok {
		if entry, ok := cached.(proxyLeafReachability); ok && now.Before(entry.expiresAt) {
			return entry.resolvable
		}
	}

	return true
}

func markProxyLeafUnreachableOnDialError(proxy C.Proxy, err error) bool {
	if outboundGroupGOOS != "ios" || proxy == nil || err == nil {
		return false
	}

	errMessage := err.Error()
	marked := false
	if isProxyLeafDNSFailure(errMessage) {
		if host, ok := proxyLeafHost(proxyLeaf(proxy)); ok {
			proxyLeafReachabilityCache.Store(host, proxyLeafReachability{
				resolvable: false,
				expiresAt:  outboundGroupNow().Add(proxyLeafFailureCacheTTL()),
			})
			marked = true
		}
	}

	if isProxyLeafDialFailure(errMessage) {
		if key, ok := proxyLeafFailureKey(proxyLeaf(proxy)); ok {
			proxyLeafDialFailureCache.Store(key, outboundGroupNow().Add(proxyLeafFailureCacheTTL()))
			marked = true
		}
	}

	return marked
}

func clearProxyLeafDialFailure(proxy C.Proxy) {
	if key, ok := proxyLeafFailureKey(proxyLeaf(proxy)); ok {
		proxyLeafDialFailureCache.Delete(key)
	}
}

func logProxyLeafDialFailure(groupName string, proxy C.Proxy, metadata *C.Metadata, err error) {
	if outboundGroupGOOS != "ios" || proxy == nil || err == nil {
		return
	}

	source := "<unknown>"
	target := "<unknown>"
	if metadata != nil {
		source = metadata.SourceDetail()
		target = metadata.RemoteAddress()
	}

	leaf := proxyLeaf(proxy)
	leafName := proxy.Name()
	leafType := proxy.Type().String()
	leafAddr := proxy.Addr()
	if leaf != nil {
		leafName = leaf.Name()
		leafType = leaf.Type().String()
		leafAddr = leaf.Addr()
	}
	mobilelog.Native(
		"warning",
		fmt.Sprintf(
			"ios proxy leaf dial failed group=%s leaf=%s type=%s addr=%s source=%s target=%s err=%s",
			groupName,
			leafName,
			leafType,
			leafAddr,
			source,
			target,
			err.Error(),
		),
	)
}

func proxyLeaf(proxy C.Proxy) C.Proxy {
	current := proxy
	seen := map[string]struct{}{}
	for current != nil {
		key := current.Name() + "|" + current.Type().String() + "|" + current.Addr()
		if _, ok := seen[key]; ok {
			break
		}
		seen[key] = struct{}{}

		next := current.Unwrap(nil, false)
		if next == nil || next == current {
			return current
		}
		current = next
	}

	return current
}

func proxyLeafHost(proxy C.Proxy) (string, bool) {
	if proxy == nil {
		return "", false
	}

	addr := proxy.Addr()
	if addr == "" {
		return "", false
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return "", false
	}

	if ip, err := netip.ParseAddr(host); err == nil && ip.IsValid() {
		return "", false
	}

	return host, true
}

func proxyLeafFailureKey(proxy C.Proxy) (string, bool) {
	if proxy == nil {
		return "", false
	}

	name := strings.TrimSpace(proxy.Name())
	addr := strings.TrimSpace(proxy.Addr())
	adapterType := proxy.Type().String()
	if name == "" && addr == "" {
		return "", false
	}

	return adapterType + "|" + name + "|" + addr, true
}

func proxyLeafDialFailureActive(proxy C.Proxy) bool {
	key, ok := proxyLeafFailureKey(proxy)
	if !ok {
		return false
	}

	cached, ok := proxyLeafDialFailureCache.Load(key)
	if !ok {
		return false
	}

	expiresAt, ok := cached.(time.Time)
	if !ok {
		proxyLeafDialFailureCache.Delete(key)
		return false
	}

	if outboundGroupNow().Before(expiresAt) {
		return true
	}

	proxyLeafDialFailureCache.Delete(key)
	return false
}

func proxyLeafFailureCacheTTL() time.Duration {
	return C.DefaultTCPTimeout
}

func isProxyLeafDNSFailure(message string) bool {
	normalized := strings.ToLower(message)
	return strings.Contains(normalized, "dns resolve failed") ||
		strings.Contains(normalized, "couldn't find ip") ||
		strings.Contains(normalized, "no ip address")
}

func isProxyLeafDialFailure(message string) bool {
	normalized := strings.ToLower(message)
	if normalized == "" ||
		strings.Contains(normalized, "context canceled") ||
		strings.Contains(normalized, "operation was canceled") {
		return false
	}

	return isProxyLeafDNSFailure(normalized) ||
		strings.Contains(normalized, "connect failed") ||
		strings.Contains(normalized, "connection refused") ||
		strings.Contains(normalized, "connection reset") ||
		strings.Contains(normalized, "i/o timeout") ||
		strings.Contains(normalized, "timeout") ||
		strings.Contains(normalized, "no route to host") ||
		strings.Contains(normalized, "network is unreachable") ||
		strings.Contains(normalized, "host is down") ||
		strings.Contains(normalized, "eof") ||
		strings.Contains(normalized, "handshake")
}

type SelectAble interface {
	Set(string) error
}
