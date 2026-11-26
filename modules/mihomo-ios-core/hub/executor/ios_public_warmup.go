package executor

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"time"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/common/mobilelog"
	"github.com/Dreamacro/clash/common/mobilephase"
	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/tunnel"
)

const iosPublicWarmupTimeout = 4 * time.Second

type proxyGroupNow interface {
	Now() string
}

// warmIOSPublicPathsAfterProviders runs after rule/provider sync so routing stays
// fail-closed. It only dials the selected leaf proxy's own server endpoint, which
// uses the encrypted proxy-server DNS path instead of application DNS or URLTest.
func warmIOSPublicPathsAfterProviders(cfg *config.Config) {
	if runtime.GOOS != "ios" || !mobilephase.FastStartupEnabled() {
		return
	}

	defer func() {
		if r := recover(); r != nil {
			mobilelog.Native("error", fmt.Sprintf("iOS egress transport warmup panicked: %v", r))
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), iosPublicWarmupTimeout)
	defer cancel()

	started := time.Now()
	mobilephase.SetPhase(
		"warmingPublicPaths",
		"Warming the overseas exit transport without application DNS or extra Internet probes.",
	)
	ok := warmIOSEgressTransport(ctx, cfg)
	mobilelog.Native(
		"info",
		fmt.Sprintf(
			"iOS egress transport warmup finished in %s (succeeded=%t).",
			time.Since(started).Round(time.Millisecond),
			ok,
		),
	)
	if ok {
		mobilephase.MarkRunning("Runtime is running.")
	}
}

func warmIOSEgressTransport(ctx context.Context, cfg *config.Config) bool {
	for _, name := range iosWarmEgressProxyNames(cfg) {
		if ctx.Err() != nil {
			return false
		}

		proxy, exist := proxiesForIOSWarmup(cfg)[name]
		if !exist {
			continue
		}

		metadata, ok := iosWarmDialMetadata(proxy)
		if !ok {
			mobilelog.Native("debug", fmt.Sprintf("iOS egress warmup skipped for %s: missing server endpoint.", name))
			continue
		}

		conn, err := proxy.DialContext(ctx, metadata)
		if err != nil {
			mobilelog.Native("debug", fmt.Sprintf("iOS egress warmup skipped for %s: %s", name, err))
			continue
		}
		_ = conn.Close()

		mobilelog.Native("info", fmt.Sprintf("iOS egress warmup succeeded for proxy %s.", name))
		return true
	}

	return false
}

func iosWarmDialMetadata(proxy C.Proxy) (*C.Metadata, bool) {
	addr := strings.TrimSpace(proxy.Addr())
	if addr == "" {
		return nil, false
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, false
	}

	metadata := &C.Metadata{
		NetWork: C.TCP,
		Host:    host,
		DstPort: port,
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		metadata.DstIP = ip
		metadata.Host = ""
	}

	return metadata, true
}

func proxiesForIOSWarmup(cfg *config.Config) map[string]C.Proxy {
	if cfg != nil && len(cfg.Proxies) > 0 {
		return cfg.Proxies
	}
	return tunnel.Proxies()
}

func iosWarmEgressProxyNames(cfg *config.Config) []string {
	proxies := proxiesForIOSWarmup(cfg)
	if len(proxies) == 0 {
		return nil
	}

	names := make([]string, 0, 4)
	seen := map[string]struct{}{}
	add := func(name string) {
		if name == "" || name == "DIRECT" || name == "REJECT" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		proxy := proxies[name]
		if proxy == nil || !isIOSWarmLeafProxy(proxy) {
			return
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}

	for _, proxy := range proxies {
		outbound, ok := proxy.(*adapter.Proxy)
		if !ok {
			continue
		}
		group, ok := outbound.ProxyAdapter.(proxyGroupNow)
		if !ok {
			continue
		}
		add(group.Now())
		if len(names) >= 4 {
			return names
		}
	}

	for name, proxy := range proxies {
		if !isIOSWarmLeafProxy(proxy) {
			continue
		}
		add(name)
		if len(names) >= 4 {
			break
		}
	}

	return names
}

func isIOSWarmLeafProxy(proxy C.Proxy) bool {
	switch proxy.Type() {
	case C.Direct, C.Reject, C.Compatible, C.Pass,
		C.Relay, C.Selector, C.Fallback, C.URLTest, C.LoadBalance:
		return false
	default:
		return true
	}
}