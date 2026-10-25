package tunnel

import (
	"net/netip"
	"testing"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/adapter/outbound"
	P "github.com/Dreamacro/clash/component/process"
	C "github.com/Dreamacro/clash/constant"
)

func TestIOSMatchedUDPRouteCannotFallThroughToDirect(t *testing.T) {
	oldOS, oldRules, oldSubRules, oldProviders, oldProxies, oldProxyProviders, oldMode := tunnelGOOS, rules, subRules, ruleProviders, proxies, providers, findProcessMode
	t.Cleanup(func() {
		tunnelGOOS = oldOS
		UpdateRules(oldRules, oldSubRules, oldProviders)
		UpdateProxies(oldProxies, oldProxyProviders)
		SetFindProcessMode(oldMode)
	})
	tunnelGOOS = "ios"
	SetFindProcessMode(P.FindProcessMode(P.FindProcessOff))
	direct := adapter.NewProxy(outbound.NewDirect())
	unsupported := adapter.NewProxy(outbound.NewBase(outbound.BaseOption{Name: "TCP only", Type: C.Socks5, UDP: false}))
	UpdateProxies(map[string]C.Proxy{"DIRECT": direct, "TCP only": unsupported}, nil)
	metadata := func(network C.NetWork) *C.Metadata {
		return &C.Metadata{NetWork: network, Type: C.TUN, DstIP: netip.MustParseAddr("198.51.100.12"), DstPort: "3478"}
	}
	for _, target := range []string{"TCP only", "Missing"} {
		UpdateRules([]C.Rule{matchRule{adapter: target}, matchRule{adapter: "DIRECT"}}, nil, nil)
		got, matched, err := match(metadata(C.UDP))
		if err == nil || got != nil || matched == nil || matched.Adapter() != target {
			t.Fatalf("UDP %q fell through to %v: %v", target, got, err)
		}
	}
	UpdateRules(nil, nil, nil)
	if got, _, err := match(metadata(C.UDP)); err == nil || got != nil {
		t.Fatal("unmatched UDP received an implicit direct route")
	}
	// Explicit local/DIRECT rules are still valid. Nothing disables UDP on LAN.
	UpdateRules([]C.Rule{matchRule{adapter: "DIRECT"}}, nil, nil)
	local := metadata(C.UDP)
	local.DstIP = netip.MustParseAddr("192.168.1.9")
	if got, _, err := match(local); err != nil || got != direct {
		t.Fatal("explicit LAN direct route was broken", err)
	}
	UpdateRules([]C.Rule{matchRule{adapter: "Missing"}, matchRule{adapter: "DIRECT"}}, nil, nil)
	if got, _, err := match(metadata(C.TCP)); err == nil || got != nil {
		t.Fatal("missing protected TCP target fell through to DIRECT")
	}
	// This copied core's non-iOS behavior is not changed by the mobile boundary.
	tunnelGOOS = "darwin"
	UpdateRules([]C.Rule{matchRule{adapter: "TCP only"}, matchRule{adapter: "DIRECT"}}, nil, nil)
	if got, _, err := match(metadata(C.UDP)); err != nil || got != direct {
		t.Fatal("non-iOS routing compatibility changed", err)
	}
}
