package executor

import (
	"net/netip"
	"testing"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
)

func TestIsIOSWarmLeafProxySkipsGroupsAndSystemOutbounds(t *testing.T) {
	group := adapter.NewProxy(outbound.NewBase(outbound.BaseOption{
		Name: "GLOBAL",
		Type: C.Selector,
	}))
	leaf := adapter.NewProxy(outbound.NewBase(outbound.BaseOption{
		Name: "KR-Primary",
		Addr: "example.com:443",
		Type: C.Trojan,
	}))
	direct := adapter.NewProxy(outbound.NewDirect())

	if isIOSWarmLeafProxy(group) {
		t.Fatal("expected selector group to be skipped")
	}
	if !isIOSWarmLeafProxy(leaf) {
		t.Fatal("expected trojan leaf to be warmed")
	}
	if isIOSWarmLeafProxy(direct) {
		t.Fatal("expected DIRECT to be skipped")
	}
}

func TestIOSWarmEgressProxyNamesPrefersGroupNowSelection(t *testing.T) {
	leaf := adapter.NewProxy(outbound.NewBase(outbound.BaseOption{
		Name: "KR-Primary",
		Addr: "example.com:443",
		Type: C.Vless,
	}))
	groupAdapter := newTestSelectableGroup("海外出口", []C.Proxy{leaf}, "KR-Primary")
	group := adapter.NewProxy(groupAdapter)

	cfg := &config.Config{
		Proxies: map[string]C.Proxy{
			"海外出口":   group,
			"KR-Primary": leaf,
		},
	}

	names := iosWarmEgressProxyNames(cfg)
	if len(names) == 0 || names[0] != "KR-Primary" {
		t.Fatalf("expected KR-Primary from group Now(), got %v", names)
	}
}

func TestIOSWarmDialMetadataUsesProxyServerEndpoint(t *testing.T) {
	leaf := adapter.NewProxy(outbound.NewBase(outbound.BaseOption{
		Name: "KR-Primary",
		Addr: "node.example.org:30401",
		Type: C.Trojan,
	}))
	meta, ok := iosWarmDialMetadata(leaf)
	if !ok || meta == nil {
		t.Fatal("expected metadata for leaf proxy")
	}
	if meta.Host != "node.example.org" || meta.DstPort != "30401" {
		t.Fatalf("unexpected dial metadata: host=%q port=%q", meta.Host, meta.DstPort)
	}

	ipLeaf := adapter.NewProxy(outbound.NewBase(outbound.BaseOption{
		Name: "KR-Literal",
		Addr: "203.0.113.10:443",
		Type: C.Trojan,
	}))
	meta, ok = iosWarmDialMetadata(ipLeaf)
	if !ok || meta.DstIP != netip.MustParseAddr("203.0.113.10") || meta.Host != "" {
		t.Fatalf("expected literal-IP metadata, got host=%q ip=%v", meta.Host, meta.DstIP)
	}
}