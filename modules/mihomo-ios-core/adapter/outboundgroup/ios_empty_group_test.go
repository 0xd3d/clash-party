package outboundgroup

import (
	"context"
	"io"
	"testing"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/adapter/outbound"
	C "github.com/Dreamacro/clash/constant"
	types "github.com/Dreamacro/clash/constant/provider"
	"github.com/Dreamacro/clash/tunnel"
)

func TestIOSEmptyGroupRejectsBeforeAndAfterFilters(t *testing.T) {
	oldGOOS := outboundGroupGOOS
	t.Cleanup(func() { outboundGroupGOOS = oldGOOS })
	outboundGroupGOOS = "ios"
	leaf := newStubProxy("Selected", "198.51.100.1:443", C.Trojan, true, 10)
	for _, tc := range []struct {
		name, filter, excludeFilter, excludeType string
		proxies                                  []C.Proxy
	}{
		{name: "empty provider"},
		{name: "include filter", filter: "^Missing$", proxies: []C.Proxy{leaf}},
		{name: "exclude filter", excludeFilter: ".*", proxies: []C.Proxy{leaf}},
		{name: "exclude type", excludeType: "Trojan", proxies: []C.Proxy{leaf}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			group := &Selector{GroupBase: NewGroupBase(GroupBaseOption{
				BaseOption: outbound.BaseOption{Name: "Protected", Type: C.Selector},
				filter:     tc.filter, excludeFilter: tc.excludeFilter, excludeType: tc.excludeType,
				providers: []types.ProxyProvider{stubProxyProvider{proxies: tc.proxies}},
			}), selected: "Selected"}
			proxies := group.GetProxies(false)
			if len(proxies) != 1 || proxies[0].Type() != C.Reject || group.Now() != "REJECT" {
				t.Fatalf("empty group did not resolve to REJECT: %#v", proxies)
			}
			conn, err := group.DialContext(context.Background(), &C.Metadata{})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err = conn.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("reject read: %v", err)
			}
			if leaf.dialCount.Load() != 0 {
				t.Fatal("empty group dialed a real proxy")
			}
		})
	}
	group := &Selector{GroupBase: NewGroupBase(GroupBaseOption{
		BaseOption: outbound.BaseOption{Name: "Protected", Type: C.Selector},
		providers:  []types.ProxyProvider{stubProxyProvider{proxies: []C.Proxy{leaf}}},
	}), selected: "Selected"}
	if group.Now() != "Selected" {
		t.Fatal("nonempty explicit selection changed")
	}
}

func TestNonIOSEmptyGroupCompatibilityUnchanged(t *testing.T) {
	oldGOOS, oldProxies, oldProviders := outboundGroupGOOS, tunnel.Proxies(), tunnel.Providers()
	t.Cleanup(func() { outboundGroupGOOS = oldGOOS; tunnel.UpdateProxies(oldProxies, oldProviders) })
	outboundGroupGOOS = "linux"
	compatible := adapter.NewProxy(outbound.NewCompatible())
	tunnel.UpdateProxies(map[string]C.Proxy{"COMPATIBLE": compatible}, nil)
	group := NewGroupBase(GroupBaseOption{BaseOption: outbound.BaseOption{Name: "legacy", Type: C.Selector}})
	if proxies := group.GetProxies(false); len(proxies) != 1 || proxies[0] != compatible {
		t.Fatal("non-iOS initial-empty fallback changed")
	}
	leaf := newStubProxy("Selected", "198.51.100.1:443", C.Trojan, true, 10)
	group = NewGroupBase(GroupBaseOption{BaseOption: outbound.BaseOption{Name: "legacy", Type: C.Selector}, excludeFilter: ".*", providers: []types.ProxyProvider{stubProxyProvider{proxies: []C.Proxy{leaf}}}})
	if len(group.GetProxies(false)) != 0 {
		t.Fatal("non-iOS post-filter behavior changed")
	}
}
