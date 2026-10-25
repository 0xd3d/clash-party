package outboundgroup

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/common/singledo"
	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
	types "github.com/Dreamacro/clash/constant/provider"
)

type stubProxyProvider struct {
	proxies []C.Proxy
}

func (p stubProxyProvider) Name() string                   { return "stub" }
func (p stubProxyProvider) VehicleType() types.VehicleType { return types.File }
func (p stubProxyProvider) Type() types.ProviderType       { return types.Proxy }
func (p stubProxyProvider) Initial() error                 { return nil }
func (p stubProxyProvider) Update() error                  { return nil }
func (p stubProxyProvider) Proxies() []C.Proxy             { return p.proxies }
func (p stubProxyProvider) Touch()                         {}
func (p stubProxyProvider) HealthCheck()                   {}
func (p stubProxyProvider) Version() uint32                { return 1 }

type stubProxy struct {
	*outbound.Base
	alive     bool
	delay     uint16
	unwrapped C.Proxy
	dialErr   error
	dialCount atomic.Int32
}

func newStubProxy(name, addr string, adapterType C.AdapterType, alive bool, delay uint16) *stubProxy {
	return &stubProxy{
		Base:  outbound.NewBase(outbound.BaseOption{Name: name, Addr: addr, Type: adapterType}),
		alive: alive,
		delay: delay,
	}
}

func (p *stubProxy) Alive() bool                    { return p.alive }
func (p *stubProxy) DelayHistory() []C.DelayHistory { return nil }
func (p *stubProxy) LastDelay() uint16              { return p.delay }
func (p *stubProxy) URLTest(ctx context.Context, url string) (uint16, error) {
	return p.delay, nil
}
func (p *stubProxy) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	p.dialCount.Add(1)
	if p.dialErr != nil {
		return nil, p.dialErr
	}
	return &stubConn{chain: C.Chain{p.Name()}, remoteDestination: p.Addr()}, nil
}
func (p *stubProxy) Dial(metadata *C.Metadata) (C.Conn, error) {
	return nil, errors.New("not implemented")
}
func (p *stubProxy) DialUDP(metadata *C.Metadata) (C.PacketConn, error) {
	return nil, errors.New("not implemented")
}
func (p *stubProxy) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	return p.unwrapped
}

type stubConn struct {
	chain             C.Chain
	remoteDestination string
}

func (c *stubConn) Read(b []byte) (int, error)         { return 0, io.EOF }
func (c *stubConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c *stubConn) Close() error                       { return nil }
func (c *stubConn) LocalAddr() net.Addr                { return stubAddr("local") }
func (c *stubConn) RemoteAddr() net.Addr               { return stubAddr("remote") }
func (c *stubConn) SetDeadline(t time.Time) error      { return nil }
func (c *stubConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *stubConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *stubConn) Chains() C.Chain                    { return c.chain }
func (c *stubConn) AppendToChains(adapter C.ProxyAdapter) {
	c.chain = append(c.chain, adapter.Name())
}
func (c *stubConn) RemoteDestination() string { return c.remoteDestination }

type stubAddr string

func (a stubAddr) Network() string { return string(a) }
func (a stubAddr) String() string  { return string(a) }

func TestSelectorSelectedProxyPreservesExplicitChoiceOnIOS(t *testing.T) {
	oldGOOS := outboundGroupGOOS
	oldNow := outboundGroupNow
	defer func() {
		outboundGroupGOOS = oldGOOS
		outboundGroupNow = oldNow
		proxyLeafReachabilityCache = sync.Map{}
	}()

	outboundGroupGOOS = "ios"
	outboundGroupNow = time.Now
	proxyLeafReachabilityCache = sync.Map{}

	badLeaf := newStubProxy("bad-leaf", "bad.example:443", C.Trojan, true, 10)
	bad := newStubProxy("bad", "", C.Selector, true, 10)
	bad.unwrapped = badLeaf

	goodLeaf := newStubProxy("good-leaf", "1.1.1.1:443", C.Trojan, true, 20)
	good := newStubProxy("good", "", C.Selector, true, 20)
	good.unwrapped = goodLeaf

	selector := &Selector{
		GroupBase: NewGroupBase(GroupBaseOption{
			BaseOption: outbound.BaseOption{Name: "selector", Type: C.Selector},
			providers:  []types.ProxyProvider{stubProxyProvider{proxies: []C.Proxy{bad, good}}},
		}),
		selected: "bad",
	}

	if got := selector.selectedProxy(false); got.Name() != "bad" {
		t.Fatalf("expected selector to preserve the explicit selection, got %s", got.Name())
	}
}

func TestURLTestFastSkipsKnownUnreachableLeafOnIOS(t *testing.T) {
	oldGOOS := outboundGroupGOOS
	oldNow := outboundGroupNow
	defer func() {
		outboundGroupGOOS = oldGOOS
		outboundGroupNow = oldNow
		proxyLeafReachabilityCache = sync.Map{}
	}()

	outboundGroupGOOS = "ios"
	outboundGroupNow = time.Now
	proxyLeafReachabilityCache = sync.Map{}
	proxyLeafReachabilityCache.Store("bad.example", proxyLeafReachability{
		resolvable: false,
		expiresAt:  outboundGroupNow().Add(time.Second),
	})

	badLeaf := newStubProxy("bad-leaf", "bad.example:443", C.Trojan, true, 5)
	bad := newStubProxy("bad", "", C.Selector, true, 5)
	bad.unwrapped = badLeaf

	goodLeaf := newStubProxy("good-leaf", "1.1.1.1:443", C.Trojan, true, 50)
	good := newStubProxy("good", "", C.Selector, true, 50)
	good.unwrapped = goodLeaf

	urlTest := &URLTest{
		GroupBase: NewGroupBase(GroupBaseOption{
			BaseOption: outbound.BaseOption{Name: "urltest", Type: C.URLTest},
			providers:  []types.ProxyProvider{stubProxyProvider{proxies: []C.Proxy{bad, good}}},
		}),
		fastNode:   bad,
		fastSingle: singledo.NewSingle[C.Proxy](time.Second),
	}

	if got := urlTest.fast(false); got.Name() != "good" {
		t.Fatalf("expected url-test to skip the unresolvable proxy, got %s", got.Name())
	}
}

func TestURLTestFastDoesNotSynchronouslyResolveLeafHostsOnIOS(t *testing.T) {
	oldGOOS := outboundGroupGOOS
	oldNow := outboundGroupNow
	defer func() {
		outboundGroupGOOS = oldGOOS
		outboundGroupNow = oldNow
		proxyLeafReachabilityCache = sync.Map{}
	}()

	outboundGroupGOOS = "ios"
	outboundGroupNow = time.Now
	proxyLeafReachabilityCache = sync.Map{}

	slow := newStubProxy("slow", "slow.example:443", C.Trojan, true, 500)
	fast := newStubProxy("fast", "fast.example:443", C.Trojan, true, 10)

	urlTest := &URLTest{
		GroupBase: NewGroupBase(GroupBaseOption{
			BaseOption: outbound.BaseOption{Name: "urltest", Type: C.URLTest},
			providers:  []types.ProxyProvider{stubProxyProvider{proxies: []C.Proxy{slow, fast}}},
		}),
		fastSingle: singledo.NewSingle[C.Proxy](time.Second),
	}

	if got := urlTest.fast(false); got.Name() != "fast" {
		t.Fatalf("expected url-test to keep delay-based selection without synchronous DNS, got %s", got.Name())
	}
}

func TestURLTestDialFailureInvalidatesUnreachableFastNodeOnIOS(t *testing.T) {
	oldGOOS := outboundGroupGOOS
	oldNow := outboundGroupNow
	defer func() {
		outboundGroupGOOS = oldGOOS
		outboundGroupNow = oldNow
		proxyLeafReachabilityCache = sync.Map{}
	}()

	outboundGroupGOOS = "ios"
	outboundGroupNow = time.Now
	proxyLeafReachabilityCache = sync.Map{}

	bad := newStubProxy("bad", "bad.example:443", C.Trojan, true, 5)
	bad.dialErr = errors.New("dns resolve failed: couldn't find ip")
	good := newStubProxy("good", "good.example:443", C.Trojan, true, 50)

	urlTest := &URLTest{
		GroupBase: NewGroupBase(GroupBaseOption{
			BaseOption: outbound.BaseOption{Name: "urltest", Type: C.URLTest},
			providers:  []types.ProxyProvider{stubProxyProvider{proxies: []C.Proxy{bad, good}}},
		}),
		fastSingle: singledo.NewSingle[C.Proxy](time.Second * 10),
	}

	conn, err := urlTest.DialContext(context.Background(), &C.Metadata{})
	if err != nil {
		t.Fatalf("expected url-test to retry the DNS-unreachable fast node on iOS: %v", err)
	}
	_ = conn.Close()

	if got := urlTest.fast(false); got.Name() != "good" {
		t.Fatalf("expected url-test to invalidate the failed fast node and choose another reachable proxy, got %s", got.Name())
	}
}

func TestURLTestDialRetriesNextProxyOnTransientIOSFailure(t *testing.T) {
	oldGOOS := outboundGroupGOOS
	oldNow := outboundGroupNow
	defer func() {
		outboundGroupGOOS = oldGOOS
		outboundGroupNow = oldNow
		proxyLeafDialFailureCache = sync.Map{}
		proxyLeafReachabilityCache = sync.Map{}
	}()

	outboundGroupGOOS = "ios"
	outboundGroupNow = time.Now
	proxyLeafDialFailureCache = sync.Map{}
	proxyLeafReachabilityCache = sync.Map{}

	bad := newStubProxy("bad", "bad.example:443", C.Trojan, true, 5)
	bad.dialErr = errors.New("connect failed: i/o timeout")
	good := newStubProxy("good", "good.example:443", C.Trojan, true, 50)

	urlTest := &URLTest{
		GroupBase: NewGroupBase(GroupBaseOption{
			BaseOption: outbound.BaseOption{Name: "urltest", Type: C.URLTest},
			providers:  []types.ProxyProvider{stubProxyProvider{proxies: []C.Proxy{bad, good}}},
		}),
		fastSingle: singledo.NewSingle[C.Proxy](time.Second * 10),
	}

	conn, err := urlTest.DialContext(context.Background(), &C.Metadata{})
	if err != nil {
		t.Fatalf("expected url-test to retry a transient iOS dial failure on the next proxy: %v", err)
	}
	_ = conn.Close()

	if got := bad.dialCount.Load(); got != 1 {
		t.Fatalf("expected failed proxy to be tried once, got %d", got)
	}
	if got := good.dialCount.Load(); got != 1 {
		t.Fatalf("expected fallback proxy to be tried once, got %d", got)
	}
	if got := urlTest.fast(false); got.Name() != "good" {
		t.Fatalf("expected url-test to keep the successful fallback proxy, got %s", got.Name())
	}
}

func TestURLTestDialDoesNotRetrySameLeafWithinSingleIOSFlow(t *testing.T) {
	oldGOOS := outboundGroupGOOS
	oldNow := outboundGroupNow
	defer func() {
		outboundGroupGOOS = oldGOOS
		outboundGroupNow = oldNow
		proxyLeafDialFailureCache = sync.Map{}
		proxyLeafReachabilityCache = sync.Map{}
	}()

	outboundGroupGOOS = "ios"
	outboundGroupNow = time.Now
	proxyLeafDialFailureCache = sync.Map{}
	proxyLeafReachabilityCache = sync.Map{}

	first := newStubProxy("first", "first.example:443", C.Vmess, true, 1)
	first.dialErr = errors.New("connect failed: network is unreachable")
	second := newStubProxy("second", "second.example:443", C.Vmess, true, 2)
	second.dialErr = errors.New("connect failed: network is unreachable")
	third := newStubProxy("third", "third.example:443", C.Vmess, true, 3)

	urlTest := &URLTest{
		GroupBase: NewGroupBase(GroupBaseOption{
			BaseOption: outbound.BaseOption{Name: "urltest", Type: C.URLTest},
			providers:  []types.ProxyProvider{stubProxyProvider{proxies: []C.Proxy{first, second, third}}},
		}),
		fastSingle: singledo.NewSingle[C.Proxy](time.Second * 10),
	}

	conn, err := urlTest.DialContext(context.Background(), &C.Metadata{})
	if err != nil {
		t.Fatalf("expected url-test to try distinct leaves until one succeeds: %v", err)
	}
	_ = conn.Close()

	if got := first.dialCount.Load(); got != 1 {
		t.Fatalf("expected first failed leaf once, got %d", got)
	}
	if got := second.dialCount.Load(); got != 1 {
		t.Fatalf("expected second failed leaf once, got %d", got)
	}
	if got := third.dialCount.Load(); got != 1 {
		t.Fatalf("expected third leaf once, got %d", got)
	}
}

func TestURLTestManualPinRetriesAwayFromFailedSelectedProxyOnIOS(t *testing.T) {
	oldGOOS := outboundGroupGOOS
	oldNow := outboundGroupNow
	defer func() {
		outboundGroupGOOS = oldGOOS
		outboundGroupNow = oldNow
		proxyLeafDialFailureCache = sync.Map{}
	}()

	outboundGroupGOOS = "ios"
	outboundGroupNow = time.Now
	proxyLeafDialFailureCache = sync.Map{}

	manual := newStubProxy("manual", "manual.example:443", C.Trojan, true, 5)
	manual.dialErr = errors.New("connect failed: i/o timeout")
	good := newStubProxy("good", "good.example:443", C.Trojan, true, 50)

	urlTest := &URLTest{
		GroupBase: NewGroupBase(GroupBaseOption{
			BaseOption: outbound.BaseOption{Name: "urltest", Type: C.URLTest},
			providers:  []types.ProxyProvider{stubProxyProvider{proxies: []C.Proxy{manual, good}}},
		}),
		selected:   "manual",
		fastSingle: singledo.NewSingle[C.Proxy](time.Second * 10),
	}

	conn, err := urlTest.DialContext(context.Background(), &C.Metadata{})
	if err != nil {
		t.Fatalf("expected manual pin to fail over on iOS after the selected proxy fails: %v", err)
	}
	_ = conn.Close()
	if got := manual.dialCount.Load(); got != 1 {
		t.Fatalf("expected manual proxy to be tried once, got %d", got)
	}
	if got := good.dialCount.Load(); got != 1 {
		t.Fatalf("expected manual pin to retry onto another proxy, got %d", got)
	}
	if got := urlTest.fast(false); got.Name() != "good" {
		t.Fatalf("expected transiently failed manual pin to be bypassed on the fast path, got %s", got.Name())
	}
	if urlTest.selected != "manual" {
		t.Fatalf("expected manual pin preference to remain stored, got %q", urlTest.selected)
	}
}

func TestURLTestSetPinsSelectedProxy(t *testing.T) {
	fast := newStubProxy("fast", "1.1.1.1:443", C.Trojan, true, 10)
	manual := newStubProxy("manual", "1.1.1.2:443", C.Trojan, true, 500)

	urlTest := &URLTest{
		GroupBase: NewGroupBase(GroupBaseOption{
			BaseOption: outbound.BaseOption{Name: "urltest", Type: C.URLTest},
			providers:  []types.ProxyProvider{stubProxyProvider{proxies: []C.Proxy{fast, manual}}},
		}),
		fastSingle: singledo.NewSingle[C.Proxy](time.Second),
	}

	if got := urlTest.fast(false); got.Name() != "fast" {
		t.Fatalf("expected delay-based selection before manual pin, got %s", got.Name())
	}

	if err := urlTest.Set("manual"); err != nil {
		t.Fatalf("expected manual pin to be accepted: %v", err)
	}

	if got := urlTest.fast(false); got.Name() != "manual" {
		t.Fatalf("expected url-test to preserve the manual pin, got %s", got.Name())
	}
}

func TestURLTestManualPinBypassesKnownUnreachableLeafOnIOS(t *testing.T) {
	oldGOOS := outboundGroupGOOS
	oldNow := outboundGroupNow
	defer func() {
		outboundGroupGOOS = oldGOOS
		outboundGroupNow = oldNow
		proxyLeafReachabilityCache = sync.Map{}
	}()

	outboundGroupGOOS = "ios"
	outboundGroupNow = time.Now
	proxyLeafReachabilityCache = sync.Map{}
	proxyLeafReachabilityCache.Store("manual.example", proxyLeafReachability{
		resolvable: false,
		expiresAt:  outboundGroupNow().Add(time.Second),
	})

	manual := newStubProxy("manual", "manual.example:443", C.Trojan, true, 10)
	fallback := newStubProxy("fallback", "fallback.example:443", C.Trojan, true, 100)

	urlTest := &URLTest{
		GroupBase: NewGroupBase(GroupBaseOption{
			BaseOption: outbound.BaseOption{Name: "urltest", Type: C.URLTest},
			providers:  []types.ProxyProvider{stubProxyProvider{proxies: []C.Proxy{manual, fallback}}},
		}),
		selected:   "manual",
		fastNode:   manual,
		fastSingle: singledo.NewSingle[C.Proxy](time.Second),
	}

	if got := urlTest.fast(false); got.Name() != "fallback" {
		t.Fatalf("expected url-test to bypass a transiently unreachable manual pin, got %s", got.Name())
	}
	if urlTest.selected != "manual" {
		t.Fatalf("expected url-test to keep the manual pin, got %q", urlTest.selected)
	}
}

func TestURLTestManualPinPreservesColdInactiveProxy(t *testing.T) {
	manual := newStubProxy("manual", "manual.example:443", C.Trojan, false, 10)
	fallback := newStubProxy("fallback", "fallback.example:443", C.Trojan, true, 100)

	urlTest := &URLTest{
		GroupBase: NewGroupBase(GroupBaseOption{
			BaseOption: outbound.BaseOption{Name: "urltest", Type: C.URLTest},
			providers:  []types.ProxyProvider{stubProxyProvider{proxies: []C.Proxy{manual, fallback}}},
		}),
		selected:   "manual",
		fastNode:   fallback,
		fastSingle: singledo.NewSingle[C.Proxy](time.Second),
	}

	if got := urlTest.fast(false); got.Name() != "manual" {
		t.Fatalf("expected url-test to preserve the manual pin during cold health-check state, got %s", got.Name())
	}
	if urlTest.selected != "manual" {
		t.Fatalf("expected url-test to keep the manual pin, got %q", urlTest.selected)
	}
}

func TestFallbackFindAliveProxyDoesNotSynchronouslyResolveLeafHostsOnIOS(t *testing.T) {
	oldGOOS := outboundGroupGOOS
	oldNow := outboundGroupNow
	defer func() {
		outboundGroupGOOS = oldGOOS
		outboundGroupNow = oldNow
		proxyLeafReachabilityCache = sync.Map{}
	}()

	outboundGroupGOOS = "ios"
	outboundGroupNow = time.Now
	proxyLeafReachabilityCache = sync.Map{}

	first := newStubProxy("first", "first.example:443", C.Trojan, true, 5)
	second := newStubProxy("second", "second.example:443", C.Trojan, true, 50)

	fallback := &Fallback{
		GroupBase: NewGroupBase(GroupBaseOption{
			BaseOption: outbound.BaseOption{Name: "fallback", Type: C.Fallback},
			providers:  []types.ProxyProvider{stubProxyProvider{proxies: []C.Proxy{first, second}}},
		}),
	}

	if got := fallback.findAliveProxy(false); got.Name() != "first" {
		t.Fatalf("expected fallback to keep first alive proxy without synchronous DNS, got %s", got.Name())
	}
}

func TestFallbackDialFailureSkipsUnreachableProxyOnIOS(t *testing.T) {
	oldGOOS := outboundGroupGOOS
	oldNow := outboundGroupNow
	defer func() {
		outboundGroupGOOS = oldGOOS
		outboundGroupNow = oldNow
		proxyLeafReachabilityCache = sync.Map{}
	}()

	outboundGroupGOOS = "ios"
	outboundGroupNow = time.Now
	proxyLeafReachabilityCache = sync.Map{}

	bad := newStubProxy("bad", "bad.example:443", C.Trojan, true, 5)
	bad.dialErr = errors.New("dns resolve failed: couldn't find ip")
	good := newStubProxy("good", "good.example:443", C.Trojan, true, 50)

	fallback := &Fallback{
		GroupBase: NewGroupBase(GroupBaseOption{
			BaseOption: outbound.BaseOption{Name: "fallback", Type: C.Fallback},
			providers:  []types.ProxyProvider{stubProxyProvider{proxies: []C.Proxy{bad, good}}},
		}),
	}

	conn, err := fallback.DialContext(context.Background(), &C.Metadata{})
	if err != nil {
		t.Fatalf("expected fallback to retry the DNS-unreachable first proxy on iOS: %v", err)
	}
	_ = conn.Close()

	if got := fallback.findAliveProxy(false); got.Name() != "good" {
		t.Fatalf("expected fallback to skip the failed DNS-unreachable proxy, got %s", got.Name())
	}
}

func TestFallbackDialRetriesNextProxyOnTransientIOSFailure(t *testing.T) {
	oldGOOS := outboundGroupGOOS
	oldNow := outboundGroupNow
	defer func() {
		outboundGroupGOOS = oldGOOS
		outboundGroupNow = oldNow
		proxyLeafDialFailureCache = sync.Map{}
		proxyLeafReachabilityCache = sync.Map{}
	}()

	outboundGroupGOOS = "ios"
	outboundGroupNow = time.Now
	proxyLeafDialFailureCache = sync.Map{}
	proxyLeafReachabilityCache = sync.Map{}

	bad := newStubProxy("bad", "bad.example:443", C.Trojan, true, 5)
	bad.dialErr = errors.New("connect failed: i/o timeout")
	good := newStubProxy("good", "good.example:443", C.Trojan, true, 50)

	fallback := &Fallback{
		GroupBase: NewGroupBase(GroupBaseOption{
			BaseOption: outbound.BaseOption{Name: "fallback", Type: C.Fallback},
			providers:  []types.ProxyProvider{stubProxyProvider{proxies: []C.Proxy{bad, good}}},
		}),
	}

	conn, err := fallback.DialContext(context.Background(), &C.Metadata{})
	if err != nil {
		t.Fatalf("expected fallback to retry a transient iOS dial failure on the next proxy: %v", err)
	}
	_ = conn.Close()

	if got := bad.dialCount.Load(); got != 1 {
		t.Fatalf("expected failed proxy to be tried once, got %d", got)
	}
	if got := good.dialCount.Load(); got != 1 {
		t.Fatalf("expected fallback proxy to be tried once, got %d", got)
	}
	if got := fallback.findAliveProxy(false); got.Name() != "good" {
		t.Fatalf("expected fallback to keep the successful fallback proxy, got %s", got.Name())
	}
}

func TestFallbackManualPinRetriesAwayFromFailedSelectedProxyOnIOS(t *testing.T) {
	oldGOOS := outboundGroupGOOS
	oldNow := outboundGroupNow
	defer func() {
		outboundGroupGOOS = oldGOOS
		outboundGroupNow = oldNow
		proxyLeafDialFailureCache = sync.Map{}
	}()

	outboundGroupGOOS = "ios"
	outboundGroupNow = time.Now
	proxyLeafDialFailureCache = sync.Map{}

	manual := newStubProxy("manual", "manual.example:443", C.Trojan, true, 5)
	manual.dialErr = errors.New("connect failed: i/o timeout")
	good := newStubProxy("good", "good.example:443", C.Trojan, true, 50)

	fallback := &Fallback{
		GroupBase: NewGroupBase(GroupBaseOption{
			BaseOption: outbound.BaseOption{Name: "fallback", Type: C.Fallback},
			providers:  []types.ProxyProvider{stubProxyProvider{proxies: []C.Proxy{manual, good}}},
		}),
		selected: "manual",
	}

	conn, err := fallback.DialContext(context.Background(), &C.Metadata{})
	if err != nil {
		t.Fatalf("expected manual pin to fail over on iOS after the selected proxy fails: %v", err)
	}
	_ = conn.Close()
	if got := manual.dialCount.Load(); got != 1 {
		t.Fatalf("expected manual proxy to be tried once, got %d", got)
	}
	if got := good.dialCount.Load(); got != 1 {
		t.Fatalf("expected manual pin to retry onto another proxy, got %d", got)
	}
	if got := fallback.findAliveProxy(false); got.Name() != "good" {
		t.Fatalf("expected transiently failed manual pin to be bypassed on the fast path, got %s", got.Name())
	}
	if fallback.selected != "manual" {
		t.Fatalf("expected manual pin preference to remain stored, got %q", fallback.selected)
	}
}

func TestFallbackManualPinBypassesKnownUnreachableLeafOnIOS(t *testing.T) {
	oldGOOS := outboundGroupGOOS
	oldNow := outboundGroupNow
	defer func() {
		outboundGroupGOOS = oldGOOS
		outboundGroupNow = oldNow
		proxyLeafReachabilityCache = sync.Map{}
	}()

	outboundGroupGOOS = "ios"
	outboundGroupNow = time.Now
	proxyLeafReachabilityCache = sync.Map{}
	proxyLeafReachabilityCache.Store("manual.example", proxyLeafReachability{
		resolvable: false,
		expiresAt:  outboundGroupNow().Add(time.Second),
	})

	manual := newStubProxy("manual", "manual.example:443", C.Trojan, true, 10)
	fallbackProxy := newStubProxy("fallback", "fallback.example:443", C.Trojan, true, 100)

	fallback := &Fallback{
		GroupBase: NewGroupBase(GroupBaseOption{
			BaseOption: outbound.BaseOption{Name: "fallback", Type: C.Fallback},
			providers:  []types.ProxyProvider{stubProxyProvider{proxies: []C.Proxy{manual, fallbackProxy}}},
		}),
		selected: "manual",
	}

	if got := fallback.findAliveProxy(false); got.Name() != "fallback" {
		t.Fatalf("expected fallback to bypass a transiently unreachable manual pin, got %s", got.Name())
	}
	if fallback.selected != "manual" {
		t.Fatalf("expected fallback to keep the manual pin, got %q", fallback.selected)
	}
}

func TestFallbackManualPinPreservesColdInactiveProxy(t *testing.T) {
	manual := newStubProxy("manual", "manual.example:443", C.Trojan, false, 10)
	fallbackProxy := newStubProxy("fallback", "fallback.example:443", C.Trojan, true, 100)

	fallback := &Fallback{
		GroupBase: NewGroupBase(GroupBaseOption{
			BaseOption: outbound.BaseOption{Name: "fallback", Type: C.Fallback},
			providers:  []types.ProxyProvider{stubProxyProvider{proxies: []C.Proxy{manual, fallbackProxy}}},
		}),
		selected: "manual",
	}

	if got := fallback.findAliveProxy(false); got.Name() != "manual" {
		t.Fatalf("expected fallback to preserve the manual pin during cold health-check state, got %s", got.Name())
	}
	if fallback.selected != "manual" {
		t.Fatalf("expected fallback to keep the manual pin, got %q", fallback.selected)
	}
}
