package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/component/dialer"
	P "github.com/Dreamacro/clash/component/process"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

type resolveIPRule struct{}

func (resolveIPRule) RuleType() C.RuleType                      { return C.IPCIDR }
func (resolveIPRule) Match(metadata *C.Metadata) (bool, string) { return false, "" }
func (resolveIPRule) Adapter() string                           { return "" }
func (resolveIPRule) Payload() string                           { return "" }
func (resolveIPRule) ShouldResolveIP() bool                     { return true }
func (resolveIPRule) ShouldFindProcess() bool                   { return false }

type matchRule struct {
	adapter string
}

func (r matchRule) RuleType() C.RuleType                      { return C.MATCH }
func (r matchRule) Match(metadata *C.Metadata) (bool, string) { return true, r.adapter }
func (r matchRule) Adapter() string                           { return r.adapter }
func (r matchRule) Payload() string                           { return "" }
func (r matchRule) ShouldResolveIP() bool                     { return false }
func (r matchRule) ShouldFindProcess() bool                   { return false }

type unwrapPanicProxy struct {
	*outbound.Base
}

func newUnwrapPanicProxy(name string) *unwrapPanicProxy {
	return &unwrapPanicProxy{
		Base: outbound.NewBase(outbound.BaseOption{
			Name: name,
			Type: C.URLTest,
			UDP:  true,
		}),
	}
}

func (p *unwrapPanicProxy) Alive() bool                    { return true }
func (p *unwrapPanicProxy) DelayHistory() []C.DelayHistory { return nil }
func (p *unwrapPanicProxy) LastDelay() uint16              { return 1 }
func (p *unwrapPanicProxy) URLTest(ctx context.Context, url string) (uint16, error) {
	return 1, nil
}
func (p *unwrapPanicProxy) Dial(metadata *C.Metadata) (C.Conn, error) {
	return nil, errors.New("not implemented")
}
func (p *unwrapPanicProxy) DialUDP(metadata *C.Metadata) (C.PacketConn, error) {
	return nil, errors.New("not implemented")
}
func (p *unwrapPanicProxy) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	panic("match must not unwrap dynamic proxy groups")
}
func (p *unwrapPanicProxy) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	return nil, errors.New("not implemented")
}
func (p *unwrapPanicProxy) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	return nil, errors.New("not implemented")
}
func (p *unwrapPanicProxy) StreamConn(conn net.Conn, metadata *C.Metadata) (net.Conn, error) {
	return nil, errors.New("not implemented")
}
func (p *unwrapPanicProxy) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"type": p.Type().String(),
	})
}

func TestIsHandleAllowsIOSTunDuringInner(t *testing.T) {
	originalGOOS := tunnelGOOS
	originalStatus := status.Load()
	t.Cleanup(func() {
		tunnelGOOS = originalGOOS
		status.Store(originalStatus)
	})

	tunnelGOOS = "ios"
	status.Store(Inner)

	if !isHandle(C.TUN) {
		t.Fatal("expected iOS TUN traffic to be handled during inner startup")
	}
	if !isHandle(C.INNER) {
		t.Fatal("expected inner traffic to keep flowing during inner startup")
	}
	if isHandle(C.HTTP) {
		t.Fatal("expected non-TUN traffic to remain blocked during inner startup")
	}
}

func TestRuleResolveTimeoutUsesIOSTunTimeout(t *testing.T) {
	originalGOOS := tunnelGOOS
	t.Cleanup(func() {
		tunnelGOOS = originalGOOS
	})

	tunnelGOOS = "ios"

	timeout := ruleResolveTimeout(&C.Metadata{Type: C.TUN})
	if timeout != iosTunRuleResolveTimeout {
		t.Fatalf("expected iOS tun timeout %s, got %s", iosTunRuleResolveTimeout, timeout)
	}

	if got := ruleResolveTimeout(&C.Metadata{Type: C.HTTP}); got != resolver.DefaultDNSTimeout {
		t.Fatalf("expected non-TUN timeout to stay at resolver default, got %s", got)
	}
}

func TestRuleResolveTimeoutKeepsIOSTunFastPathBelowInteractiveBudget(t *testing.T) {
	originalGOOS := tunnelGOOS
	t.Cleanup(func() {
		tunnelGOOS = originalGOOS
	})

	tunnelGOOS = "ios"

	timeout := ruleResolveTimeout(&C.Metadata{Type: C.TUN})
	const maxInteractiveDNSBudget = 300 * time.Millisecond
	if timeout > maxInteractiveDNSBudget {
		t.Fatalf("expected iOS TUN rule DNS timeout to stay below %s, got %s", maxInteractiveDNSBudget, timeout)
	}
}

func TestShouldResolveIPSkipsSynchronousDNSForIOSTunDomainTraffic(t *testing.T) {
	originalGOOS := tunnelGOOS
	t.Cleanup(func() {
		tunnelGOOS = originalGOOS
	})

	tunnelGOOS = "ios"

	metadata := &C.Metadata{
		Type: C.TUN,
		Host: "www.google.com",
	}

	if shouldResolveIP(resolveIPRule{}, metadata) {
		t.Fatal("expected iOS TUN domain traffic to skip synchronous rule DNS resolution")
	}
}

func TestMatchDoesNotUnwrapDynamicProxyGroupsForPassCheck(t *testing.T) {
	originalRules := rules
	originalSubRules := subRules
	originalProxies := proxies
	originalFindProcessMode := findProcessMode
	t.Cleanup(func() {
		UpdateRules(originalRules, originalSubRules, nil)
		UpdateProxies(originalProxies, nil)
		SetFindProcessMode(originalFindProcessMode)
	})

	group := adapter.NewProxy(newUnwrapPanicProxy("auto"))
	UpdateRules([]C.Rule{matchRule{adapter: "auto"}}, nil, nil)
	UpdateProxies(map[string]C.Proxy{
		"auto":   group,
		"DIRECT": adapter.NewProxy(outbound.NewDirect()),
	}, nil)
	SetFindProcessMode(P.FindProcessMode(P.FindProcessOff))

	proxy, rule, err := match(&C.Metadata{
		NetWork: C.TCP,
		Type:    C.TUN,
		Host:    "www.google.com",
		DstPort: "443",
	})
	if err != nil {
		t.Fatalf("expected match to succeed: %v", err)
	}
	if rule == nil {
		t.Fatal("expected a rule match")
	}
	if proxy == nil || proxy.Name() != "auto" {
		t.Fatalf("expected dynamic proxy group to be returned without unwrapping, got %#v", proxy)
	}
}

func TestIOSTunFlowDiagnosticsRequireExplicitDebugOptIn(t *testing.T) {
	originalGOOS := tunnelGOOS
	originalEnabled := iosTunFlowDiagnosticsEnabled
	originalLogLevel := log.Level()
	t.Cleanup(func() {
		tunnelGOOS = originalGOOS
		iosTunFlowDiagnosticsEnabled = originalEnabled
		log.SetLevel(originalLogLevel)
	})

	tunnelGOOS = "ios"
	log.SetLevel(log.DEBUG)
	SetIOSTunFlowDiagnosticsEnabled(false)
	if shouldLogIOSTunFlowDiagnostics() {
		t.Fatal("expected iOS TUN flow diagnostics to stay disabled without explicit opt-in")
	}

	SetIOSTunFlowDiagnosticsEnabled(true)
	if !shouldLogIOSTunFlowDiagnostics() {
		t.Fatal("expected iOS TUN flow diagnostics to be enabled after explicit opt-in at debug log level")
	}

	log.SetLevel(log.INFO)
	if shouldLogIOSTunFlowDiagnostics() {
		t.Fatal("expected iOS TUN flow diagnostics to be disabled above debug log level")
	}
}

func TestIOSTunUsesNonBlockingSniff(t *testing.T) {
	originalGOOS := tunnelGOOS
	t.Cleanup(func() {
		tunnelGOOS = originalGOOS
	})

	tunnelGOOS = "ios"
	if !shouldUseNonBlockingSniff(&C.Metadata{Type: C.TUN}) {
		t.Fatal("expected iOS TUN TCP sniffing to avoid waiting for application payload on the route hot path")
	}
	if shouldUseNonBlockingSniff(&C.Metadata{Type: C.HTTP}) {
		t.Fatal("expected non-TUN inbound sniffing to keep the normal blocking sniff semantics")
	}

	tunnelGOOS = "darwin"
	if shouldUseNonBlockingSniff(&C.Metadata{Type: C.TUN}) {
		t.Fatal("expected non-iOS TUN sniffing to keep the normal blocking sniff semantics")
	}
}

func TestDialRetryAttemptsUseShortIOSTunInteractiveBudget(t *testing.T) {
	originalGOOS := tunnelGOOS
	t.Cleanup(func() {
		tunnelGOOS = originalGOOS
	})

	tunnelGOOS = "ios"

	if got := dialRetryAttempts(&C.Metadata{Type: C.TUN}); got != iosTunDialRetryAttempts {
		t.Fatalf("expected iOS TUN retry attempts %d, got %d", iosTunDialRetryAttempts, got)
	}
	if got := dialRetryAttempts(&C.Metadata{Type: C.TUN}); got != 1 {
		t.Fatalf("expected iOS TUN outer tunnel retry to be fail-fast because proxy groups own node failover, got %d", got)
	}
	if got := dialRetryAttempts(&C.Metadata{Type: C.HTTP}); got != defaultDialRetryAttempts {
		t.Fatalf("expected non-TUN retry attempts %d, got %d", defaultDialRetryAttempts, got)
	}
	if got := dialRetryMaxWait(&C.Metadata{Type: C.TUN}); got != iosTunDialRetryMaxWait {
		t.Fatalf("expected iOS TUN retry max wait %s, got %s", iosTunDialRetryMaxWait, got)
	}
	if got := dialRetryMaxWait(&C.Metadata{Type: C.HTTP}); got != defaultDialRetryMaxWait {
		t.Fatalf("expected non-TUN retry max wait %s, got %s", defaultDialRetryMaxWait, got)
	}

	tunnelGOOS = "darwin"
	if got := dialRetryAttempts(&C.Metadata{Type: C.TUN}); got != defaultDialRetryAttempts {
		t.Fatalf("expected non-iOS retry attempts %d, got %d", defaultDialRetryAttempts, got)
	}
	if got := dialRetryMaxWait(&C.Metadata{Type: C.TUN}); got != defaultDialRetryMaxWait {
		t.Fatalf("expected non-iOS retry max wait %s, got %s", defaultDialRetryMaxWait, got)
	}
}

func TestRetryReturnsImmediatelyAfterFinalFailedAttempt(t *testing.T) {
	originalGOOS := tunnelGOOS
	originalRetryAfter := retryAfter
	t.Cleanup(func() {
		tunnelGOOS = originalGOOS
		retryAfter = originalRetryAfter
	})

	tunnelGOOS = "ios"

	attempts := 0
	sleepCount := 0
	retryAfter = func(time.Duration) <-chan time.Time {
		sleepCount++
		ch := make(chan time.Time, 1)
		ch <- time.Now()
		return ch
	}

	errFinal := errors.New("final dial failure")
	_, err := retry(
		context.Background(),
		&C.Metadata{Type: C.TUN},
		func(context.Context) (int, error) {
			attempts++
			return 0, errFinal
		},
		nil,
	)
	if !errors.Is(err, errFinal) {
		t.Fatalf("expected final retry error, got %v", err)
	}
	if attempts != iosTunDialRetryAttempts {
		t.Fatalf("expected %d attempts, got %d", iosTunDialRetryAttempts, attempts)
	}
	if sleepCount != 0 {
		t.Fatalf("expected sleeps only between retry attempts, got %d", sleepCount)
	}
}

func TestResolveUDPMetadataUsesIOSTunInteractiveTimeout(t *testing.T) {
	originalGOOS := tunnelGOOS
	originalResolveIP := resolveIP
	t.Cleanup(func() {
		tunnelGOOS = originalGOOS
		resolveIP = originalResolveIP
	})

	tunnelGOOS = "ios"

	var observedDeadline time.Time
	resolveIP = func(ctx context.Context, host string) (netip.Addr, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("expected iOS TUN UDP resolution to carry a deadline")
		}
		observedDeadline = deadline
		return netip.MustParseAddr("8.8.8.8"), nil
	}

	metadata := &C.Metadata{
		Type:    C.TUN,
		NetWork: C.UDP,
		Host:    "dns.google",
		DstPort: "443",
	}
	startedAt := time.Now()
	if err := resolveUDPMetadata(metadata); err != nil {
		t.Fatalf("expected UDP metadata resolution to succeed: %v", err)
	}
	if !metadata.DstIP.IsValid() {
		t.Fatal("expected UDP metadata resolution to fill DstIP")
	}
	budget := observedDeadline.Sub(startedAt)
	if budget <= 0 || budget > iosTunRuleResolveTimeout+50*time.Millisecond {
		t.Fatalf("expected iOS TUN UDP DNS budget around %s, got %s", iosTunRuleResolveTimeout, budget)
	}
}

func TestRouteDecisionsUseTunnelQueueCapacityAndNewestFirst(t *testing.T) {
	resetRouteDecisionStoreForTest(t)

	proxy := adapter.NewProxy(outbound.NewDirect())
	recordRouteDecision(
		"tcp",
		&C.Metadata{
			NetWork:      C.TCP,
			Type:         C.TUN,
			SrcIP:        netip.MustParseAddr("172.31.255.1"),
			SrcPort:      "51000",
			DstIP:        netip.MustParseAddr("142.250.72.196"),
			DstPort:      "443",
			Host:         "www.google.com",
			SniffHost:    "www.google.com",
			DNSMode:      C.DNSMapping,
			DstASNLabel:  "AS15169 Google LLC",
			SpecialProxy: "",
		},
		matchRule{adapter: "GLOBAL"},
		proxy,
		C.Chain{"HK-01", "Auto", "GLOBAL"},
		12,
		34,
	)
	recordRouteDecision(
		"udp",
		&C.Metadata{
			NetWork: C.UDP,
			Type:    C.TUN,
			SrcIP:   netip.MustParseAddr("172.31.255.1"),
			SrcPort: "51001",
			DstIP:   netip.MustParseAddr("8.8.8.8"),
			DstPort: "53",
			Host:    "dns.google",
		},
		matchRule{adapter: "GLOBAL"},
		proxy,
		C.Chain{"DIRECT"},
		0,
		0,
	)

	decisions := RouteDecisions()
	if got, want := cap(routeDecisionStore.items), routeDecisionCapacity(); got != want {
		t.Fatalf("expected route decision store capacity %d, got %d", want, got)
	}
	if got, want := len(decisions), 2; got != want {
		t.Fatalf("expected %d route decisions, got %d", want, got)
	}
	if decisions[0].Network != "udp" || decisions[1].Network != "tcp" {
		t.Fatalf("expected route decisions newest first, got %#v", decisions)
	}

	tcpDecision := decisions[1]
	if tcpDecision.Host != "www.google.com" {
		t.Fatalf("expected sniffed host to be preserved, got %q", tcpDecision.Host)
	}
	if tcpDecision.DestinationIP != "142.250.72.196" || tcpDecision.DestinationPort != 443 {
		t.Fatalf("expected destination endpoint to be preserved, got %s:%d", tcpDecision.DestinationIP, tcpDecision.DestinationPort)
	}
	if tcpDecision.DestinationIPASN != "AS15169 Google LLC" {
		t.Fatalf("expected ASN label to be preserved, got %q", tcpDecision.DestinationIPASN)
	}
	if tcpDecision.MatchedRule != "Match" || tcpDecision.MatchedRuleKind != "match" {
		t.Fatalf("expected matched rule evidence to be normalized, got %s/%s", tcpDecision.MatchedRule, tcpDecision.MatchedRuleKind)
	}
	if tcpDecision.FinalNode != "HK-01" || tcpDecision.Outcome != "ruleHit" {
		t.Fatalf("expected route decision to identify the leaf node, got final=%q outcome=%q", tcpDecision.FinalNode, tcpDecision.Outcome)
	}
	if tcpDecision.ChainComponents[0] != "HK-01" || len(tcpDecision.ChainComponents) != 3 {
		t.Fatalf("expected normalized route chain, got %#v", tcpDecision.ChainComponents)
	}
}

func resetRouteDecisionStoreForTest(t *testing.T) {
	t.Helper()
	routeDecisionStore.Lock()
	routeDecisionStore.next = 0
	routeDecisionStore.items = nil
	routeDecisionStore.Unlock()
	t.Cleanup(func() {
		routeDecisionStore.Lock()
		routeDecisionStore.next = 0
		routeDecisionStore.items = nil
		routeDecisionStore.Unlock()
	})
}
