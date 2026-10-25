package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/jpillora/backoff"

	"github.com/Dreamacro/clash/common/mobilelog"
	N "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/component/nat"
	P "github.com/Dreamacro/clash/component/process"
	"github.com/Dreamacro/clash/component/resolver"
	"github.com/Dreamacro/clash/component/sniffer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
	icontext "github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/tunnel/statistic"
)

var (
	status         = newAtomicStatus(Suspend)
	tcpQueue       = make(chan C.ConnContext, 200)
	udpQueue       = make(chan C.PacketAdapter, 200)
	natTable       = nat.New()
	rules          []C.Rule
	listeners      = make(map[string]C.InboundListener)
	subRules       map[string][]C.Rule
	proxies        = make(map[string]C.Proxy)
	providers      map[string]provider.ProxyProvider
	ruleProviders  map[string]provider.RuleProvider
	sniffingEnable = false
	configMux      sync.RWMutex

	// Outbound Rule
	mode = Rule

	// default timeout for UDP session
	udpTimeout = 60 * time.Second

	findProcessMode P.FindProcessMode

	fakeIPRange netip.Prefix
)

const iosTunRuleResolveTimeout = 250 * time.Millisecond

const (
	defaultDialRetryAttempts = 10
	iosTunDialRetryAttempts  = 1
	defaultDialRetryMaxWait  = 1 * time.Second
	iosTunDialRetryMaxWait   = 120 * time.Millisecond
)

var (
	tunnelGOOS                   = runtime.GOOS
	iosTunFlowDiagnosticsEnabled = false
	retryAfter                   = time.After
	resolveIP                    = resolver.ResolveIP
)

func SetIOSTunFlowDiagnosticsEnabled(enabled bool) {
	iosTunFlowDiagnosticsEnabled = enabled
	statistic.SetTrackerLifecycleDiagnosticsEnabled(enabled)
}

func OnSuspend() {
	status.Store(Suspend)
}

func OnInnerLoading() {
	status.Store(Inner)
}

func OnRunning() {
	status.Store(Running)
}

func Status() TunnelStatus {
	return status.Load()
}

func SetFakeIPRange(p netip.Prefix) {
	fakeIPRange = p
}

func FakeIPRange() netip.Prefix {
	return fakeIPRange
}

func SetSniffing(b bool) {
	if sniffer.Dispatcher.Enable() {
		configMux.Lock()
		sniffingEnable = b
		configMux.Unlock()
	}
}

func IsSniffing() bool {
	return sniffingEnable
}

func init() {
	go process()
}

// TCPIn return fan-in queue
func TCPIn() chan<- C.ConnContext {
	return tcpQueue
}

// UDPIn return fan-in udp queue
func UDPIn() chan<- C.PacketAdapter {
	return udpQueue
}

// NatTable return nat table
func NatTable() C.NatTable {
	return natTable
}

// Rules return all rules
func Rules() []C.Rule {
	return rules
}

func Listeners() map[string]C.InboundListener {
	return listeners
}

// UpdateRules handle update rules
func UpdateRules(newRules []C.Rule, newSubRule map[string][]C.Rule, rp map[string]provider.RuleProvider) {
	configMux.Lock()
	rules = newRules
	ruleProviders = rp
	subRules = newSubRule
	configMux.Unlock()
}

// Proxies return all proxies
func Proxies() map[string]C.Proxy {
	return proxies
}

// Providers return all compatible providers
func Providers() map[string]provider.ProxyProvider {
	return providers
}

// RuleProviders return all loaded rule providers
func RuleProviders() map[string]provider.RuleProvider {
	return ruleProviders
}

// UpdateProxies handle update proxies
func UpdateProxies(newProxies map[string]C.Proxy, newProviders map[string]provider.ProxyProvider) {
	configMux.Lock()
	proxies = newProxies
	providers = newProviders
	configMux.Unlock()
}

func UpdateListeners(newListeners map[string]C.InboundListener) {
	configMux.Lock()
	defer configMux.Unlock()
	listeners = newListeners
}

func UpdateSniffer(dispatcher *sniffer.SnifferDispatcher) {
	configMux.Lock()
	sniffer.Dispatcher = dispatcher
	sniffingEnable = dispatcher.Enable()
	configMux.Unlock()
}

// Mode return current mode
func Mode() TunnelMode {
	return mode
}

// SetMode change the mode of tunnel
func SetMode(m TunnelMode) {
	mode = m
}

// SetFindProcessMode replace SetAlwaysFindProcess
// always find process info if legacyAlways = true or mode.Always() = true, may be increase many memory
func SetFindProcessMode(mode P.FindProcessMode) {
	findProcessMode = mode
}

func isHandle(t C.Type) bool {
	status := status.Load()
	if status == Running {
		return true
	}
	if status != Inner {
		return false
	}
	if t == C.INNER {
		return true
	}
	return tunnelGOOS == "ios" && t == C.TUN
}

// processUDP starts a loop to handle udp packet
func processUDP() {
	queue := udpQueue
	for conn := range queue {
		if !isHandle(conn.Metadata().Type) {
			conn.Drop()
			continue
		}
		handleUDPConn(conn)
	}
}

func process() {
	numUDPWorkers := 4
	if num := runtime.GOMAXPROCS(0); num > numUDPWorkers {
		numUDPWorkers = num
	}
	for i := 0; i < numUDPWorkers; i++ {
		go processUDP()
	}

	queue := tcpQueue
	for conn := range queue {
		logTCPQueueMaybe("dequeued", conn)
		if !isHandle(conn.Metadata().Type) {
			logTCPQueueMaybe("dropped_before_handle", conn)
			_ = conn.Conn().Close()
			continue
		}
		go handleTCPConn(conn)
	}
}

func needLookupIP(metadata *C.Metadata) bool {
	return resolver.MappingEnabled() && metadata.Host == "" && metadata.DstIP.IsValid()
}

func preHandleMetadata(metadata *C.Metadata) error {
	// handle IP string on host
	if ip, err := netip.ParseAddr(metadata.Host); err == nil {
		metadata.DstIP = ip
		metadata.Host = ""
	}

	// preprocess enhanced-mode metadata
	if needLookupIP(metadata) {
		host, exist := resolver.FindHostByIP(metadata.DstIP)
		if exist {
			metadata.Host = host
			metadata.DNSMode = C.DNSMapping
			if resolver.FakeIPEnabled() {
				metadata.DstIP = netip.Addr{}
				metadata.DNSMode = C.DNSFakeIP
			} else if node, ok := resolver.DefaultHosts.Search(host, false); ok {
				// redir-host should lookup the hosts
				metadata.DstIP, _ = node.RandIP()
			} else if node != nil && node.IsDomain {
				metadata.Host = node.Domain
			}
		} else if resolver.IsFakeIP(metadata.DstIP) {
			return fmt.Errorf("fake DNS record %s missing", metadata.DstIP)
		}
	} else if node, ok := resolver.DefaultHosts.Search(metadata.Host, true); ok {
		// try use domain mapping
		metadata.Host = node.Domain
	}

	return nil
}

func resolveMetadata(ctx C.PlainContext, metadata *C.Metadata) (proxy C.Proxy, rule C.Rule, err error) {
	if metadata.SpecialProxy != "" {
		var exist bool
		proxy, exist = proxies[metadata.SpecialProxy]
		if !exist {
			err = fmt.Errorf("proxy %s not found", metadata.SpecialProxy)
		}
		return
	}

	switch mode {
	case Direct:
		proxy = proxies["DIRECT"]
	case Global:
		proxy = proxies["GLOBAL"]
	// Rule
	default:
		proxy, rule, err = match(metadata)
	}
	return
}

func handleUDPConn(packet C.PacketAdapter) {
	metadata := packet.Metadata()
	if !metadata.Valid() {
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}

	// make a fAddr if request ip is fakeip
	var fAddr netip.Addr
	if resolver.IsExistFakeIP(metadata.DstIP) {
		fAddr = metadata.DstIP
	}

	if err := preHandleMetadata(metadata); err != nil {
		log.Debugln("[Metadata PreHandle] error: %s", err)
		return
	}

	if err := resolveUDPMetadata(metadata); err != nil {
		log.Debugln("[UDP] resolve metadata failed: %s", err.Error())
		return
	}

	key := packet.LocalAddr().String()

	handle := func() bool {
		pc := natTable.Get(key)
		if pc != nil {
			_ = handleUDPToRemote(packet, pc, metadata)
			return true
		}
		return false
	}

	if handle() {
		return
	}

	lockKey := key + "-lock"
	cond, loaded := natTable.GetOrCreateLock(lockKey)

	go func() {
		if loaded {
			cond.L.Lock()
			cond.Wait()
			handle()
			cond.L.Unlock()
			return
		}

		defer func() {
			natTable.Delete(lockKey)
			cond.Broadcast()
		}()

		pCtx := icontext.NewPacketConnContext(metadata)
		proxy, rule, err := resolveMetadata(pCtx, metadata)
		if err != nil {
			log.Warnln("[UDP] Parse metadata failed: %s", err.Error())
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), C.DefaultUDPTimeout)
		defer cancel()
		rawPc, err := retry(ctx, metadata, func(ctx context.Context) (C.PacketConn, error) {
			return proxy.ListenPacketContext(ctx, metadata.Pure())
		}, func(err error) {
			if rule == nil {
				log.Warnln(
					"[UDP] dial %s %s --> %s error: %s",
					proxy.Name(),
					metadata.SourceDetail(),
					metadata.RemoteAddress(),
					err.Error(),
				)
			} else {
				log.Warnln("[UDP] dial %s (match %s/%s) %s --> %s error: %s", proxy.Name(), rule.RuleType().String(), rule.Payload(), metadata.SourceDetail(), metadata.RemoteAddress(), err.Error())
			}
		})
		if err != nil {
			return
		}
		pCtx.InjectPacketConn(rawPc)

		pc := statistic.NewUDPTracker(rawPc, statistic.DefaultManager, metadata, rule, 0, 0)
		recordRouteDecision("udp", metadata, rule, proxy, rawPc.Chains(), 0, 0)

		switch true {
		case metadata.SpecialProxy != "":
			log.Infoln("[UDP] %s --> %s using %s", metadata.SourceDetail(), metadata.RemoteAddress(), metadata.SpecialProxy)
		case rule != nil:
			if rule.Payload() != "" {
				log.Infoln("[UDP] %s --> %s match %s using %s", metadata.SourceDetail(), metadata.RemoteAddress(), fmt.Sprintf("%s(%s)", rule.RuleType().String(), rule.Payload()), rawPc.Chains().String())
			} else {
				log.Infoln("[UDP] %s --> %s match %s using %s", metadata.SourceDetail(), metadata.RemoteAddress(), rule.Payload(), rawPc.Chains().String())
			}
		case mode == Global:
			log.Infoln("[UDP] %s --> %s using GLOBAL", metadata.SourceDetail(), metadata.RemoteAddress())
		case mode == Direct:
			log.Infoln("[UDP] %s --> %s using DIRECT", metadata.SourceDetail(), metadata.RemoteAddress())
		default:
			log.Infoln("[UDP] %s --> %s doesn't match any rule using DIRECT", metadata.SourceDetail(), metadata.RemoteAddress())
		}

		oAddr := metadata.DstIP
		natTable.Set(key, pc)

		go handleUDPToLocal(packet, pc, key, oAddr, fAddr)

		handle()
	}()
}

func handleTCPConn(connCtx C.ConnContext) {
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(connCtx.Conn())

	logTCPQueueMaybe("handling", connCtx)
	metadata := connCtx.Metadata()
	if !metadata.Valid() {
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}

	if err := preHandleMetadata(metadata); err != nil {
		log.Debugln("[Metadata PreHandle] error: %s", err)
		return
	}
	logIostunTCPStageMaybe(metadata, "pre-handle metadata completed")

	conn := connCtx.Conn()
	conn.ResetPeeked() // reset before sniffer
	if sniffer.Dispatcher.Enable() && sniffingEnable {
		if shouldUseNonBlockingSniff(metadata) {
			sniffer.Dispatcher.TCPSniffAvailable(conn, metadata)
		} else {
			sniffer.Dispatcher.TCPSniff(conn, metadata)
		}
	}

	peekMutex := sync.Mutex{}
	asyncPeekStarted := false
	if !conn.Peeked() && !shouldSkipIOSTunnelAsyncPeek(metadata) {
		asyncPeekStarted = true
		peekMutex.Lock()
		go func() {
			defer peekMutex.Unlock()
			logIostunTCPStageMaybe(metadata, "async peek warmup started")
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			_, _ = conn.Peek(1)
			_ = conn.SetReadDeadline(time.Time{})
			logIostunTCPStageMaybe(metadata, "async peek warmup finished")
		}()
	} else if !conn.Peeked() {
		logIostunTCPStageMaybe(metadata, "skipping async peek warmup on iOS tun")
	}

	logIostunTCPStageMaybe(metadata, "resolving metadata")
	resolveStartedAt := time.Now()
	proxy, rule, err := resolveMetadata(connCtx, metadata)
	if err != nil {
		log.Warnln("[Metadata] parse failed: %s", err.Error())
		return
	}
	logIostunTCPResolvedMaybe(metadata, proxy, rule)
	logIostunTCPStagefMaybe(metadata, "resolve metadata finished durationMs=%d", time.Since(resolveStartedAt).Milliseconds())

	dialMetadata := metadata
	if len(metadata.Host) > 0 {
		if node, ok := resolver.DefaultHosts.Search(metadata.Host, false); ok {
			if dstIp, _ := node.RandIP(); !FakeIPRange().Contains(dstIp) {
				dialMetadata.DstIP = dstIp
				dialMetadata.DNSMode = C.DNSHosts
				dialMetadata = dialMetadata.Pure()
			}
		}
	}

	var peekBytes []byte
	var peekLen int

	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTCPTimeout)
	defer cancel()
	attempt := 0
	remoteConn, err := retry(ctx, metadata, func(ctx context.Context) (remoteConn C.Conn, err error) {
		attempt++
		logIostunTCPStagefMaybe(metadata, "dial attempt=%d proxy=%s target=%s", attempt, proxy.Name(), dialMetadata.RemoteAddress())
		remoteConn, err = proxy.DialContext(ctx, dialMetadata)
		if err != nil {
			return
		}
		logIostunTCPStagefMaybe(metadata, "dial completed attempt=%d proxy=%s needHandshake=%t chain=%s", attempt, proxy.Name(), N.NeedHandshake(remoteConn), remoteConn.Chains().String())

		if N.NeedHandshake(remoteConn) {
			defer func() {
				for _, chain := range remoteConn.Chains() {
					if chain == "REJECT" {
						err = nil
						return
					}
				}
				if err != nil {
					remoteConn = nil
				}
			}()
			bufferedLen := conn.Buffered()
			logIostunTCPStagefMaybe(metadata, "handshake preparing buffered=%d asyncPeekStarted=%t peeked=%t", bufferedLen, asyncPeekStarted, conn.Peeked())
			if asyncPeekStarted {
				logIostunTCPStageMaybe(metadata, "handshake waiting for async peek warmup")
				peekMutex.Lock()
				defer peekMutex.Unlock()
				logIostunTCPStagefMaybe(metadata, "handshake resumed after async peek buffered=%d", conn.Buffered())
			}

			bufferedLen = conn.Buffered()
			if bufferedLen == 0 {
				logIostunTCPStageMaybe(metadata, "handshake continuing without buffered client bytes")
				return
			}

			peekBytes, _ = conn.Peek(bufferedLen)
			_, err = remoteConn.Write(peekBytes)
			if err != nil {
				return
			}
			if peekLen = len(peekBytes); peekLen > 0 {
				_, _ = conn.Discard(peekLen)
			}
			logIostunTCPStagefMaybe(metadata, "handshake forwarded buffered client bytes=%d", peekLen)
		}
		return
	}, func(err error) {
		logIostunTCPStagefMaybe(metadata, "dial attempt=%d failed err=%s", attempt, err.Error())
		if rule == nil {
			log.Warnln(
				"[TCP] dial %s %s --> %s error: %s",
				proxy.Name(),
				metadata.SourceDetail(),
				metadata.RemoteAddress(),
				err.Error(),
			)
		} else {
			log.Warnln("[TCP] dial %s (match %s/%s) %s --> %s error: %s", proxy.Name(), rule.RuleType().String(), rule.Payload(), metadata.SourceDetail(), metadata.RemoteAddress(), err.Error())
		}
	})
	if err != nil {
		return
	}

	logIostunTCPStagefMaybe(metadata, "creating tcp tracker peekBytes=%d chain=%s", peekLen, remoteConn.Chains().String())
	recordRouteDecision("tcp", metadata, rule, proxy, remoteConn.Chains(), 0, int64(peekLen))
	remoteConn = statistic.NewTCPTracker(remoteConn, statistic.DefaultManager, metadata, rule, 0, int64(peekLen))
	defer func(remoteConn C.Conn) {
		_ = remoteConn.Close()
	}(remoteConn)

	switch true {
	case metadata.SpecialProxy != "":
		log.Infoln("[TCP] %s --> %s using %s", metadata.SourceDetail(), metadata.RemoteAddress(), metadata.SpecialProxy)
	case rule != nil:
		if rule.Payload() != "" {
			log.Infoln("[TCP] %s --> %s match %s using %s", metadata.SourceDetail(), metadata.RemoteAddress(), fmt.Sprintf("%s(%s)", rule.RuleType().String(), rule.Payload()), remoteConn.Chains().String())
		} else {
			log.Infoln("[TCP] %s --> %s match %s using %s", metadata.SourceDetail(), metadata.RemoteAddress(), rule.RuleType().String(), remoteConn.Chains().String())
		}
	case mode == Global:
		log.Infoln("[TCP] %s --> %s using GLOBAL", metadata.SourceDetail(), metadata.RemoteAddress())
	case mode == Direct:
		log.Infoln("[TCP] %s --> %s using DIRECT", metadata.SourceDetail(), metadata.RemoteAddress())
	default:
		log.Infoln(
			"[TCP] %s --> %s doesn't match any rule using DIRECT",
			metadata.SourceDetail(),
			metadata.RemoteAddress(),
		)
	}

	_ = conn.SetReadDeadline(time.Now()) // stop unfinished peek
	peekMutex.Lock()
	defer peekMutex.Unlock()
	_ = conn.SetReadDeadline(time.Time{}) // reset
	logIostunTCPStageMaybe(metadata, "starting socket relay")
	handleSocket(connCtx, remoteConn)
}

func logTCPQueueMaybe(event string, connCtx C.ConnContext) {
	if !shouldLogIOSTunFlowDiagnostics() || connCtx == nil {
		return
	}

	metadata := connCtx.Metadata()
	if metadata == nil || metadata.Type != C.TUN {
		return
	}

	mobilelog.Native(
		"debug",
		fmt.Sprintf(
			"tunnel %s tcp stream status=%s source=%s target=%s",
			event,
			Status().String(),
			metadata.SourceDetail(),
			metadata.RemoteAddress(),
		),
	)
}

func shouldSkipIOSTunnelAsyncPeek(metadata *C.Metadata) bool {
	return tunnelGOOS == "ios" && metadata != nil && metadata.Type == C.TUN
}

func shouldUseNonBlockingSniff(metadata *C.Metadata) bool {
	return tunnelGOOS == "ios" && metadata != nil && metadata.Type == C.TUN
}

func shouldLogIOSTunFlowDiagnostics() bool {
	return tunnelGOOS == "ios" && iosTunFlowDiagnosticsEnabled && log.Level() <= log.DEBUG
}

func logIostunTCPStageMaybe(metadata *C.Metadata, stage string) {
	if !shouldLogIOSTunFlowDiagnostics() || metadata == nil || metadata.Type != C.TUN {
		return
	}

	mobilelog.Native(
		"debug",
		fmt.Sprintf(
			"tunnel tcp stage=%s source=%s target=%s",
			stage,
			metadata.SourceDetail(),
			metadata.RemoteAddress(),
		),
	)
}

func logIostunTCPStagefMaybe(metadata *C.Metadata, format string, args ...any) {
	if !shouldLogIOSTunFlowDiagnostics() || metadata == nil || metadata.Type != C.TUN {
		return
	}
	logIostunTCPStageMaybe(metadata, fmt.Sprintf(format, args...))
}

func logIostunTCPResolvedMaybe(metadata *C.Metadata, proxy C.Proxy, rule C.Rule) {
	if !shouldLogIOSTunFlowDiagnostics() || metadata == nil || metadata.Type != C.TUN || proxy == nil {
		return
	}

	ruleDesc := "none"
	if rule != nil {
		ruleDesc = rule.RuleType().String()
		if payload := rule.Payload(); payload != "" {
			ruleDesc = fmt.Sprintf("%s(%s)", ruleDesc, payload)
		}
	}

	mobilelog.Native(
		"debug",
		fmt.Sprintf(
			"tunnel tcp stage=resolved proxy=%s rule=%s source=%s target=%s",
			proxy.Name(),
			ruleDesc,
			metadata.SourceDetail(),
			metadata.RemoteAddress(),
		),
	)
}

func shouldResolveIP(rule C.Rule, metadata *C.Metadata) bool {
	if !rule.ShouldResolveIP() || metadata.Host == "" || metadata.DstIP.IsValid() {
		return false
	}

	// iOS Packet Tunnel should route Fake DNS-restored domain traffic without
	// blocking the hot path on external DNS. IP-only rules can still match
	// when metadata already carries a real destination IP.
	if tunnelGOOS == "ios" && metadata.Type == C.TUN {
		return false
	}

	return true
}

func ruleResolveTimeout(metadata *C.Metadata) time.Duration {
	if tunnelGOOS == "ios" && metadata != nil && metadata.Type == C.TUN {
		return iosTunRuleResolveTimeout
	}

	return resolver.DefaultDNSTimeout
}

func udpResolveTimeout(metadata *C.Metadata) time.Duration {
	if tunnelGOOS == "ios" && metadata != nil && metadata.Type == C.TUN {
		return ruleResolveTimeout(metadata)
	}

	return resolver.DefaultDNSTimeout
}

func resolveUDPMetadata(metadata *C.Metadata) error {
	if metadata == nil || metadata.Resolved() {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), udpResolveTimeout(metadata))
	defer cancel()

	ip, err := resolveIP(ctx, metadata.Host)
	if err != nil {
		return err
	}
	metadata.DstIP = ip
	return nil
}

func match(metadata *C.Metadata) (C.Proxy, C.Rule, error) {
	configMux.RLock()
	defer configMux.RUnlock()
	var (
		resolved     bool
		processFound bool
	)

	if node, ok := resolver.DefaultHosts.Search(metadata.Host, false); ok {
		metadata.DstIP, _ = node.RandIP()
		resolved = true
	}

	for _, rule := range getRules(metadata) {
		if !resolved && shouldResolveIP(rule, metadata) {
			func() {
				ctx, cancel := context.WithTimeout(context.Background(), ruleResolveTimeout(metadata))
				defer cancel()
				ip, err := resolver.ResolveIP(ctx, metadata.Host)
				if err != nil {
					log.Debugln("[DNS] resolve %s error: %s", metadata.Host, err.Error())
				} else {
					log.Debugln("[DNS] %s --> %s", metadata.Host, ip.String())
					metadata.DstIP = ip
				}
				resolved = true
			}()
		}

		if !findProcessMode.Off() && !processFound && (findProcessMode.Always() || rule.ShouldFindProcess()) {
			srcPort, err := strconv.ParseUint(metadata.SrcPort, 10, 16)
			uid, path, err := P.FindProcessName(metadata.NetWork.String(), metadata.SrcIP, int(srcPort))
			if err != nil {
				log.Debugln("[Process] find process %s: %v", metadata.String(), err)
			} else {
				metadata.Process = filepath.Base(path)
				metadata.ProcessPath = path
				metadata.Uid = uid
				processFound = true
			}
		}

		if matched, ada := rule.Match(metadata); matched {
			adapter, ok := proxies[ada]
			if !ok {
				continue
			}

			if adapter.Type() == C.Pass {
				log.Debugln("%s match Pass rule", adapter.Name())
				continue
			}

			if metadata.NetWork == C.UDP && !adapter.SupportUDP() {
				log.Debugln("%s UDP is not supported", adapter.Name())
				continue
			}

			return adapter, rule, nil
		}
	}

	return proxies["DIRECT"], nil, nil
}

func getRules(metadata *C.Metadata) []C.Rule {
	if sr, ok := subRules[metadata.SpecialRules]; ok {
		log.Debugln("[Rule] use %s rules", metadata.SpecialRules)
		return sr
	} else {
		log.Debugln("[Rule] use default rules")
		return rules
	}
}

func retry[T any](ctx context.Context, metadata *C.Metadata, ft func(context.Context) (T, error), fe func(err error)) (t T, err error) {
	b := &backoff.Backoff{
		Min:    10 * time.Millisecond,
		Max:    dialRetryMaxWait(metadata),
		Factor: 2,
		Jitter: true,
	}
	maxAttempts := dialRetryAttempts(metadata)
	for i := 0; i < maxAttempts; i++ {
		t, err = ft(ctx)
		if err != nil {
			if fe != nil {
				fe(err)
			}
			if i == maxAttempts-1 {
				break
			}
			select {
			case <-retryAfter(b.Duration()):
				continue
			case <-ctx.Done():
				return
			}
		} else {
			break
		}
	}
	return
}

func dialRetryAttempts(metadata *C.Metadata) int {
	if tunnelGOOS == "ios" && metadata != nil && metadata.Type == C.TUN {
		return iosTunDialRetryAttempts
	}
	return defaultDialRetryAttempts
}

func dialRetryMaxWait(metadata *C.Metadata) time.Duration {
	if tunnelGOOS == "ios" && metadata != nil && metadata.Type == C.TUN {
		return iosTunDialRetryMaxWait
	}
	return defaultDialRetryMaxWait
}
