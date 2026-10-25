package executor

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/adapter/outboundgroup"
	"github.com/Dreamacro/clash/common/mobilelog"
	"github.com/Dreamacro/clash/common/mobilephase"
	"github.com/Dreamacro/clash/component/auth"
	"github.com/Dreamacro/clash/component/dialer"
	G "github.com/Dreamacro/clash/component/geodata"
	"github.com/Dreamacro/clash/component/iface"
	"github.com/Dreamacro/clash/component/mmdb"
	"github.com/Dreamacro/clash/component/profile"
	"github.com/Dreamacro/clash/component/profile/cachefile"
	"github.com/Dreamacro/clash/component/resolver"
	SNI "github.com/Dreamacro/clash/component/sniffer"
	CTLS "github.com/Dreamacro/clash/component/tls"
	"github.com/Dreamacro/clash/component/trie"
	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
	"github.com/Dreamacro/clash/dns"
	"github.com/Dreamacro/clash/listener"
	authStore "github.com/Dreamacro/clash/listener/auth"
	LC "github.com/Dreamacro/clash/listener/config"
	"github.com/Dreamacro/clash/listener/inner"
	"github.com/Dreamacro/clash/listener/tproxy"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/tunnel"
)

var (
	mux                    sync.Mutex
	routeDatabaseWarmupMux sync.Mutex
	routeDatabaseWarming   bool
)

type selectableProxyGroup interface {
	outboundgroup.SelectAble
}

func readConfig(path string) ([]byte, error) {
	mobilelog.Native("debug", "executor.readConfig is checking the config path: "+path)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("configuration file %s is empty", path)
	}

	mobilelog.Native("debug", fmt.Sprintf("executor.readConfig loaded %d bytes from %s.", len(data), path))
	return data, err
}

// Parse config with default config path
func Parse() (*config.Config, error) {
	mobilelog.Native("info", "executor.Parse is using the default config path.")
	return ParseWithPath(C.Path.Config())
}

// ParseWithPath parse config with custom config path
func ParseWithPath(path string) (*config.Config, error) {
	mobilelog.Native("info", "executor.ParseWithPath is loading config from "+path)
	buf, err := readConfig(path)
	if err != nil {
		return nil, err
	}

	mobilelog.Native("info", "executor.ParseWithPath finished reading the config file. Parsing bytes next.")
	return ParseWithBytes(buf)
}

// ParseWithBytes config with buffer
func ParseWithBytes(buf []byte) (*config.Config, error) {
	mobilelog.Native("info", fmt.Sprintf("executor.ParseWithBytes received %d bytes. Calling config.Parse.", len(buf)))
	return config.Parse(buf)
}

// ApplyConfig dispatch configure to all parts
func ApplyConfig(cfg *config.Config, force bool) {
	mux.Lock()
	defer mux.Unlock()
	defer func() {
		if r := recover(); r != nil {
			message := fmt.Sprintf("ApplyConfig panicked after updateTun: %v", r)
			mobilephase.MarkFailure("applyingConfig", message)
			mobilelog.Native("error", message)
			panic(r)
		}
	}()

	mobilephase.SetPhase("applyingConfig", "Applying runtime configuration.")
	mobilelog.Native("info", "ApplyConfig entered.")
	tunnel.OnSuspend()
	fastStartup := runtime.GOOS == "ios" && mobilephase.FastStartupEnabled()

	CTLS.ResetCertificate()
	for _, c := range cfg.TLS.CustomTrustCert {
		if err := CTLS.AddCertificate(c); err != nil {
			log.Warnln("%s\nadd error: %s", c, err.Error())
		}
	}

	updateUsers(cfg.Users)
	updateProxies(cfg.Proxies, cfg.Providers)
	updateRules(cfg.Rules, cfg.SubRules, cfg.RuleProviders)
	warmRouteDatabasesAsync(cfg)
	updateSniffer(cfg.Sniffer)
	updateHosts(cfg.Hosts)
	updateGeneral(cfg.General)
	mobilelog.Native("debug", "ApplyConfig finished updateGeneral.")
	updateDNS(cfg.DNS, cfg.General.IPv6)
	mobilelog.Native("debug", "ApplyConfig finished updateDNS.")
	updateListeners(cfg.General, cfg.Listeners, force)
	mobilelog.Native("debug", "ApplyConfig finished updateListeners.")
	updateIPTables(cfg)
	mobilephase.SetPhase("startingTun", "Creating TUN interface and preparing the data plane.")
	mobilelog.Native("info", "ApplyConfig is starting the TUN setup path.")
	updateTun(cfg.General)
	mobilelog.Native("info", "ApplyConfig returned from updateTun.")
	if cfg.General != nil && cfg.General.Tun.Enable && !listener.GetTunConf().Enable {
		mobilephase.MarkFailure("startingTun", "TUN listener did not start successfully.")
		mobilelog.Native("error", "ApplyConfig detected that the TUN listener did not enter the enabled state.")
		log.Errorln("TUN listener did not enter the enabled state after ApplyConfig")
		return
	}
	mobilelog.Native("info", "ApplyConfig confirmed that the TUN listener is enabled or not required.")
	mobilelog.Native("debug", "ApplyConfig is entering updateExperimental.")
	updateExperimental(cfg)
	mobilelog.Native("debug", "ApplyConfig returned from updateExperimental.")
	mobilelog.Native("debug", "ApplyConfig is entering updateTunnels.")
	updateTunnels(cfg.Tunnels)
	mobilelog.Native("debug", "ApplyConfig returned from updateTunnels.")

	mobilelog.Native("debug", "ApplyConfig is switching tunnel status to inner loading.")
	tunnel.OnInnerLoading()
	mobilelog.Native("debug", "ApplyConfig finished tunnel.OnInnerLoading.")

	mobilelog.Native("debug", "ApplyConfig is entering initInnerTcp.")
	initInnerTcp()
	mobilelog.Native("debug", "ApplyConfig returned from initInnerTcp.")

	if fastStartup {
		mobilelog.Native("info", "ApplyConfig is restoring stored proxy selections during iOS startup isolation.")
		restoreProfileSelections(cfg)
		mobilelog.Native("debug", "ApplyConfig returned from restoreProfileSelections.")
		mobilelog.Native("info", "ApplyConfig is skipping the non-critical updateProfile tail during iOS startup isolation.")
	} else {
		mobilelog.Native("debug", "ApplyConfig is entering updateProfile.")
		updateProfile(cfg)
		mobilelog.Native("debug", "ApplyConfig returned from updateProfile.")
	}

	mobilephase.SetPhase("finalizingStartup", "Finalizing the critical startup tail before declaring readiness.")
	mobilelog.Native("debug", "ApplyConfig entered the final startup tail before the runtime ready signal.")
	if fastStartup {
		mobilelog.Native("debug", "ApplyConfig is switching tunnel status to running on the iOS fast-start path.")
		tunnel.OnRunning()
		mobilelog.Native("debug", "ApplyConfig finished tunnel.OnRunning on the iOS fast-start path.")
		mobilelog.Native("info", "ApplyConfig is calling mobilephase.MarkCriticalReady immediately after tunnel.OnRunning.")
		mobilephase.MarkCriticalReady("Critical runtime path is ready. Deferred startup work continues in background.")
		mobilelog.Native("info", "ApplyConfig called mobilephase.MarkCriticalReady on the iOS fast-start path.")
		go func(
			applyCfg *config.Config,
			logLevel log.LogLevel,
		) {
			defer func() {
				if r := recover(); r != nil {
					mobilelog.Native("error", fmt.Sprintf("Deferred iOS fast-start tail panicked: %v", r))
				}
			}()
			mobilelog.Native("debug", "ApplyConfig is applying the configured log level on the deferred iOS fast-start path.")
			log.SetLevel(logLevel)
			mobilelog.Native("debug", "ApplyConfig applied the configured log level on the deferred iOS fast-start path.")
			mobilelog.Native("debug", "ApplyConfig is running deferred runtime.GC() on the iOS fast-start path.")
			runtime.GC()
			mobilelog.Native("debug", "ApplyConfig finished deferred runtime.GC() on the iOS fast-start path.")
			mobilelog.Native("info", "ApplyConfig is warming providers in background on the iOS fast-start path.")
			warmProvidersAsync(applyCfg)
			mobilelog.Native("info", "ApplyConfig finished deferred provider warmup on the iOS fast-start path.")
		}(cfg, cfg.General.LogLevel)
		return
	}

	mobilelog.Native("debug", "ApplyConfig is applying the configured log level.")
	log.SetLevel(cfg.General.LogLevel)
	mobilelog.Native("debug", "ApplyConfig applied the configured log level.")
	mobilelog.Native("debug", "ApplyConfig is switching tunnel status to running.")
	tunnel.OnRunning()
	mobilelog.Native("debug", "ApplyConfig finished tunnel.OnRunning.")
	mobilelog.Native("info", "ApplyConfig is warming providers synchronously.")
	warmProvidersSync(cfg)
	mobilephase.MarkRunning("Runtime is running.")
	mobilelog.Native("info", "ApplyConfig marked the runtime as running.")
}

func initInnerTcp() {
	inner.New(tunnel.TCPIn())
}

func GetGeneral() *config.General {
	ports := listener.GetPorts()
	var authenticator []string
	if auth := authStore.Authenticator(); auth != nil {
		authenticator = auth.Users()
	}

	general := &config.General{
		Inbound: config.Inbound{
			Port:              ports.Port,
			SocksPort:         ports.SocksPort,
			RedirPort:         ports.RedirPort,
			TProxyPort:        ports.TProxyPort,
			MixedPort:         ports.MixedPort,
			Tun:               listener.GetTunConf(),
			TuicServer:        listener.GetTuicConf(),
			ShadowSocksConfig: ports.ShadowSocksConfig,
			VmessConfig:       ports.VmessConfig,
			Authentication:    authenticator,
			AllowLan:          listener.AllowLan(),
			BindAddress:       listener.BindAddress(),
		},
		Mode:          tunnel.Mode(),
		LogLevel:      log.Level(),
		IPv6:          !resolver.DisableIPv6,
		GeodataLoader: G.LoaderName(),
		Interface:     dialer.DefaultInterface.Load(),
		Sniffing:      tunnel.IsSniffing(),
		TCPConcurrent: dialer.GetTcpConcurrent(),
	}

	return general
}

func updateListeners(general *config.General, listeners map[string]C.InboundListener, force bool) {
	tcpIn := tunnel.TCPIn()
	udpIn := tunnel.UDPIn()
	natTable := tunnel.NatTable()

	listener.PatchInboundListeners(listeners, tcpIn, udpIn, natTable, true)
	if !force {
		return
	}

	allowLan := general.AllowLan
	listener.SetAllowLan(allowLan)

	bindAddress := general.BindAddress
	listener.SetBindAddress(bindAddress)
	listener.ReCreateHTTP(general.Port, tcpIn)
	listener.ReCreateSocks(general.SocksPort, tcpIn, udpIn)
	listener.ReCreateRedir(general.RedirPort, tcpIn, udpIn, natTable)
	listener.ReCreateAutoRedir(general.EBpf.AutoRedir, tcpIn, udpIn)
	listener.ReCreateTProxy(general.TProxyPort, tcpIn, udpIn, natTable)
	listener.ReCreateMixed(general.MixedPort, tcpIn, udpIn)
	listener.ReCreateShadowSocks(general.ShadowSocksConfig, tcpIn, udpIn)
	listener.ReCreateVmess(general.VmessConfig, tcpIn, udpIn)
	listener.ReCreateTuic(LC.TuicServer(general.TuicServer), tcpIn, udpIn)
}

func updateExperimental(c *config.Config) {
	if runtime.GOOS == "ios" && mobilephase.FastStartupEnabled() {
		mobilelog.Native("info", "updateExperimental deferred runtime.GC() because iOS fast-start is still in the critical startup path.")
		return
	}
	runtime.GC()
}

func updateDNS(c *config.DNS, generalIPv6 bool) {
	if !c.Enable {
		mobilelog.Native("info", "updateDNS detected that DNS is disabled. Clearing resolver state.")
		resolver.DefaultResolver = nil
		resolver.ProxyServerHostResolver = nil
		resolver.DefaultHostMapper = nil
		resolver.DefaultLocalServer = nil
		dns.ReCreateServer("", nil, nil)
		return
	}

	cfg := dns.Config{
		Main:         c.NameServer,
		Fallback:     c.Fallback,
		IPv6:         c.IPv6 && generalIPv6,
		IPv6Timeout:  c.IPv6Timeout,
		EnhancedMode: c.EnhancedMode,
		Pool:         c.FakeIPRange,
		Hosts:        c.Hosts,
		FallbackFilter: dns.FallbackFilter{
			GeoIP:     c.FallbackFilter.GeoIP,
			GeoIPCode: c.FallbackFilter.GeoIPCode,
			IPCIDR:    c.FallbackFilter.IPCIDR,
			Domain:    c.FallbackFilter.Domain,
			GeoSite:   c.FallbackFilter.GeoSite,
		},
		Default:     c.DefaultNameserver,
		Policy:      c.NameServerPolicy,
		ProxyServer: c.ProxyServerNameserver,
	}

	mobilelog.Native("info", fmt.Sprintf(
		"updateDNS is building the resolver. nameserver=%d fallback=%d default=%d proxyServer=%d policy=%d",
		len(cfg.Main), len(cfg.Fallback), len(cfg.Default), len(cfg.ProxyServer), len(cfg.Policy),
	))
	mobilephase.SetPhase("applyingConfig", "Preparing DNS resolver and Fake DNS state.")
	mobilelog.Native("debug", "updateDNS is calling dns.NewResolver.")
	r := dns.NewResolver(cfg)
	mobilelog.Native("debug", "updateDNS returned from dns.NewResolver.")
	mobilelog.Native("debug", "updateDNS is calling dns.NewProxyServerHostResolver.")
	pr := dns.NewProxyServerHostResolver(r)
	if resolver.RequireEncryptedProxyServerDNS {
		candidates := append(append([]dns.NameServer(nil), c.ProxyServerNameserver...), c.DefaultNameserver...)
		pr = dns.NewIndependentProxyServerHostResolver(r, candidates)
	}
	mobilelog.Native("debug", "updateDNS returned from dns.NewProxyServerHostResolver.")
	mobilelog.Native("debug", "updateDNS is calling dns.NewEnhancer.")
	m := dns.NewEnhancer(cfg)
	mobilelog.Native("debug", "updateDNS returned from dns.NewEnhancer.")

	// reuse cache of old host mapper
	if old := resolver.DefaultHostMapper; old != nil {
		mobilelog.Native("debug", "updateDNS is patching the new enhancer from the existing host mapper.")
		m.PatchFrom(old.(*dns.ResolverEnhancer))
	}

	resolver.DefaultResolver = r
	resolver.DefaultHostMapper = m
	mobilelog.Native("debug", "updateDNS is calling dns.NewLocalServer.")
	resolver.DefaultLocalServer = dns.NewLocalServer(r, m)
	mobilelog.Native("debug", "updateDNS returned from dns.NewLocalServer.")

	if pr.HasProxyServer() {
		mobilelog.Native("debug", "updateDNS detected proxy server DNS entries and is installing the proxy host resolver.")
		resolver.ProxyServerHostResolver = pr
	} else {
		resolver.ProxyServerHostResolver = nil
		mobilelog.Native("debug", "updateDNS did not receive proxy server DNS entries; cleared the previous proxy resolver.")
	}

	mobilelog.Native("debug", "updateDNS is calling dns.ReCreateServer.")
	dns.ReCreateServer(c.Listen, r, m)
	mobilelog.Native("info", "updateDNS completed successfully.")
}

func updateHosts(tree *trie.DomainTrie[resolver.HostValue]) {
	resolver.DefaultHosts = resolver.NewHosts(tree)
}

func updateProxies(proxies map[string]C.Proxy, providers map[string]provider.ProxyProvider) {
	tunnel.UpdateProxies(proxies, providers)
}

func updateRules(rules []C.Rule, subRules map[string][]C.Rule, ruleProviders map[string]provider.RuleProvider) {
	tunnel.UpdateRules(rules, subRules, ruleProviders)
}

func loadProvider(pv provider.Provider) {
	if pv.VehicleType() == provider.Compatible {
		log.Infoln("Start initial compatible provider %s", pv.Name())
	} else {
		log.Infoln("Start initial provider %s", (pv).Name())
	}

	if err := pv.Initial(); err != nil {
		switch pv.Type() {
		case provider.Proxy:
			{
				log.Errorln("initial proxy provider %s error: %v", (pv).Name(), err)
			}
		case provider.Rule:
			{
				log.Errorln("initial rule provider %s error: %v", (pv).Name(), err)
			}

		}
	}
}

func loadRuleProvider(ruleProviders map[string]provider.RuleProvider) {
	wg := sync.WaitGroup{}
	ch := make(chan struct{}, concurrentCount)
	for _, ruleProvider := range ruleProviders {
		ruleProvider := ruleProvider
		wg.Add(1)
		ch <- struct{}{}
		go func() {
			defer func() { <-ch; wg.Done() }()
			loadProvider(ruleProvider)

		}()
	}

	wg.Wait()
}

func loadProxyProvider(proxyProviders map[string]provider.ProxyProvider) {
	// limit concurrent size
	wg := sync.WaitGroup{}
	ch := make(chan struct{}, concurrentCount)
	for _, proxyProvider := range proxyProviders {
		proxyProvider := proxyProvider
		wg.Add(1)
		ch <- struct{}{}
		go func() {
			defer func() { <-ch; wg.Done() }()
			loadProvider(proxyProvider)
		}()
	}

	wg.Wait()
}

func warmProvidersSync(cfg *config.Config) {
	if len(cfg.Providers) == 0 && len(cfg.RuleProviders) == 0 {
		return
	}

	loadProxyProvider(cfg.Providers)
	reapplyStoredSelectionsAfterProxyWarmup(cfg)
	loadRuleProvider(cfg.RuleProviders)
}

func warmProvidersAsync(cfg *config.Config) {
	if len(cfg.Providers) == 0 && len(cfg.RuleProviders) == 0 {
		mobilephase.MarkRunning("Runtime is running.")
		return
	}

	done := make(chan struct{}, 1)
	go func() {
		warmProvidersSync(cfg)
		done <- struct{}{}
	}()

	select {
	case <-done:
		mobilephase.MarkRunning("Runtime is running.")
	case <-time.After(15 * time.Second):
		mobilephase.MarkRunning("Critical runtime path is online. Providers continue warming in background.")
	}
}

func warmRouteDatabasesAsync(cfg *config.Config) {
	routeDatabaseWarmupMux.Lock()
	if routeDatabaseWarming {
		routeDatabaseWarmupMux.Unlock()
		return
	}
	routeDatabaseWarming = true
	routeDatabaseWarmupMux.Unlock()

	go func() {
		defer func() {
			routeDatabaseWarmupMux.Lock()
			routeDatabaseWarming = false
			routeDatabaseWarmupMux.Unlock()
		}()
		if err := mmdb.WarmCountryCache(); err != nil {
			mobilelog.Native("warn", "ApplyConfig could not warm Country MMDB for route matching: "+err.Error())
		}
		if configUsesASNRules(cfg) {
			if err := mmdb.WarmASNCache(); err != nil {
				mobilelog.Native("warn", "ApplyConfig could not warm ASN MMDB for route matching: "+err.Error())
			}
		}
	}()
}

func configUsesASNRules(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}

	for _, rule := range cfg.Rules {
		if ruleUsesASN(rule) {
			return true
		}
	}
	for _, rules := range cfg.SubRules {
		for _, rule := range rules {
			if ruleUsesASN(rule) {
				return true
			}
		}
	}
	return false
}

func ruleUsesASN(rule C.Rule) bool {
	if rule == nil {
		return false
	}
	if rule.RuleType() == C.IPASN {
		return true
	}
	return strings.Contains(strings.ToUpper(rule.Payload()), "IPASN") ||
		strings.Contains(strings.ToUpper(rule.Payload()), "IP-ASN") ||
		strings.Contains(strings.ToUpper(rule.Payload()), "ASN,")
}

func reapplyStoredSelectionsAfterProxyWarmup(cfg *config.Config) {
	if cfg == nil || !cfg.Profile.StoreSelected {
		return
	}

	mobilelog.Native("info", "ApplyConfig is reapplying stored proxy selections after proxy providers finished loading.")
	restoreProfileSelections(cfg)
	mobilelog.Native("debug", "ApplyConfig finished reapplying stored proxy selections after proxy provider warmup.")
}

func updateTun(general *config.General) {
	if general == nil {
		return
	}
	mobilelog.Native("info", "updateTun is calling listener.ReCreateTun.")
	listener.ReCreateTun(LC.Tun(general.Tun), tunnel.TCPIn(), tunnel.UDPIn())
	mobilelog.Native("info", "updateTun returned from listener.ReCreateTun.")
	if runtime.GOOS == "ios" {
		mobilelog.Native("info", "updateTun is skipping listener.ReCreateRedirToTun on iOS.")
		return
	}
	mobilelog.Native("info", "updateTun is calling listener.ReCreateRedirToTun.")
	listener.ReCreateRedirToTun(general.Tun.RedirectToTun)
	mobilelog.Native("debug", "updateTun returned from listener.ReCreateRedirToTun.")
}

func updateSniffer(sniffer *config.Sniffer) {
	if sniffer.Enable {
		dispatcher, err := SNI.NewSnifferDispatcher(
			sniffer.Sniffers, sniffer.ForceDomain, sniffer.SkipDomain,
			sniffer.ForceDnsMapping, sniffer.ParsePureIp,
		)
		if err != nil {
			log.Warnln("initial sniffer failed, err:%v", err)
		}

		tunnel.UpdateSniffer(dispatcher)
		log.Infoln("Sniffer is loaded and working")
	} else {
		dispatcher, err := SNI.NewCloseSnifferDispatcher()
		if err != nil {
			log.Warnln("initial sniffer failed, err:%v", err)
		}

		tunnel.UpdateSniffer(dispatcher)
		log.Infoln("Sniffer is closed")
	}
}

func updateTunnels(tunnels []LC.Tunnel) {
	listener.PatchTunnel(tunnels, tunnel.TCPIn(), tunnel.UDPIn())
}

func updateGeneral(general *config.General) {
	tunnel.SetMode(general.Mode)
	tunnel.SetFindProcessMode(general.FindProcessMode)
	resolver.DisableIPv6 = !general.IPv6

	if general.TCPConcurrent {
		dialer.SetTcpConcurrent(general.TCPConcurrent)
		log.Infoln("Use tcp concurrent")
	}

	inbound.SetTfo(general.InboundTfo)

	adapter.UnifiedDelay.Store(general.UnifiedDelay)

	dialer.DefaultInterface.Store(general.Interface)
	dialer.DefaultRoutingMark.Store(int32(general.RoutingMark))
	if general.RoutingMark > 0 {
		log.Infoln("Use routing mark: %#x", general.RoutingMark)
	}

	iface.FlushCache()
	geodataLoader := general.GeodataLoader
	G.SetLoader(geodataLoader)
}

func updateUsers(users []auth.AuthUser) {
	authenticator := auth.NewAuthenticator(users)
	authStore.SetAuthenticator(authenticator)
	if authenticator != nil {
		log.Infoln("Authentication of local server updated")
	}
}

func updateProfile(cfg *config.Config) {
	restoreProfileSelections(cfg)
}

func restoreProfileSelections(cfg *config.Config) {
	if cfg == nil || cfg.Profile == nil {
		return
	}

	profileCfg := cfg.Profile

	profile.StoreSelected.Store(profileCfg.StoreSelected)
	if profileCfg.StoreSelected {
		patchSelectGroup(cfg.Proxies)
	}
}

func patchSelectGroup(proxies map[string]C.Proxy) {
	cacheSelections := cachefile.Cache().SelectedMap()
	appSelections, appSelectionPath, appSelectionErr := readAppStoredProxySelections()
	if appSelectionErr != nil && !os.IsNotExist(appSelectionErr) {
		mobilelog.Native("warn", "restoreProfileSelections could not load app-stored proxy selections: "+appSelectionErr.Error())
	}
	if len(cacheSelections) > 0 && appStoredProxySelectionFileIsAuthoritative(appSelectionErr) {
		mobilelog.Native("debug", "restoreProfileSelections skipped cache-backed selector overrides because the app-stored proxy selection file is authoritative.")
	}
	cacheSelections = cacheSelectionsForRestore(cacheSelections, appSelections, appSelectionErr)

	if len(cacheSelections) == 0 && len(appSelections) == 0 {
		mobilelog.Native("debug", "restoreProfileSelections did not find any stored selector overrides.")
		return
	}

	if len(appSelections) > 0 {
		mobilelog.Native(
			"info",
			fmt.Sprintf("restoreProfileSelections loaded %d app-stored proxy selections from %s.", len(appSelections), appSelectionPath),
		)
	}

	appliedFromApp := 0
	appliedFromCache := 0

	for name, proxy := range proxies {
		outbound, ok := proxy.(*adapter.Proxy)
		if !ok {
			continue
		}

		group, ok := outbound.ProxyAdapter.(selectableProxyGroup)
		if !ok {
			continue
		}

		if selected, exist := appSelections[name]; exist {
			if err := applyStoredSelection(group, selected); err == nil {
				appliedFromApp++
				if name == "GLOBAL" {
					mobilelog.Native("info", "restoreProfileSelections applied app-stored selection '"+selected+"' to group 'GLOBAL'.")
				}
				continue
			} else {
				mobilelog.Native("warn", "restoreProfileSelections could not apply app-stored selection '"+selected+"' for group '"+name+"': "+err.Error())
			}
		}

		selected, exist := cacheSelections[name]
		if !exist {
			continue
		}

		if err := applyStoredSelection(group, selected); err == nil {
			appliedFromCache++
			if name == "GLOBAL" {
				mobilelog.Native("info", "restoreProfileSelections applied cache-backed selection '"+selected+"' to group 'GLOBAL'.")
			}
		} else {
			mobilelog.Native("warn", "restoreProfileSelections could not apply cache-backed selection '"+selected+"' for group '"+name+"': "+err.Error())
		}
	}

	if appliedFromApp > 0 || appliedFromCache > 0 {
		mobilelog.Native(
			"info",
			fmt.Sprintf("restoreProfileSelections applied %d app-stored and %d cache-backed selector overrides.", appliedFromApp, appliedFromCache),
		)
	}
}

func cacheSelectionsForRestore(
	cacheSelections map[string]string,
	appSelections map[string]string,
	appSelectionErr error,
) map[string]string {
	if appStoredProxySelectionFileIsAuthoritative(appSelectionErr) {
		return nil
	}
	return cacheSelections
}

func appStoredProxySelectionFileIsAuthoritative(appSelectionErr error) bool {
	return appSelectionErr == nil || !os.IsNotExist(appSelectionErr)
}

func applyStoredSelection(group selectableProxyGroup, selected string) error {
	return group.Set(selected)
}

func readAppStoredProxySelections() (map[string]string, string, error) {
	candidatePaths := appStoredProxySelectionPaths()
	var lastErr error

	for _, path := range candidatePaths {
		info, err := os.Stat(path)
		if err != nil {
			lastErr = err
			continue
		}

		if info.IsDir() {
			lastErr = fmt.Errorf("%s is a directory", path)
			continue
		}

		mobilelog.Native(
			"debug",
			fmt.Sprintf("readAppStoredProxySelections is checking %s (%d bytes).", path, info.Size()),
		)

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, path, err
		}

		mapping := map[string]string{}
		if err := json.Unmarshal(data, &mapping); err != nil {
			return nil, path, err
		}

		normalized := make(map[string]string, len(mapping))
		for group, selected := range mapping {
			groupName := strings.TrimSpace(group)
			selectionName := strings.TrimSpace(selected)
			if groupName == "" || selectionName == "" {
				continue
			}
			normalized[groupName] = selectionName
		}

		mobilelog.Native(
			"info",
			fmt.Sprintf("readAppStoredProxySelections loaded %d non-empty entries from %s.", len(normalized), path),
		)
		return normalized, path, nil
	}

	if lastErr == nil {
		lastErr = os.ErrNotExist
	}
	return nil, candidatePaths[0], lastErr
}

func appStoredProxySelectionPaths() []string {
	primary := C.Path.Resolve("proxy-selection-preferences.json")
	fallback := filepath.Join(filepath.Dir(C.Path.HomeDir()), "proxy-selection-preferences.json")
	if fallback == primary {
		return []string{primary}
	}
	return []string{primary, fallback}
}

func updateIPTables(cfg *config.Config) {
	tproxy.CleanupTProxyIPTables()

	iptables := cfg.IPTables
	if runtime.GOOS != "linux" || !iptables.Enable {
		return
	}

	var err error
	defer func() {
		if err != nil {
			log.Errorln("[IPTABLES] setting iptables failed: %s", err.Error())
			os.Exit(2)
		}
	}()

	if cfg.General.Tun.Enable {
		err = fmt.Errorf("when tun is enabled, iptables cannot be set automatically")
		return
	}

	var (
		inboundInterface = "lo"
		bypass           = iptables.Bypass
		tProxyPort       = cfg.General.TProxyPort
		dnsCfg           = cfg.DNS
	)

	if tProxyPort == 0 {
		err = fmt.Errorf("tproxy-port must be greater than zero")
		return
	}

	if !dnsCfg.Enable {
		err = fmt.Errorf("DNS server must be enable")
		return
	}

	dnsPort, err := netip.ParseAddrPort(dnsCfg.Listen)
	if err != nil {
		err = fmt.Errorf("DNS server must be correct")
		return
	}

	if iptables.InboundInterface != "" {
		inboundInterface = iptables.InboundInterface
	}

	if dialer.DefaultRoutingMark.Load() == 0 {
		dialer.DefaultRoutingMark.Store(2158)
	}

	err = tproxy.SetTProxyIPTables(inboundInterface, bypass, uint16(tProxyPort), dnsPort.Port())
	if err != nil {
		return
	}

	log.Infoln("[IPTABLES] Setting iptables completed")
}

func Shutdown() {
	listener.Cleanup(false)
	tproxy.CleanupTProxyIPTables()
	resolver.StoreFakePoolState()

	log.Warnln("Clash shutting down")
}
