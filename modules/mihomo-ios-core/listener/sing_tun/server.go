package sing_tun

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/mobilelog"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/iface"
	C "github.com/Dreamacro/clash/constant"
	LC "github.com/Dreamacro/clash/listener/config"
	"github.com/Dreamacro/clash/listener/sing"
	"github.com/Dreamacro/clash/log"

	tun "github.com/metacubex/sing-tun"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/ranges"
)

var InterfaceName = "Meta"

type Listener struct {
	closed  bool
	options LC.Tun
	handler *ListenerHandler
	tunName string
	addrStr string

	tunIf    tun.Tun
	tunStack tun.Stack

	networkUpdateMonitor    tun.NetworkUpdateMonitor
	defaultInterfaceMonitor tun.DefaultInterfaceMonitor
	packageManager          tun.PackageManager
}

func CalculateInterfaceName(name string) (tunName string) {
	if runtime.GOOS == "darwin" {
		tunName = "utun"
	} else if name != "" {
		tunName = name
		return
	} else {
		tunName = "tun"
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return
	}
	var tunIndex int
	for _, netInterface := range interfaces {
		if strings.HasPrefix(netInterface.Name, tunName) {
			index, parseErr := strconv.ParseInt(netInterface.Name[len(tunName):], 10, 16)
			if parseErr == nil {
				tunIndex = int(index) + 1
			}
		}
	}
	tunName = F.ToString(tunName, tunIndex)
	return
}

func checkTunName(tunName string) (ok bool) {
	defer func() {
		if !ok {
			log.Warnln("[TUN] Unsupported tunName(%s) in %s, force regenerate by ourselves.", tunName, runtime.GOOS)
		}
	}()
	if runtime.GOOS == "darwin" {
		if len(tunName) <= 4 {
			return false
		}
		if tunName[:4] != "utun" {
			return false
		}
		if _, parseErr := strconv.ParseInt(tunName[4:], 10, 16); parseErr != nil {
			return false
		}
	}
	return true
}

func New(options LC.Tun, tcpIn chan<- C.ConnContext, udpIn chan<- C.PacketAdapter, additions ...inbound.Addition) (l *Listener, err error) {
	mobilelog.Native("info", "sing_tun.New entered.")
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-TUN"),
			inbound.WithSpecialRules(""),
		}
	}
	tunName := options.Device
	if tunName == "" || !checkTunName(tunName) {
		tunName = CalculateInterfaceName(InterfaceName)
		options.Device = tunName
	}
	tunMTU := options.MTU
	if tunMTU == 0 {
		tunMTU = 9000
	}
	var udpTimeout int64
	if options.UDPTimeout != 0 {
		udpTimeout = options.UDPTimeout
	} else {
		udpTimeout = int64(sing.UDPTimeout.Seconds())
	}
	includeUID := uidToRange(options.IncludeUID)
	if len(options.IncludeUIDRange) > 0 {
		var err error
		includeUID, err = parseRange(includeUID, options.IncludeUIDRange)
		if err != nil {
			return nil, E.Cause(err, "parse include_uid_range")
		}
	}
	excludeUID := uidToRange(options.ExcludeUID)
	if len(options.ExcludeUIDRange) > 0 {
		var err error
		excludeUID, err = parseRange(excludeUID, options.ExcludeUIDRange)
		if err != nil {
			return nil, E.Cause(err, "parse exclude_uid_range")
		}
	}

	var dnsAdds []netip.AddrPort

	for _, d := range options.DNSHijack {
		if _, after, ok := strings.Cut(d, "://"); ok {
			d = after
		}
		d = strings.Replace(d, "any", "0.0.0.0", 1)
		addrPort, err := netip.ParseAddrPort(d)
		if err != nil {
			return nil, fmt.Errorf("parse dns-hijack url error: %w", err)
		}

		dnsAdds = append(dnsAdds, addrPort)
	}
	for _, a := range options.Inet4Address {
		addrPort := netip.AddrPortFrom(a.Build().Addr().Next(), 53)
		dnsAdds = append(dnsAdds, addrPort)
	}
	for _, a := range options.Inet6Address {
		addrPort := netip.AddrPortFrom(a.Build().Addr().Next(), 53)
		dnsAdds = append(dnsAdds, addrPort)
	}

	handler := &ListenerHandler{
		ListenerHandler: sing.ListenerHandler{
			TcpIn:      tcpIn,
			UdpIn:      udpIn,
			Type:       C.TUN,
			Additions:  additions,
			UDPTimeout: time.Second * time.Duration(udpTimeout),
		},
		DnsAdds: dnsAdds,
	}
	l = &Listener{
		closed:  false,
		options: options,
		handler: handler,
		tunName: tunName,
	}
	defer func() {
		if err != nil {
			l.Close()
			l = nil
		}
	}()

	networkUpdateMonitor, err := tun.NewNetworkUpdateMonitor(handler)
	if err != nil {
		err = E.Cause(err, "create NetworkUpdateMonitor")
		return
	}
	l.networkUpdateMonitor = networkUpdateMonitor
	mobilelog.Native("debug", "sing_tun.New created the network update monitor. Starting it next.")
	err = networkUpdateMonitor.Start()
	if err != nil {
		err = E.Cause(err, "start NetworkUpdateMonitor")
		return
	}
	mobilelog.Native("debug", "sing_tun.New started the network update monitor.")

	defaultInterfaceMonitor, err := tun.NewDefaultInterfaceMonitor(networkUpdateMonitor, tun.DefaultInterfaceMonitorOptions{OverrideAndroidVPN: true})
	if err != nil {
		err = E.Cause(err, "create DefaultInterfaceMonitor")
		return
	}
	l.defaultInterfaceMonitor = defaultInterfaceMonitor
	mobilelog.Native("debug", "sing_tun.New created the default interface monitor.")
	defaultInterfaceMonitor.RegisterCallback(func(event int) error {
		l.FlushDefaultInterface()
		return nil
	})
	err = defaultInterfaceMonitor.Start()
	if err != nil {
		err = E.Cause(err, "start DefaultInterfaceMonitor")
		return
	}
	mobilelog.Native("debug", "sing_tun.New started the default interface monitor.")
	mobilelog.Native("debug", "sing_tun.New is flushing the initial default interface after the monitor start.")
	l.FlushDefaultInterface()

	tunOptions := tun.Options{
		Name:               tunName,
		MTU:                tunMTU,
		Inet4Address:       common.Map(options.Inet4Address, LC.ListenPrefix.Build),
		Inet6Address:       common.Map(options.Inet6Address, LC.ListenPrefix.Build),
		AutoRoute:          options.AutoRoute,
		StrictRoute:        options.StrictRoute,
		Inet4RouteAddress:  common.Map(options.Inet4RouteAddress, LC.ListenPrefix.Build),
		Inet6RouteAddress:  common.Map(options.Inet6RouteAddress, LC.ListenPrefix.Build),
		IncludeUID:         includeUID,
		ExcludeUID:         excludeUID,
		IncludeAndroidUser: options.IncludeAndroidUser,
		IncludePackage:     options.IncludePackage,
		ExcludePackage:     options.ExcludePackage,
		FileDescriptor:     options.FileDescriptor,
		InterfaceMonitor:   defaultInterfaceMonitor,
		TableIndex:         2022,
	}

	err = l.buildAndroidRules(&tunOptions)
	if err != nil {
		err = E.Cause(err, "build android rules")
		return
	}
	mobilelog.Native("debug", "sing_tun.New finished buildAndroidRules.")
	tunIf, err := tunNew(tunOptions)
	if err != nil {
		err = E.Cause(err, "configure tun interface")
		return
	}
	l.tunIf = tunIf
	mobilelog.Native("debug", "sing_tun.New created the iOS tun interface wrapper.")
	stackName := strings.ToLower(options.Stack.String())
	if runtime.GOOS == "ios" {
		if stackName == "" || stackName == "system" || stackName == "gvisor" {
			stackName = "lwip"
			mobilelog.Native("info", "sing_tun.New forced the iOS tun stack to use lwip for Packet Tunnel compatibility.")
		}
	}
	mobilelog.Native("debug", "sing_tun.New is creating the tun stack with stack name: "+stackName)
	l.tunStack, err = tun.NewStack(stackName, tun.StackOptions{
		Context:                context.TODO(),
		Tun:                    tunIf,
		MTU:                    tunOptions.MTU,
		Name:                   tunOptions.Name,
		Inet4Address:           tunOptions.Inet4Address,
		Inet6Address:           tunOptions.Inet6Address,
		EndpointIndependentNat: options.EndpointIndependentNat,
		UDPTimeout:             udpTimeout,
		Handler:                handler,
		Logger:                 log.SingLogger,
		UnderPlatform:          runtime.GOOS == "ios",
	})
	if err != nil {
		return
	}
	mobilelog.Native("debug", "sing_tun.New created the tun stack. Starting it next.")

	err = l.tunStack.Start()
	if err != nil {
		return
	}
	mobilelog.Native("info", "sing_tun.New started the tun stack successfully.")
	mobilelog.Native("debug", "sing_tun.New is preparing the listener address string after the tun stack start.")

	//l.openAndroidHotspot(tunOptions)

	l.addrStr = fmt.Sprintf("%s(%s,%s), mtu: %d, auto route: %v, ip stack: %s",
		tunName, tunOptions.Inet4Address, tunOptions.Inet6Address, tunMTU, options.AutoRoute, options.Stack)
	mobilelog.Native("debug", "sing_tun.New stored the listener address string after the tun stack start.")
	mobilelog.Native("info", "sing_tun.New completed successfully.")
	return
}

func (l *Listener) FlushDefaultInterface() {
	if !l.options.AutoDetectInterface {
		return
	}

	for _, destination := range []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified(), netip.MustParseAddr("1.1.1.1")} {
		autoDetectInterfaceName := l.defaultInterfaceMonitor.DefaultInterfaceName(destination)
		if autoDetectInterfaceName == "" || autoDetectInterfaceName == "<nil>" {
			log.Warnln("[TUN] Auto detect interface by %s get empty name.", destination.String())
			mobilelog.Native("warning", "[TUN] Auto detect interface by "+destination.String()+" returned an empty interface name.")
			continue
		}
		if l.isTunnelLikeInterfaceName(autoDetectInterfaceName) {
			log.Warnln("[TUN] Auto detect interface by %s returned tunnel-like interface %s.", destination.String(), autoDetectInterfaceName)
			mobilelog.Native("warning", "[TUN] Auto detect interface by "+destination.String()+" returned tunnel-like interface "+autoDetectInterfaceName+".")
			continue
		}

		l.storeDefaultInterface(autoDetectInterfaceName, "monitor", " for destination "+destination.String())
		return
	}

	if fallbackInterface := l.fallbackPhysicalInterfaceName(); fallbackInterface != "" {
		l.storeDefaultInterface(fallbackInterface, "fallback physical interface", "")
	}
}

func (l *Listener) storeDefaultInterface(interfaceName string, reason string, suffix string) {
	if old := dialer.DefaultInterface.Load(); old != interfaceName {
		log.Warnln("[TUN] default interface changed by %s, %s => %s", reason, old, interfaceName)
		mobilelog.Native("info", "[TUN] default interface changed by "+reason+", "+old+" => "+interfaceName)
		dialer.DefaultInterface.Store(interfaceName)
		iface.FlushCache()
	} else {
		mobilelog.Native("debug", "[TUN] default interface "+reason+" kept interface "+interfaceName+suffix+".")
	}
}

func (l *Listener) isTunnelLikeInterfaceName(interfaceName string) bool {
	if interfaceName == l.tunName {
		return true
	}
	if runtime.GOOS == "ios" || runtime.GOOS == "darwin" {
		return strings.HasPrefix(interfaceName, "utun")
	}
	return false
}

func (l *Listener) fallbackPhysicalInterfaceName() string {
	if runtime.GOOS != "ios" {
		return ""
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		mobilelog.Native("warning", "[TUN] fallback physical interface lookup failed: "+err.Error())
		return ""
	}

	for _, prefix := range []string{"en", "pdp_ip"} {
		if interfaceName := l.firstUsablePhysicalInterfaceName(interfaces, prefix); interfaceName != "" {
			return interfaceName
		}
	}
	return l.firstUsablePhysicalInterfaceName(interfaces, "")
}

func (l *Listener) firstUsablePhysicalInterfaceName(interfaces []net.Interface, prefix string) string {
	for _, netInterface := range interfaces {
		if prefix != "" && !strings.HasPrefix(netInterface.Name, prefix) {
			continue
		}
		if netInterface.Flags&net.FlagUp == 0 || netInterface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if l.isTunnelLikeInterfaceName(netInterface.Name) {
			continue
		}
		mobilelog.Native("debug", "[TUN] fallback physical interface candidate "+netInterface.Name+" flags="+netInterface.Flags.String()+".")
		return netInterface.Name
	}
	return ""
}

func uidToRange(uidList []uint32) []ranges.Range[uint32] {
	return common.Map(uidList, func(uid uint32) ranges.Range[uint32] {
		return ranges.NewSingle(uid)
	})
}

func parseRange(uidRanges []ranges.Range[uint32], rangeList []string) ([]ranges.Range[uint32], error) {
	for _, uidRange := range rangeList {
		if !strings.Contains(uidRange, ":") {
			return nil, E.New("missing ':' in range: ", uidRange)
		}
		subIndex := strings.Index(uidRange, ":")
		if subIndex == 0 {
			return nil, E.New("missing range start: ", uidRange)
		} else if subIndex == len(uidRange)-1 {
			return nil, E.New("missing range end: ", uidRange)
		}
		var start, end uint64
		var err error
		start, err = strconv.ParseUint(uidRange[:subIndex], 10, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range start")
		}
		end, err = strconv.ParseUint(uidRange[subIndex+1:], 10, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range end")
		}
		uidRanges = append(uidRanges, ranges.New(uint32(start), uint32(end)))
	}
	return uidRanges, nil
}

func (l *Listener) Close() error {
	l.closed = true
	return common.Close(
		l.tunStack,
		l.tunIf,
		l.defaultInterfaceMonitor,
		l.networkUpdateMonitor,
		l.packageManager,
	)
}

func (l *Listener) Config() LC.Tun {
	return l.options
}

func (l *Listener) Address() string {
	return l.addrStr
}
