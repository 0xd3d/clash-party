package dialer

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"syscall"

	"github.com/Dreamacro/clash/component/iface"

	"golang.org/x/sys/unix"
)

var skipDarwinInterfaceBind = runtime.GOOS == "ios"

func bindControl(ifaceIdx int) controlFn {
	return func(ctx context.Context, network, address string, c syscall.RawConn) (err error) {
		addrPort, err := netip.ParseAddrPort(address)
		if err == nil && !addrPort.Addr().IsGlobalUnicast() {
			return
		}

		var innerErr error
		err = c.Control(func(fd uintptr) {
			switch network {
			case "tcp4", "udp4":
				innerErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, ifaceIdx)
			case "tcp6", "udp6":
				innerErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, ifaceIdx)
			}
		})

		if innerErr != nil {
			err = innerErr
		}

		return
	}
}

func bindIfaceToDialer(ifaceName string, dialer *net.Dialer, _ string, _ netip.Addr) error {
	if skipDarwinInterfaceBind {
		return nil
	}

	ifaceObj, err := iface.ResolveInterface(ifaceName)
	if err != nil {
		return err
	}

	addControlToDialer(dialer, bindControl(ifaceObj.Index))
	return nil
}

func bindIfaceToListenConfig(ifaceName string, lc *net.ListenConfig, _, address string) (string, error) {
	if skipDarwinInterfaceBind {
		return address, nil
	}

	ifaceObj, err := iface.ResolveInterface(ifaceName)
	if err != nil {
		return "", err
	}

	addControlToListenConfig(lc, bindControl(ifaceObj.Index))
	return address, nil
}

func ParseNetwork(network string, addr netip.Addr) string {
	switch network {
	case "tcp", "udp":
		unmapped := addr.Unmap()
		if unmapped.Is4() {
			return network + "4"
		}
		if unmapped.Is6() {
			return network + "6"
		}
	}
	return network
}
