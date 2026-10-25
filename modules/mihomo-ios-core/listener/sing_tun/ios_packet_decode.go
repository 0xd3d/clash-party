package sing_tun

import (
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
)

func decodeIOSPacketForDispatch(data []byte, packetOffset int) ([]byte, tcpip.NetworkProtocolNumber, bool) {
	if len(data) <= packetOffset {
		return nil, 0, false
	}

	packet := data[packetOffset:]
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		return packet, header.IPv4ProtocolNumber, true
	case header.IPv6Version:
		return packet, header.IPv6ProtocolNumber, true
	default:
		return nil, 0, false
	}
}
