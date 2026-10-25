//go:build ios && with_gvisor

package sing_tun

/*
#include <stdint.h>

extern int MihomoIOSReadPacket(void *buffer, int maxLen);
extern int MihomoIOSWritePacket(const void *buffer, int len);
extern int MihomoIOSPacketFlowAttached(void);
extern uint64_t MihomoIOSPacketFlowNewReader(void);
extern void MihomoIOSPacketFlowCloseReader(uint64_t reader);
extern int MihomoIOSPacketFlowReaderActive(uint64_t reader);
extern int MihomoIOSReadPacketForReader(void *buffer, int maxLen, uint64_t reader);
*/
import "C"

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/Dreamacro/clash/common/mobilelog"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"

	"github.com/metacubex/gvisor/pkg/bufferv2"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"

	tun "github.com/metacubex/sing-tun"
)

type iosTun struct {
	closed       atomic.Bool
	readerID     C.uint64_t
	mtu          uint32
	inet4Address tcpip.Address
	inet6Address tcpip.Address
	loggedRead   bool
	loggedWrite  bool
}

const iosPacketOffset = 4

func newIOSTun(options tun.Options) (tun.Tun, error) {
	device := &iosTun{
		mtu:      options.MTU,
		readerID: C.MihomoIOSPacketFlowNewReader(),
	}
	if len(options.Inet4Address) > 0 {
		device.inet4Address = tcpip.Address(options.Inet4Address[0].Addr().AsSlice())
	}
	if len(options.Inet6Address) > 0 {
		device.inet6Address = tcpip.Address(options.Inet6Address[0].Addr().AsSlice())
	}
	return device, nil
}

func (t *iosTun) Read(p []byte) (int, error) {
	defer func() {
		if r := recover(); r != nil {
			mobilelog.Native("error", fmt.Sprintf("iosTun.Read panicked: %v", r))
		}
	}()
	if len(p) <= iosPacketOffset {
		return 0, nil
	}

	for {
		if t.closed.Load() {
			return 0, io.EOF
		}
		if C.MihomoIOSPacketFlowAttached() == 0 {
			time.Sleep(50 * time.Millisecond)
			continue
		}

		if !t.loggedRead {
			mobilelog.Native("debug", "iosTun.Read is calling MihomoIOSReadPacket for the first time.")
		}
		n := int(C.MihomoIOSReadPacketForReader(
			unsafe.Pointer(&p[iosPacketOffset]),
			C.int(len(p)-iosPacketOffset),
			t.readerID,
		))
		if t.closed.Load() {
			return 0, io.EOF
		}
		if !t.loggedRead {
			mobilelog.Native("debug", fmt.Sprintf("iosTun.Read returned from MihomoIOSReadPacket with value %d.", n))
		}
		switch {
		case n > 0:
			version := p[iosPacketOffset] >> 4
			switch version {
			case 4:
				p[0], p[1], p[2], p[3] = 0x00, 0x00, 0x00, 0x02
			case 6:
				p[0], p[1], p[2], p[3] = 0x00, 0x00, 0x00, 0x1e
			default:
				if !t.loggedRead {
					mobilelog.Native("warn", fmt.Sprintf("iosTun.Read received a packet with an unknown IP version nibble %d.", version))
				}
				continue
			}
			if !t.loggedRead {
				mobilelog.Native("debug", fmt.Sprintf("iosTun.Read received the first packet from MihomoIOSReadPacket (%d bytes).", n))
				t.loggedRead = true
			}
			return n + iosPacketOffset, nil
		case n == 0:
			time.Sleep(10 * time.Millisecond)
		default:
			return 0, io.EOF
		}
	}
}

func (t *iosTun) Write(p []byte) (int, error) {
	defer func() {
		if r := recover(); r != nil {
			mobilelog.Native("error", fmt.Sprintf("iosTun.Write panicked: %v", r))
		}
	}()
	if len(p) == 0 {
		return 0, nil
	}
	if t.closed.Load() || C.MihomoIOSPacketFlowReaderActive(t.readerID) == 0 {
		return 0, io.ErrClosedPipe
	}
	if !t.loggedWrite {
		mobilelog.Native("debug", fmt.Sprintf("iosTun.Write is sending the first packet to MihomoIOSWritePacket (%d bytes).", len(p)))
	}
	n := int(C.MihomoIOSWritePacket(unsafe.Pointer(&p[0]), C.int(len(p))))
	if !t.loggedWrite {
		mobilelog.Native("debug", fmt.Sprintf("iosTun.Write returned from MihomoIOSWritePacket with value %d.", n))
		t.loggedWrite = true
	}
	if n < 0 {
		return 0, io.ErrClosedPipe
	}
	return n, nil
}

func (t *iosTun) Close() error {
	if !t.closed.Swap(true) {
		C.MihomoIOSPacketFlowCloseReader(t.readerID)
	}
	return nil
}

func (t *iosTun) NewEndpoint() (stack.LinkEndpoint, error) {
	return &iosEndpoint{tun: t}, nil
}

type iosEndpoint struct {
	tun        *iosTun
	dispatcher stack.NetworkDispatcher
}

func (e *iosEndpoint) MTU() uint32 {
	return e.tun.mtu
}

func (e *iosEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (e *iosEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (e *iosEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}

func (e *iosEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	defer func() {
		if r := recover(); r != nil {
			mobilelog.Native("error", fmt.Sprintf("iosEndpoint.Attach panicked: %v", r))
		}
	}()
	if dispatcher == nil && e.dispatcher != nil {
		mobilelog.Native("debug", "iosEndpoint.Attach received a nil dispatcher. Clearing the existing dispatcher.")
		e.dispatcher = nil
		return
	}
	if dispatcher != nil && e.dispatcher == nil {
		mobilelog.Native("debug", "iosEndpoint.Attach received a network dispatcher. Launching the iOS dispatch loop.")
		e.dispatcher = dispatcher
		go e.dispatchLoop()
	}
}

func (e *iosEndpoint) dispatchLoop() {
	defer func() {
		if r := recover(); r != nil {
			mobilelog.Native("error", fmt.Sprintf("iosEndpoint.dispatchLoop panicked: %v", r))
		}
	}()
	mobilelog.Native("debug", "iosEndpoint.dispatchLoop entered.")
	_buffer := buf.StackNewSize(int(e.tun.mtu) + iosPacketOffset)
	defer common.KeepAlive(_buffer)
	buffer := common.Dup(_buffer)
	defer buffer.Release()
	data := buffer.FreeBytes()
	firstPacket := true
	for {
		n, err := e.tun.Read(data)
		if err != nil {
			mobilelog.Native("error", fmt.Sprintf("iosEndpoint.dispatchLoop failed to read from the iOS tun wrapper: %v", err))
			break
		}
		if firstPacket {
			mobilelog.Native("debug", fmt.Sprintf("iosEndpoint.dispatchLoop received the first packet from the iOS tun wrapper (%d bytes).", n))
			firstPacket = false
		}
		packet, networkProtocol, ok := decodeIOSPacketForDispatch(data[:n], iosPacketOffset)
		if !ok {
			continue
		}
		switch networkProtocol {
		case header.IPv4ProtocolNumber:
			if header.IPv4(packet).DestinationAddress() == e.tun.inet4Address {
				_, _ = e.tun.Write(packet)
				continue
			}
		case header.IPv6ProtocolNumber:
			if header.IPv6(packet).DestinationAddress() == e.tun.inet6Address {
				_, _ = e.tun.Write(packet)
				continue
			}
		}

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload:           bufferv2.MakeWithData(packet),
			IsForwardedPacket: true,
		})
		pkt.NetworkProtocolNumber = networkProtocol
		dispatcher := e.dispatcher
		if dispatcher == nil {
			mobilelog.Native("warn", "iosEndpoint.dispatchLoop found a nil dispatcher while delivering a packet. Exiting the dispatch loop.")
			pkt.DecRef()
			return
		}
		dispatcher.DeliverNetworkPacket(networkProtocol, pkt)
		pkt.DecRef()
	}
	mobilelog.Native("info", "iosEndpoint.dispatchLoop exited.")
}

func (e *iosEndpoint) IsAttached() bool {
	return e.dispatcher != nil
}

func (e *iosEndpoint) Wait() {
}

func (e *iosEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (e *iosEndpoint) AddHeader(buffer stack.PacketBufferPtr) {
}

func (e *iosEndpoint) WritePackets(packetBufferList stack.PacketBufferList) (int, tcpip.Error) {
	defer func() {
		if r := recover(); r != nil {
			mobilelog.Native("error", fmt.Sprintf("iosEndpoint.WritePackets panicked: %v", r))
		}
	}()
	mobilelog.Native("debug", fmt.Sprintf("iosEndpoint.WritePackets entered with %d packets.", len(packetBufferList.AsSlice())))
	var written int
	for _, packet := range packetBufferList.AsSlice() {
		payload := packet.ToView().AsSlice()
		if len(payload) == 0 {
			continue
		}
		if _, err := e.tun.Write(payload); err != nil {
			return written, &tcpip.ErrAborted{}
		}
		written++
	}
	return written, nil
}

var _ tun.GVisorTun = (*iosTun)(nil)
