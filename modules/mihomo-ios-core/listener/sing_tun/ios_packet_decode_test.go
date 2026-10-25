package sing_tun

import (
	"bytes"
	"testing"

	"github.com/metacubex/gvisor/pkg/tcpip/header"
)

func TestDecodeIOSPacketForDispatchStripsPacketInformationHeader(t *testing.T) {
	frame := []byte{
		0x00, 0x00, 0x00, 0x02,
		0x45, 0x00, 0x00, 0x54,
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x01, 0x00, 0x00,
		0xc0, 0x00, 0x02, 0x01,
		0xc6, 0x33, 0x64, 0x01,
	}

	packet, protocol, ok := decodeIOSPacketForDispatch(frame, 4)
	if !ok {
		t.Fatal("expected IPv4 packet to decode successfully")
	}
	if protocol != header.IPv4ProtocolNumber {
		t.Fatalf("expected IPv4 protocol number, got %v", protocol)
	}
	if !bytes.Equal(packet, frame[4:]) {
		t.Fatalf("expected payload without packet information header, got %v", packet)
	}
}

func TestDecodeIOSPacketForDispatchAcceptsIPv6(t *testing.T) {
	frame := []byte{
		0x00, 0x00, 0x00, 0x1e,
		0x60, 0x00, 0x00, 0x00,
		0x00, 0x08, 0x3a, 0x40,
		0x20, 0x01, 0x0d, 0xb8,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		0x20, 0x01, 0x0d, 0xb8,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x02,
	}

	packet, protocol, ok := decodeIOSPacketForDispatch(frame, 4)
	if !ok {
		t.Fatal("expected IPv6 packet to decode successfully")
	}
	if protocol != header.IPv6ProtocolNumber {
		t.Fatalf("expected IPv6 protocol number, got %v", protocol)
	}
	if !bytes.Equal(packet, frame[4:]) {
		t.Fatalf("expected payload without packet information header, got %v", packet)
	}
}

func TestDecodeIOSPacketForDispatchRejectsShortFrames(t *testing.T) {
	if _, _, ok := decodeIOSPacketForDispatch([]byte{0x00, 0x00, 0x00, 0x02}, 4); ok {
		t.Fatal("expected packet shorter than the offset to be rejected")
	}
}

func TestDecodeIOSPacketForDispatchRejectsUnknownVersions(t *testing.T) {
	frame := []byte{0x00, 0x00, 0x00, 0x02, 0x10, 0x00, 0x00, 0x00}
	if _, _, ok := decodeIOSPacketForDispatch(frame, 4); ok {
		t.Fatal("expected packet with unsupported IP version nibble to be rejected")
	}
}
