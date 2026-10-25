//go:build darwin

package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

type recordingNetDialer struct {
	network string
	address string
}

func (d *recordingNetDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.network = network
	d.address = address
	return nil, errors.New("recorded dial")
}

func TestDarwinDialContextSpecializesUnspecifiedTCPNetworkByDestination(t *testing.T) {
	dialer := &recordingNetDialer{}

	_, err := dialContext(
		context.Background(),
		"tcp",
		netip.MustParseAddr("103.181.165.67"),
		"30401",
		&option{netDialer: dialer},
	)
	if err == nil {
		t.Fatal("expected recording dialer to return an error")
	}
	if dialer.network != "tcp4" {
		t.Fatalf("expected tcp IPv4 dial to use tcp4 so Darwin IP_BOUND_IF can apply, got %q", dialer.network)
	}
	if dialer.address != "103.181.165.67:30401" {
		t.Fatalf("expected joined IPv4 address to be preserved, got %q", dialer.address)
	}
}

func TestDarwinBindIfaceToDialerSkipsInterfaceBindingOnIOS(t *testing.T) {
	oldSkip := skipDarwinInterfaceBind
	defer func() {
		skipDarwinInterfaceBind = oldSkip
	}()

	skipDarwinInterfaceBind = true
	dialer := &net.Dialer{}

	if err := bindIfaceToDialer("definitely-not-a-real-interface", dialer, "tcp4", netip.MustParseAddr("1.1.1.1")); err != nil {
		t.Fatalf("expected iOS Packet Tunnel path to skip interface binding, got %v", err)
	}
}

func TestDarwinParseNetworkSpecializesUnspecifiedNetworkByDestination(t *testing.T) {
	tests := []struct {
		name    string
		network string
		addr    netip.Addr
		want    string
	}{
		{
			name:    "tcp ipv4",
			network: "tcp",
			addr:    netip.MustParseAddr("103.181.165.67"),
			want:    "tcp4",
		},
		{
			name:    "udp ipv4",
			network: "udp",
			addr:    netip.MustParseAddr("103.181.165.67"),
			want:    "udp4",
		},
		{
			name:    "tcp ipv6",
			network: "tcp",
			addr:    netip.MustParseAddr("2001:db8::1"),
			want:    "tcp6",
		},
		{
			name:    "already specialized",
			network: "tcp4",
			addr:    netip.MustParseAddr("103.181.165.67"),
			want:    "tcp4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseNetwork(tt.network, tt.addr); got != tt.want {
				t.Fatalf("ParseNetwork(%q, %s) = %q, want %q", tt.network, tt.addr, got, tt.want)
			}
		})
	}
}
