package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDualStackDialContextSkipsEmptyAddressFamilies(t *testing.T) {
	ipv4Err := errors.New("ipv4 dial failed")
	var emptyFamilyCalls int32

	dialFn := func(ctx context.Context, network string, ips []netip.Addr, port string, opt *option) (net.Conn, error) {
		if len(ips) == 0 {
			atomic.AddInt32(&emptyFamilyCalls, 1)
			return nil, ErrorNoIpAddress
		}
		return nil, ipv4Err
	}

	_, err := dualStackDialContext(
		context.Background(),
		dialFn,
		"tcp",
		[]netip.Addr{netip.MustParseAddr("203.0.113.1")},
		"443",
		&option{},
	)
	if err == nil {
		t.Fatal("expected non-empty address family dial failure")
	}
	if atomic.LoadInt32(&emptyFamilyCalls) != 0 {
		t.Fatalf("expected empty address families to be skipped, got %d call(s)", emptyFamilyCalls)
	}
	if strings.Contains(err.Error(), ErrorNoIpAddress.Error()) {
		t.Fatalf("expected empty-family no-ip error to be omitted, got %v", err)
	}
	if !strings.Contains(err.Error(), ipv4Err.Error()) {
		t.Fatalf("expected non-empty address family error to be preserved, got %v", err)
	}
}
