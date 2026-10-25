package inner

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/Dreamacro/clash/adapter/inbound"
	C "github.com/Dreamacro/clash/constant"
)

var tcpIn chan<- C.ConnContext
var tcpInMu sync.RWMutex

func New(in chan<- C.ConnContext) { tcpInMu.Lock(); tcpIn = in; tcpInMu.Unlock() }
func IsReady() bool               { tcpInMu.RLock(); defer tcpInMu.RUnlock(); return tcpIn != nil }

// HandleTcpContext never leaves an HTTP/provider dial hung on an uninitialized
// or saturated inner queue after its request has already been cancelled.
func HandleTcpContext(ctx context.Context, dst, host string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tcpInMu.RLock()
	in := tcpIn
	tcpInMu.RUnlock()
	if in == nil {
		return nil, errors.New("core rule-aware TCP transport is not ready")
	}
	conn1, conn2 := net.Pipe()
	inboundContext := inbound.NewInner(conn2, dst, host)
	select {
	case in <- inboundContext:
		return conn1, nil
	case <-ctx.Done():
		_ = conn1.Close()
		_ = conn2.Close()
		return nil, ctx.Err()
	}
}

func HandleTcp(dst, host string) net.Conn {
	conn, _ := HandleTcpContext(context.Background(), dst, host)
	return conn
}
