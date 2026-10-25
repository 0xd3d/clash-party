package inner

import (
	"context"
	"errors"
	"testing"
	"time"

	C "github.com/Dreamacro/clash/constant"
)

func TestHandleTcpContextRejectsMissingQueueAndHonorsCancellation(t *testing.T) {
	tcpInMu.RLock()
	old := tcpIn
	tcpInMu.RUnlock()
	defer New(old)
	New(nil)
	if IsReady() {
		t.Fatal("missing queue reported ready")
	}
	if conn, err := HandleTcpContext(context.Background(), "example.org:443", ""); err == nil || conn != nil {
		t.Fatal("uninitialized queue accepted a dial")
	}
	New(make(chan C.ConnContext))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	start := time.Now()
	conn, err := HandleTcpContext(ctx, "example.org:443", "")
	if conn != nil || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("blocked queue ignored cancellation: %v %v", conn, err)
	}
}
