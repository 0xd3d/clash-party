package dns

import (
	"fmt"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Dreamacro/clash/common/mobilelog"
	D "github.com/miekg/dns"
)

var mobileAudit struct {
	sync.Mutex
	window time.Time
	count  int
}

func safeDNSUpstream(source string) string {
	if strings.HasPrefix(source, "cache") {
		return source
	}
	if u, err := url.Parse(source); err == nil && u.Host != "" {
		u.User = nil
		u.RawQuery = ""
		u.Fragment = ""
		return u.String()
	}
	return strings.SplitN(source, "#", 2)[0]
}

// Bounded query metadata only: no DNS wire data or arbitrary endpoint tokens.
func recordMobileDNSAnswer(domain, source string, msg *D.Msg) {
	if runtime.GOOS != "ios" || msg == nil {
		return
	}
	ips := msgToIP(msg)
	if len(ips) == 0 {
		return
	}
	mobileAudit.Lock()
	now := time.Now()
	if now.Sub(mobileAudit.window) >= time.Minute {
		mobileAudit.window = now
		mobileAudit.count = 0
	}
	if mobileAudit.count >= 32 {
		mobileAudit.Unlock()
		return
	}
	mobileAudit.count++
	mobileAudit.Unlock()
	if len(ips) > 4 {
		ips = ips[:4]
	}
	mobilelog.Native("info", fmt.Sprintf("iOS DNS answer domain=%s upstream=%s ips=%v", domain, safeDNSUpstream(source), ips))
}
