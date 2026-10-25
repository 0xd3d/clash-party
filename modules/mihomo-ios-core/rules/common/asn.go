package common

import (
	"fmt"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/Dreamacro/clash/component/mmdb"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

var asnMMDBLookupWarnOnce sync.Once
var asnMMDBNotReadyWarnOnce sync.Once
var ipASNGOOS = runtime.GOOS

type IPASN struct {
	*Base
	asn     uint
	adapter string
}

func (a *IPASN) RuleType() C.RuleType {
	return C.IPASN
}

func (a *IPASN) Match(metadata *C.Metadata) (bool, string) {
	if metadata == nil {
		return false, ""
	}

	ip := metadata.DstIP
	if !ip.IsValid() {
		return false, ""
	}

	if shouldSkipASNLookup(ip) {
		metadata.DstASNFailed = true
		return false, ""
	}

	if !metadata.DstASNReady && !metadata.DstASNFailed {
		record, ready, err := mmdb.LookupASNFromCache(ip.AsSlice())
		if !ready {
			if shouldAvoidColdASNLookup(metadata) {
				metadata.DstASNFailed = true
				asnMMDBNotReadyWarnOnce.Do(func() {
					log.Warnln("IP-ASN rule skipped cold ASN lookup on the iOS TUN hot path because GeoLite2-ASN.mmdb has not been warmed yet")
				})
				return false, ""
			}
			record, err = mmdb.LookupASN(ip.AsSlice())
		}
		if err != nil {
			metadata.DstASNFailed = true
			asnMMDBLookupWarnOnce.Do(func() {
				log.Warnln("IP-ASN rule skipped ASN lookup because GeoLite2-ASN.mmdb lookup failed: %s", err.Error())
			})
			return false, ""
		}
		metadata.DstASN = uint(record.AutonomousSystemNumber)
		metadata.DstASNReady = true
		if record.AutonomousSystemNumber != 0 {
			metadata.DstASNLabel = fmt.Sprintf("AS%d", record.AutonomousSystemNumber)
		}
	}

	if metadata.DstASNFailed {
		return false, ""
	}

	return metadata.DstASN == a.asn, a.adapter
}

func shouldAvoidColdASNLookup(metadata *C.Metadata) bool {
	return ipASNGOOS == "ios" && metadata != nil && metadata.Type == C.TUN
}

func shouldSkipASNLookup(ip netip.Addr) bool {
	return ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		resolver.IsFakeIP(ip) ||
		resolver.IsFakeBroadcastIP(ip)
}

func (a *IPASN) Adapter() string {
	return a.adapter
}

func (a *IPASN) Payload() string {
	return strconv.FormatUint(uint64(a.asn), 10)
}

func (a *IPASN) ShouldResolveIP() bool {
	return false
}

func NewIPASN(payload string, adapter string, _ bool) (*IPASN, error) {
	normalized := strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(payload), "AS"))
	asn, err := strconv.ParseUint(normalized, 10, 32)
	if err != nil || asn == 0 {
		return nil, errPayload
	}

	return &IPASN{
		Base:    &Base{},
		asn:     uint(asn),
		adapter: adapter,
	}, nil
}

var _ C.Rule = (*IPASN)(nil)
