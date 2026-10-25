package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/common/callback"
	N "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/common/singledo"
	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
)

type urlTestOption func(*URLTest)

func urlTestWithTolerance(tolerance uint16) urlTestOption {
	return func(u *URLTest) {
		u.tolerance = tolerance
	}
}

type URLTest struct {
	*GroupBase
	tolerance  uint16
	disableUDP bool
	selected   string
	fastNode   C.Proxy
	fastSingle *singledo.Single[C.Proxy]
}

func (u *URLTest) Now() string {
	return u.fast(false).Name()
}

// DialContext implements C.ProxyAdapter
func (u *URLTest) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (c C.Conn, err error) {
	var proxy C.Proxy
	attempts := groupDialAttempts(len(u.GetProxies(false)))
	excluded := groupDialAttemptExclusions(attempts)
	for attempt := 0; attempt < attempts; attempt++ {
		proxy = u.fastExcept(true, excluded)
		if proxy == nil {
			break
		}
		rememberProxyAttempt(excluded, proxy)
		c, err = proxy.DialContext(ctx, metadata, u.Base.DialOptions(opts...)...)
		if err == nil {
			clearProxyLeafDialFailure(proxy)
			c.AppendToChains(u)
			break
		}

		logProxyLeafDialFailure(u.Name(), proxy, metadata, err)
		if markProxyLeafUnreachableOnDialError(proxy, err) {
			u.fastSingle.Reset()
		}
		u.onDialFailed(proxy.Type(), err)
		if attempt == attempts-1 || !shouldRetryGroupDialOnIOS(err) {
			break
		}
	}

	if N.NeedHandshake(c) {
		c = &callback.FirstWriteCallBackConn{
			Conn: c,
			Callback: func(err error) {
				if err == nil {
					clearProxyLeafDialFailure(proxy)
					u.onDialSuccess()
				} else {
					logProxyLeafDialFailure(u.Name(), proxy, metadata, err)
					if markProxyLeafUnreachableOnDialError(proxy, err) {
						u.fastSingle.Reset()
					}
					u.onDialFailed(proxy.Type(), err)
				}
			},
		}
	}

	return c, err
}

// ListenPacketContext implements C.ProxyAdapter
func (u *URLTest) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	proxy := u.fast(true)
	pc, err := proxy.ListenPacketContext(ctx, metadata, u.Base.DialOptions(opts...)...)
	if err == nil {
		clearProxyLeafDialFailure(proxy)
		pc.AppendToChains(u)
	} else {
		logProxyLeafDialFailure(u.Name(), proxy, metadata, err)
		if markProxyLeafUnreachableOnDialError(proxy, err) {
			u.fastSingle.Reset()
		}
	}

	return pc, err
}

// Unwrap implements C.ProxyAdapter
func (u *URLTest) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	return u.fast(touch)
}

func (u *URLTest) fast(touch bool) C.Proxy {
	return u.fastExcept(touch, nil)
}

func (u *URLTest) fastExcept(touch bool, excluded map[string]struct{}) C.Proxy {
	if len(excluded) > 0 {
		proxies := u.GetProxies(touch)
		fast := firstAliveReachableProxyExcept(proxies, excluded)
		requireReachable := true
		if fast == nil {
			requireReachable = false
			fast = fastestAliveProxyExcept(proxies, excluded)
		}
		if fast == nil {
			fast = firstProxyExcept(proxies, excluded)
		}
		if fast == nil {
			return nil
		}

		min := fast.LastDelay()
		if !fast.Alive() {
			min = ^uint16(0)
		}
		for _, proxy := range proxies {
			if proxyExcluded(proxy, excluded) || !proxy.Alive() || (requireReachable && !proxyLeafReachable(proxy)) {
				continue
			}

			delay := proxy.LastDelay()
			if delay < min {
				fast = proxy
				min = delay
			}
		}
		return fast
	}

	elm, _, shared := u.fastSingle.Do(func() (C.Proxy, error) {
		proxies := u.GetProxies(touch)
		if len(u.selected) != 0 {
			for _, proxy := range proxies {
				if proxy.Name() == u.selected && shouldUseSelectedProxy(proxy) {
					return proxy, nil
				}
			}
		}

		fast := firstAliveReachableProxy(proxies)
		requireReachable := true
		if fast == nil {
			requireReachable = false
			fast = fastestAliveProxy(proxies)
		}
		if fast == nil {
			fast = proxies[0]
		}
		min := fast.LastDelay()
		fastNotExist := true

		if !fast.Alive() {
			min = ^uint16(0)
		}

		for _, proxy := range proxies {
			if u.fastNode != nil && proxy.Name() == u.fastNode.Name() {
				fastNotExist = false
			}

			if !proxy.Alive() || (requireReachable && !proxyLeafReachable(proxy)) {
				continue
			}

			delay := proxy.LastDelay()
			if delay < min {
				fast = proxy
				min = delay
			}
		}

		// tolerance
		fastNodeUnavailable := false
		if u.fastNode != nil {
			fastNodeUnavailable = !u.fastNode.Alive() || (requireReachable && !proxyLeafReachable(u.fastNode))
		}
		if u.fastNode == nil || fastNotExist || fastNodeUnavailable || u.fastNode.LastDelay() > fast.LastDelay()+u.tolerance {
			u.fastNode = fast
		}

		return u.fastNode, nil
	})
	if shared && touch { // a shared fastSingle.Do() may cause providers untouched, so we touch them again
		u.Touch()
	}

	return elm
}

func (u *URLTest) Set(name string) error {
	for _, proxy := range u.GetProxies(false) {
		if proxy.Name() == name {
			u.selected = name
			u.fastNode = proxy
			u.fastSingle.Reset()
			return nil
		}
	}

	return errors.New("proxy not exist")
}

// SupportUDP implements C.ProxyAdapter
func (u *URLTest) SupportUDP() bool {
	if u.disableUDP {
		return false
	}

	return u.fast(false).SupportUDP()
}

// MarshalJSON implements C.ProxyAdapter
func (u *URLTest) MarshalJSON() ([]byte, error) {
	all := []string{}
	for _, proxy := range u.GetProxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type": u.Type().String(),
		"now":  u.Now(),
		"all":  all,
	})
}

func parseURLTestOption(config map[string]any) []urlTestOption {
	opts := []urlTestOption{}

	// tolerance
	if elm, ok := config["tolerance"]; ok {
		if tolerance, ok := elm.(int); ok {
			opts = append(opts, urlTestWithTolerance(uint16(tolerance)))
		}
	}

	return opts
}

func NewURLTest(option *GroupCommonOption, providers []provider.ProxyProvider, options ...urlTestOption) *URLTest {
	urlTest := &URLTest{
		GroupBase: NewGroupBase(GroupBaseOption{
			outbound.BaseOption{
				Name:        option.Name,
				Type:        C.URLTest,
				Interface:   option.Interface,
				RoutingMark: option.RoutingMark,
			},

			option.Filter,
			option.ExcludeFilter,
			option.ExcludeType,
			providers,
		}),
		fastSingle: singledo.NewSingle[C.Proxy](time.Second * 10),
		disableUDP: option.DisableUDP,
	}

	for _, option := range options {
		option(urlTest)
	}

	return urlTest
}
