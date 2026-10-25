package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/common/callback"
	N "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
)

type Fallback struct {
	*GroupBase
	disableUDP bool
	testUrl    string
	selected   string
}

func (f *Fallback) Now() string {
	proxy := f.findAliveProxy(false)
	return proxy.Name()
}

// DialContext implements C.ProxyAdapter
func (f *Fallback) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	var (
		proxy C.Proxy
		c     C.Conn
		err   error
	)
	attempts := groupDialAttempts(len(f.GetProxies(false)))
	excluded := groupDialAttemptExclusions(attempts)
	for attempt := 0; attempt < attempts; attempt++ {
		proxy = f.findAliveProxyExcept(true, excluded)
		if proxy == nil {
			break
		}
		rememberProxyAttempt(excluded, proxy)
		c, err = proxy.DialContext(ctx, metadata, f.Base.DialOptions(opts...)...)
		if err == nil {
			clearProxyLeafDialFailure(proxy)
			c.AppendToChains(f)
			break
		}

		logProxyLeafDialFailure(f.Name(), proxy, metadata, err)
		_ = markProxyLeafUnreachableOnDialError(proxy, err)
		f.onDialFailed(proxy.Type(), err)
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
					f.onDialSuccess()
				} else {
					logProxyLeafDialFailure(f.Name(), proxy, metadata, err)
					_ = markProxyLeafUnreachableOnDialError(proxy, err)
					f.onDialFailed(proxy.Type(), err)
				}
			},
		}
	}

	return c, err
}

// ListenPacketContext implements C.ProxyAdapter
func (f *Fallback) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	proxy := f.findAliveProxy(true)
	pc, err := proxy.ListenPacketContext(ctx, metadata, f.Base.DialOptions(opts...)...)
	if err == nil {
		clearProxyLeafDialFailure(proxy)
		pc.AppendToChains(f)
	} else {
		logProxyLeafDialFailure(f.Name(), proxy, metadata, err)
		_ = markProxyLeafUnreachableOnDialError(proxy, err)
	}

	return pc, err
}

// SupportUDP implements C.ProxyAdapter
func (f *Fallback) SupportUDP() bool {
	if f.disableUDP {
		return false
	}

	proxy := f.findAliveProxy(false)
	return proxy.SupportUDP()
}

// MarshalJSON implements C.ProxyAdapter
func (f *Fallback) MarshalJSON() ([]byte, error) {
	all := []string{}
	for _, proxy := range f.GetProxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type": f.Type().String(),
		"now":  f.Now(),
		"all":  all,
	})
}

// Unwrap implements C.ProxyAdapter
func (f *Fallback) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	proxy := f.findAliveProxy(touch)
	return proxy
}

func (f *Fallback) findAliveProxy(touch bool) C.Proxy {
	return f.findAliveProxyExcept(touch, nil)
}

func (f *Fallback) findAliveProxyExcept(touch bool, excluded map[string]struct{}) C.Proxy {
	proxies := f.GetProxies(touch)
	if len(f.selected) != 0 {
		for _, proxy := range proxies {
			if proxy.Name() != f.selected {
				continue
			}
			if shouldUseSelectedProxy(proxy) {
				return proxy
			}
			break
		}
	}

	for _, proxy := range proxies {
		if proxyExcluded(proxy, excluded) {
			continue
		}
		if proxy.Alive() && proxyLeafReachable(proxy) {
			return proxy
		}
	}

	return firstProxyExcept(proxies, excluded)
}

func (f *Fallback) Set(name string) error {
	var p C.Proxy
	for _, proxy := range f.GetProxies(false) {
		if proxy.Name() == name {
			p = proxy
			break
		}
	}

	if p == nil {
		return errors.New("proxy not exist")
	}

	f.selected = name
	if !p.Alive() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*time.Duration(5000))
		defer cancel()
		_, _ = p.URLTest(ctx, f.testUrl)
	}

	return nil
}

func NewFallback(option *GroupCommonOption, providers []provider.ProxyProvider) *Fallback {
	return &Fallback{
		GroupBase: NewGroupBase(GroupBaseOption{
			outbound.BaseOption{
				Name:        option.Name,
				Type:        C.Fallback,
				Interface:   option.Interface,
				RoutingMark: option.RoutingMark,
			},
			option.Filter,
			option.ExcludeFilter,
			option.ExcludeType,
			providers,
		}),
		disableUDP: option.DisableUDP,
		testUrl:    option.URL,
	}
}
