package config

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/geodata"
	"github.com/Dreamacro/clash/component/geodata/router"
	clashHttp "github.com/Dreamacro/clash/component/http"
	"github.com/Dreamacro/clash/component/mmdb"
	"github.com/Dreamacro/clash/component/resource"
	SNI "github.com/Dreamacro/clash/component/sniffer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/inner"
	R "github.com/Dreamacro/clash/rules"
	"github.com/Dreamacro/clash/tunnel"
	"google.golang.org/protobuf/proto"
)

type denyDirectResourceTransport struct{ calls atomic.Int32 }

func (transport *denyDirectResourceTransport) RoundTrip(*http.Request) (*http.Response, error) {
	transport.calls.Add(1)
	return nil, errors.New("direct fixture transport is forbidden")
}

type fixtureResourceEgress struct {
	*outbound.Base
	calls  atomic.Int32
	bodies map[string][]byte
}

func (egress *fixtureResourceEgress) DialContext(_ context.Context, metadata *C.Metadata, _ ...dialer.Option) (C.Conn, error) {
	if metadata.Type != C.INNER || metadata.Host != "resource-audit.example.org" {
		return nil, fmt.Errorf("download did not enter inner rules: %+v", metadata)
	}
	egress.calls.Add(1)
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		request, err := http.ReadRequest(bufio.NewReader(server))
		if err != nil {
			return
		}
		defer request.Body.Close()
		code := http.StatusOK
		body := egress.bodies[request.URL.Path]
		if request.URL.Path == "/failure" {
			code = http.StatusServiceUnavailable
			body = []byte("fixture failure")
		}
		_, _ = fmt.Fprintf(server, "HTTP/1.1 %d Fixture\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", code, len(body))
		_, _ = server.Write(body)
	}()
	return outbound.NewConn(client, egress), nil
}

func TestIOSGeoAndProvidersUseExistingInnerRulesAndRetainCache(t *testing.T) {
	oldRequired, oldHome, oldMode := clashHttp.RequireRuleResourceDownloads, C.Path.HomeDir(), C.GeodataMode
	oldGeo, oldSite, oldMMDB, oldASN, oldLoader := C.GeoIpUrl, C.GeoSiteUrl, C.MmdbUrl, C.ASNUrl, geodata.LoaderName()
	oldRules, oldRuleProviders := tunnel.Rules(), tunnel.RuleProviders()
	oldProxies, oldProviders, oldTunnelMode, oldStatus := tunnel.Proxies(), tunnel.Providers(), tunnel.Mode(), tunnel.Status()
	oldTransport := http.DefaultTransport
	oldSniffer := SNI.Dispatcher
	defer func() {
		clashHttp.RequireRuleResourceDownloads = oldRequired
		C.SetHomeDir(oldHome)
		C.GeodataMode = oldMode
		C.GeoIpUrl = oldGeo
		C.GeoSiteUrl = oldSite
		C.MmdbUrl = oldMMDB
		C.ASNUrl = oldASN
		geodata.SetLoader(oldLoader)
		geodata.ClearCache()
		http.DefaultTransport = oldTransport
		if oldSniffer != nil {
			tunnel.UpdateSniffer(oldSniffer)
		} else {
			SNI.Dispatcher = nil
		}
		inner.New(nil)
		tunnel.UpdateRules(oldRules, nil, oldRuleProviders)
		tunnel.UpdateProxies(oldProxies, oldProviders)
		tunnel.SetMode(oldTunnelMode)
		switch oldStatus {
		case tunnel.Running:
			tunnel.OnRunning()
		case tunnel.Inner:
			tunnel.OnInnerLoading()
		default:
			tunnel.OnSuspend()
		}
	}()
	clashHttp.RequireRuleResourceDownloads = true
	home := t.TempDir()
	C.SetHomeDir(home)
	C.GeodataMode = true
	geodata.SetLoader("standard")
	geodata.ClearCache()
	C.GeoIpUrl = "http://resource-audit.example.org/ip"
	C.GeoSiteUrl = "http://resource-audit.example.org/site"
	C.MmdbUrl = "http://resource-audit.example.org/mmdb"
	C.ASNUrl = "http://resource-audit.example.org/asn"
	direct := &denyDirectResourceTransport{}
	http.DefaultTransport = direct
	inner.New(nil)
	cache := filepath.Join(home, "existing.mmdb")
	if err := os.WriteFile(cache, []byte("existing valid cache fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := mmdb.DownloadMMDB(cache); err == nil {
		t.Fatal("startup without rules used a temporary direct download")
	}
	if data, _ := os.ReadFile(cache); string(data) != "existing valid cache fixture" {
		t.Fatal("failed startup truncated the cache")
	}
	if direct.calls.Load() != 0 {
		t.Fatal("startup entered the direct HTTP transport")
	}
	site, _ := proto.Marshal(&router.GeoSiteList{Entry: []*router.GeoSite{{CountryCode: "CN", Domain: []*router.Domain{{Type: router.Domain_Full, Value: "fixture.example.org"}}}}})
	ip, _ := proto.Marshal(&router.GeoIPList{Entry: []*router.GeoIP{{CountryCode: "CN", Cidr: []*router.CIDR{{Ip: []byte{192, 0, 2, 0}, Prefix: 24}}}}})
	egress := &fixtureResourceEgress{Base: outbound.NewBase(outbound.BaseOption{Name: "Fixture Egress", Type: C.Vless}), bodies: map[string][]byte{"/site": site, "/ip": ip, "/mmdb": []byte("mmdb fixture"), "/asn": []byte("asn fixture"), "/provider": []byte("payload:\n  - +.example.org\n")}}
	rule, err := R.ParseRule("DOMAIN", "resource-audit.example.org", egress.Name(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	tunnel.UpdateProxies(map[string]C.Proxy{egress.Name(): adapter.NewProxy(egress)}, nil)
	tunnel.UpdateRules([]C.Rule{rule}, nil, nil)
	tunnel.SetMode(tunnel.Rule)
	tunnel.OnInnerLoading()
	closedSniffer, _ := SNI.NewCloseSnifferDispatcher()
	tunnel.UpdateSniffer(closedSniffer)
	inner.New(tunnel.TCPIn())
	if err := geodata.InitGeoSite(); err != nil {
		t.Fatal(err)
	}
	if err := geodata.InitGeoIP(); err != nil {
		t.Fatal(err)
	}
	if err := mmdb.DownloadMMDB(cache); err != nil {
		t.Fatal(err)
	}
	if err := mmdb.DownloadASN(filepath.Join(home, "asn.mmdb")); err != nil {
		t.Fatal(err)
	}
	if _, err := downloadForBytes(C.GeoSiteUrl); err != nil {
		t.Fatal(err)
	}
	provider := resource.NewHTTPVehicle("http://resource-audit.example.org/provider", filepath.Join(home, "provider.yaml"))
	if data, err := provider.Read(); err != nil || string(data) != "payload:\n  - +.example.org\n" {
		t.Fatalf("provider failed after inner initialization: %q %v", data, err)
	}
	C.MmdbUrl = "http://resource-audit.example.org/failure"
	if err := mmdb.DownloadMMDB(cache); err == nil {
		t.Fatal("failed update accepted")
	}
	if data, _ := os.ReadFile(cache); string(data) != "mmdb fixture" {
		t.Fatal("failed update changed a complete cache")
	}
	if direct.calls.Load() != 0 || egress.calls.Load() < 7 {
		t.Fatalf("Geo/provider requests did not use the actual core rule: direct=%d egress=%d", direct.calls.Load(), egress.calls.Load())
	}
}
