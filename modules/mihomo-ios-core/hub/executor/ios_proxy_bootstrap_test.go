package executor

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Dreamacro/clash/component/resolver"
	CTLS "github.com/Dreamacro/clash/component/tls"
	"github.com/Dreamacro/clash/config"
	"github.com/Dreamacro/clash/dns"
	D "github.com/miekg/dns"
)

func TestIOSProxyBootstrapFailsClosedWithoutChangingApplicationDNS(t *testing.T) {
	oldStrict, oldMain, oldProxy, oldMapper, oldLocal := resolver.RequireEncryptedProxyServerDNS, resolver.DefaultResolver, resolver.ProxyServerHostResolver, resolver.DefaultHostMapper, resolver.DefaultLocalServer
	defer func() {
		resolver.RequireEncryptedProxyServerDNS = oldStrict
		resolver.DefaultResolver = oldMain
		resolver.ProxyServerHostResolver = oldProxy
		resolver.DefaultHostMapper = oldMapper
		resolver.DefaultLocalServer = oldLocal
	}()
	resolver.RequireEncryptedProxyServerDNS = true
	var mainQueries, bootstrapQueries atomic.Int32
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bootstrap" {
			bootstrapQueries.Add(1)
			http.Error(w, "fixture upstream failure", 503)
			return
		}
		mainQueries.Add(1)
		data, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		if err != nil {
			t.Error(err)
			return
		}
		query := new(D.Msg)
		if err := query.Unpack(data); err != nil {
			t.Error(err)
			return
		}
		answer := new(D.Msg)
		answer.SetReply(query)
		answer.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.40")}}
		body, _ := answer.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(body)
	}))
	defer endpoint.Close()
	if err := CTLS.AddCertificate(string(endpoint.Certificate().Raw)); err != nil {
		t.Fatal(err)
	}
	defer CTLS.ResetCertificate()
	cfg := &config.DNS{Enable: true, NameServer: []dns.NameServer{{Net: "https", Addr: endpoint.URL + "/application"}}, ProxyServerNameserver: []dns.NameServer{{Addr: "192.0.2.53:53"}}, DefaultNameserver: []dns.NameServer{{Net: "https", Addr: endpoint.URL + "/bootstrap"}}}
	updateDNS(cfg, false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := resolver.DefaultResolver.LookupIPv4(ctx, "application.example.org"); err != nil {
		t.Fatal(err)
	}
	baseline := mainQueries.Load()
	if ips, err := resolver.LookupIPv4ProxyServerHost(ctx, "unused-node.example.org"); err == nil || len(ips) > 0 {
		t.Fatalf("failed bootstrap unexpectedly resolved: %v %v", ips, err)
	}
	if bootstrapQueries.Load() == 0 || mainQueries.Load() != baseline {
		t.Fatalf("proxy DNS fell back into application DNS: bootstrap=%d main=%d", bootstrapQueries.Load(), mainQueries.Load())
	}
	// No independent endpoint: hostname errors without querying main DNS, while the
	// currently selected literal-IP node still requires no network DNS at all.
	cfg.DefaultNameserver = nil
	updateDNS(cfg, false)
	if _, err := resolver.LookupIPv4ProxyServerHost(ctx, "another-unused-node.example.org"); err == nil {
		t.Fatal("missing independent endpoint accepted")
	}
	ips, err := resolver.LookupIPv4ProxyServerHost(ctx, "198.51.100.10")
	if err != nil || len(ips) != 1 || ips[0].String() != "198.51.100.10" {
		t.Fatalf("unrelated hostname failure blocked a literal node: %v %v", ips, err)
	}
	if mainQueries.Load() != baseline {
		t.Fatal("missing bootstrap used application DNS")
	}
	if _, err := resolver.DefaultResolver.LookupIPv4(ctx, "another-application.example.org"); err != nil {
		t.Fatalf("application DNS was changed: %v", err)
	}
	cfg.Enable = false
	updateDNS(cfg, false)
	if resolver.ProxyServerHostResolver != nil {
		t.Fatal("stale proxy resolver survives DNS disable")
	}
}
