package executor

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Dreamacro/clash/component/resolver"
	CTLS "github.com/Dreamacro/clash/component/tls"
	"github.com/Dreamacro/clash/config"
	"github.com/Dreamacro/clash/dns"
	D "github.com/miekg/dns"
)

// Exercise actual TLS DoH requests through Main, policy and proxy resolvers.
// The same question must not reuse an answer from the other resolver's cache.
func TestEncryptedDNSUpstreamsAndProxyCacheIsolation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		q := new(D.Msg)
		if err := q.Unpack(data); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		addr := "192.0.2.1"
		if r.URL.Path == "/proxy" {
			addr = "192.0.2.2"
		}
		if r.URL.Path == "/policy" {
			addr = "192.0.2.3"
		}
		reply := new(D.Msg)
		reply.SetReply(q)
		reply.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.ParseIP(addr)}}
		body, _ := reply.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(body)
	}))
	defer server.Close()
	if err := CTLS.AddCertificate(string(server.Certificate().Raw)); err != nil {
		t.Fatal(err)
	}
	defer CTLS.ResetCertificate()
	oldMain, oldProxy, oldMapper, oldLocal := resolver.DefaultResolver, resolver.ProxyServerHostResolver, resolver.DefaultHostMapper, resolver.DefaultLocalServer
	defer func() {
		resolver.DefaultResolver = oldMain
		resolver.ProxyServerHostResolver = oldProxy
		resolver.DefaultHostMapper = oldMapper
		resolver.DefaultLocalServer = oldLocal
	}()
	ns := func(path string) []dns.NameServer { return []dns.NameServer{{Net: "https", Addr: server.URL + path}} }
	cfg := &config.DNS{Enable: true, NameServer: ns("/main"), ProxyServerNameserver: ns("/proxy"), DefaultNameserver: ns("/main"), NameServerPolicy: map[string][]dns.NameServer{"policy.example": ns("/policy")}}
	updateDNS(cfg, false)
	query := func(r resolver.Resolver, host, want string) {
		t.Helper()
		ips, err := r.LookupIPv4(context.Background(), host)
		if err != nil || len(ips) != 1 || ips[0].String() != want {
			t.Fatalf("%s want %s got %v error=%v", host, want, ips, err)
		}
	}
	query(resolver.DefaultResolver, "same.example", "192.0.2.1")
	query(resolver.ProxyServerHostResolver, "same.example", "192.0.2.2")
	query(resolver.DefaultResolver, "same.example", "192.0.2.1")
	query(resolver.DefaultResolver, "policy.example", "192.0.2.3")
	cfg.ProxyServerNameserver = nil
	updateDNS(cfg, false)
	if resolver.ProxyServerHostResolver != nil {
		t.Fatal(fmt.Errorf("removed proxy-server resolver survives reload"))
	}
}
