package dns

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/resolver"
	CTLS "github.com/Dreamacro/clash/component/tls"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/tunnel"
	D "github.com/miekg/dns"
)

type dnsFixtureProxy struct {
	C.Proxy
	calls atomic.Int32
	fail  bool
}

func (p *dnsFixtureProxy) DialContext(ctx context.Context, m *C.Metadata, _ ...dialer.Option) (C.Conn, error) {
	p.calls.Add(1)
	if p.fail {
		return nil, errors.New("fixture selected proxy unavailable")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(m.Host, m.DstPort))
	if err != nil {
		return nil, err
	}
	return &dnsFixtureConn{Conn: conn}, nil
}
func (p *dnsFixtureProxy) SupportUDP() bool { return false }

type dnsFixtureConn struct{ net.Conn }

func (*dnsFixtureConn) Chains() C.Chain               { return C.Chain{"Fixture proxy"} }
func (*dnsFixtureConn) AppendToChains(C.ProxyAdapter) {}
func (*dnsFixtureConn) RemoteDestination() string     { return "fixture" }

func TestIOSBusinessDNSProxyFailuresAndRedirectsDoNotBypass(t *testing.T) {
	oldStrict, oldProxies, oldProviders := resolver.RequireEncryptedProxyServerDNS, tunnel.Proxies(), tunnel.Providers()
	resolver.RequireEncryptedProxyServerDNS = true
	t.Cleanup(func() {
		resolver.RequireEncryptedProxyServerDNS = oldStrict
		tunnel.UpdateProxies(oldProxies, oldProviders)
	})
	var clearRequests, encryptedRequests atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { clearRequests.Add(1); w.WriteHeader(500) }))
	defer plain.Close()
	encrypted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		encryptedRequests.Add(1)
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, plain.URL, http.StatusFound)
			return
		}
		raw, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		if err != nil {
			t.Error(err)
			return
		}
		query := new(D.Msg)
		if err := query.Unpack(raw); err != nil {
			t.Error(err)
			return
		}
		response := new(D.Msg)
		response.SetReply(query)
		response.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.33")}}
		bytes, _ := response.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(bytes)
	}))
	defer encrypted.Close()
	if err := CTLS.AddCertificate(string(encrypted.Certificate().Raw)); err != nil {
		t.Fatal(err)
	}
	defer CTLS.ResetCertificate()
	fixture := &dnsFixtureProxy{}
	tunnel.UpdateProxies(map[string]C.Proxy{"Selected": fixture}, nil)
	query := new(D.Msg)
	query.SetQuestion("business.example.org.", D.TypeA)
	exchange := func(path, target string) error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		client := newDoHClient(encrypted.URL+path, nil, false, nil, target).(*dnsOverHTTPS)
		defer client.Close()
		_, err := client.ExchangeContext(ctx, query)
		return err
	}
	if err := exchange("/valid", "Selected"); err != nil {
		t.Fatal("proxied TLS DNS fixture failed:", err)
	}
	if fixture.calls.Load() == 0 || encryptedRequests.Load() != 1 {
		t.Fatal("business DNS bypassed the explicit proxy")
	}
	before := encryptedRequests.Load()
	fixture.fail = true
	if err := exchange("/unavailable", "Selected"); err == nil {
		t.Fatal("failed proxy silently fell back")
	}
	if err := exchange("/missing", "Missing"); err == nil {
		t.Fatal("missing proxy silently became direct/interface traffic")
	}
	if encryptedRequests.Load() != before {
		t.Fatal("DNS directly reached the upstream after proxy failure")
	}
	if _, err := getDialHandler(nil, "Missing")(context.Background(), "udp", "127.0.0.1:53"); err == nil {
		t.Fatal("missing UDP adapter silently fell back")
	}
	if _, err := listenPacket(context.Background(), "Missing", "udp", "127.0.0.1:53", nil); err == nil {
		t.Fatal("missing QUIC adapter silently fell back")
	}
	fixture.fail = false
	if err := exchange("/redirect", "Selected"); err == nil {
		t.Fatal("business DoH accepted a cleartext redirect")
	}
	if clearRequests.Load() != 0 {
		t.Fatal("DoH followed a cleartext redirect")
	}
}
