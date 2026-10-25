package dns

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	CTLS "github.com/Dreamacro/clash/component/tls"
	D "github.com/miekg/dns"
)

func TestIndependentProxyDNSFiltersUnsafeTransports(t *testing.T) {
	for _, test := range []struct {
		server NameServer
		safe   bool
	}{
		{NameServer{Net: "https", Addr: "https://1.1.1.1:443/dns-query?token=fixture"}, true},
		{NameServer{Net: "https", Addr: "https://[2606:4700:4700::1111]/dns-query", ProxyAdapter: "DIRECT"}, true},
		{NameServer{Net: "", Addr: "223.5.5.5:53"}, false},
		{NameServer{Net: "tcp", Addr: "1.1.1.1:53"}, false},
		{NameServer{Net: "https", Addr: "http://1.1.1.1/dns-query"}, false},
		{NameServer{Net: "https", Addr: "https://resolver.example.org/dns-query"}, false},
		{NameServer{Net: "https", Addr: "https://1.1.1.1/dns-query", ProxyAdapter: "Selected proxy"}, false},
		{NameServer{Net: "https", Addr: "https://user:fixture@1.1.1.1/dns-query"}, false},
		{NameServer{Net: "https", Addr: "https://1.1.1.1:0/dns-query"}, false},
		{NameServer{Net: "https", Addr: "https://1.1.1.1:65536/dns-query"}, false},
	} {
		if got := independentHTTPSNameServer(test.server); got != test.safe {
			t.Fatalf("safe(%q,%q)=%v want %v", test.server.Net, test.server.Addr, got, test.safe)
		}
	}
}

func TestIndependentProxyDNSUsesTLSAndRejectsRedirectsAndInvalidAnswers(t *testing.T) {
	plainRequests := 0
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainRequests++
		http.Error(w, "must not be reached", 500)
	}))
	defer plain.Close()
	encrypted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, plain.URL, http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		if r.URL.Path == "/oversized" {
			_, _ = w.Write([]byte(strings.Repeat("x", 65536)))
			return
		}
		raw, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		if err != nil {
			t.Error(err)
			http.Error(w, "invalid", 400)
			return
		}
		query := new(D.Msg)
		if err := query.Unpack(raw); err != nil {
			t.Error(err)
			http.Error(w, "invalid", 400)
			return
		}
		if r.URL.Path == "/valid" && r.URL.Query().Get("token") != "fixture" {
			t.Error("upstream query parameters were lost")
		}
		response := new(D.Msg)
		response.SetReply(query)
		if r.URL.Path == "/mismatch" {
			response.Question[0].Name = "unrelated.example.org."
		}
		response.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.21")}}
		body, _ := response.Pack()
		_, _ = w.Write(body)
	}))
	defer encrypted.Close()
	if err := CTLS.AddCertificate(string(encrypted.Certificate().Raw)); err != nil {
		t.Fatal(err)
	}
	defer CTLS.ResetCertificate()
	base := NewResolver(Config{})
	for _, path := range []string{"/valid?token=fixture", "/redirect", "/oversized", "/mismatch"} {
		t.Run(path, func(t *testing.T) {
			r := NewIndependentProxyServerHostResolver(base, []NameServer{{Net: "https", Addr: encrypted.URL + path}})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			ips, err := r.LookupIPv4(ctx, "node.example.org")
			if strings.HasPrefix(path, "/valid") {
				if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.21" {
					t.Fatalf("valid encrypted lookup failed: %v %v", ips, err)
				}
				var workers sync.WaitGroup
				for i := 0; i < 8; i++ {
					workers.Add(1)
					go func(index int) {
						defer workers.Done()
						answers, err := r.LookupIPv4(ctx, fmt.Sprintf("node-%d.example.org", index))
						if err != nil || len(answers) != 1 || answers[0].String() != "192.0.2.21" {
							t.Errorf("concurrent encrypted lookup failed: %v %v", answers, err)
						}
					}(i)
				}
				workers.Wait()
			} else if err == nil {
				t.Fatalf("unsafe encrypted reply accepted: %v", ips)
			}
		})
	}
	if plainRequests != 0 {
		t.Fatalf("bootstrap followed a cleartext redirect %d times", plainRequests)
	}
}
