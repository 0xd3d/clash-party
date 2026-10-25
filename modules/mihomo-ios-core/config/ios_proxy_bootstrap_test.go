package config

import (
	"net/url"
	"testing"
)

func TestHTTPSNameServerPreservesPathAndQuery(t *testing.T) {
	servers, err := parseNameServer([]string{"https://1.1.1.1/dns%2Dquery?token=fixture&mode=strict#DIRECT"}, false)
	if err != nil || len(servers) != 1 {
		t.Fatalf("parse failed: %v %v", servers, err)
	}
	endpoint, err := url.Parse(servers[0].Addr)
	if err != nil || endpoint.EscapedPath() != "/dns%2Dquery" || endpoint.Query().Get("token") != "fixture" || endpoint.Query().Get("mode") != "strict" || servers[0].ProxyAdapter != "DIRECT" {
		t.Fatalf("HTTPS endpoint changed during parsing: %+v %v", servers[0], err)
	}
}
