package dns

import "testing"

func TestDNSAuditDoesNotExposeCredentialsOrQueryTokens(t *testing.T) {
	source := "https://name:secret@resolver.example:443/dns-query?token=sensitive#Proxy"
	if got := safeDNSUpstream(source); got != "https://resolver.example:443/dns-query" {
		t.Fatalf("unsafe upstream logged: %s", got)
	}
}
