package config

import "testing"

// Exercise the actual Go URL/fragment parser used after Swift serializes a
// protected upstream. Percent escapes are decoded once, never recursively.
func TestIOSProtectedDNSFragmentSerialization(t *testing.T) {
	for _, raw := range []string{
		"https://1.1.1.1/dns-query#h3=true&Protected",
		"https://1.1.1.1/dns-query#h3=true%2526DIRECT&Protected",
		"https://1.1.1.1/dns-query#h3=%252526DIRECT&Protected",
		"https://1.1.1.1/dns-query#h3=false&Protected",
	} {
		upstreams, err := parseNameServer([]string{raw}, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(upstreams) != 1 || upstreams[0].ProxyAdapter != "Protected" {
			t.Fatalf("fragment escaped the protected adapter: %#v", upstreams)
		}
	}
}
