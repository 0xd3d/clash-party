package rules

import (
	"testing"

	C "github.com/Dreamacro/clash/constant"
)

func TestParseRuleSupportsIPASN(t *testing.T) {
	tests := []string{"IP-ASN", "IPASN", "ASN"}
	for _, tt := range tests {
		rule, err := ParseRule(tt, "AS15169", "PROXY", []string{"no-resolve"}, nil)
		if err != nil {
			t.Fatalf("expected %s rule to parse: %v", tt, err)
		}
		if rule.RuleType() != C.IPASN {
			t.Fatalf("expected %s to parse as IPASN, got %s", tt, rule.RuleType().String())
		}
		if rule.Payload() != "15169" {
			t.Fatalf("expected normalized ASN payload, got %q", rule.Payload())
		}
		if rule.ShouldResolveIP() {
			t.Fatalf("expected %s to rely on existing IP metadata instead of resolving IP", tt)
		}
	}
}
