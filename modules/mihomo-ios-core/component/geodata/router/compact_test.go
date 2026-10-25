package router

import "testing"

func TestCompactDomainMatcherPreservesAllPatternTypes(t *testing.T) {
	domains := []*Domain{{Type: Domain_Full, Value: "API.Example"}, {Type: Domain_Domain, Value: "Example.com"}, {Type: Domain_Plain, Value: "track"}, {Type: Domain_Regex, Value: `^r[0-9]+\.test$`}, {Type: Domain_Domain, Value: "example.com"}}
	for _, invert := range []bool{false, true} {
		old, err := NewMphMatcherGroup(domains, invert)
		if err != nil {
			t.Fatal(err)
		}
		b := new(CompactDomainBuilder)
		for _, d := range domains {
			if err := b.Add(d); err != nil {
				t.Fatal(err)
			}
		}
		compact := b.Build(invert)
		for _, q := range []string{"api.example", "API.EXAMPLE", "example.com", "a.example.com", "notexample.com", "r1.test", "www.r1.test", "track.example.org", "example.com.", "", "example.net"} {
			if compact.ApplyDomain(q) != old.ApplyDomain(q) {
				t.Fatalf("q=%q invert=%v differs", q, invert)
			}
		}
	}
	if err := new(CompactDomainBuilder).Add(&Domain{Type: Domain_Regex, Value: "["}); err == nil {
		t.Fatal("invalid regex accepted")
	}
	if err := new(CompactDomainBuilder).Add(&Domain{Type: 99, Value: "a"}); err == nil {
		t.Fatal("invalid type accepted")
	}
}
