package dns

import (
	"github.com/Dreamacro/clash/component/trie"
	D "github.com/miekg/dns"
	"testing"
	"time"
)

func TestLazyGeoSiteRetainsPolicyWithoutBlockingDNS(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	f := newLazyGeoSiteFilter(func() (fallbackDomainFilter, error) {
		close(started)
		<-release
		return NewDomainFilter([]string{"+.example.cn"}), nil
	})
	if f.Match("example.cn") {
		t.Fatal("unloaded filter must use main resolver")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("loader not started")
	}
	if f.Match("example.cn") {
		t.Fatal("blocked loader unexpectedly completed")
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for !f.Match("example.cn") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !f.Match("a.example.cn") || f.Match("example.com") {
		t.Fatal("policy did not become active after lazy load")
	}
}

func TestUnloadedInverseGeoPolicyDoesNotOverrideMain(t *testing.T) {
	release := make(chan struct{})
	f := newLazyGeoSiteFilter(func() (fallbackDomainFilter, error) { <-release; return NewDomainFilter([]string{"+.example.cn"}), nil })
	r := &Resolver{policy: trie.New[*Policy](), geositePolicy: []geositePolicyRecord{{matcher: f, inversedMatching: true, policy: NewPolicy([]dnsClient{&client{addr: "127.0.0.1:53"}})}}}
	q := new(D.Msg)
	q.SetQuestion("example.com.", D.TypeA)
	if len(r.matchPolicy(q)) != 0 {
		t.Fatal("unloaded inverse policy captured main queries")
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for len(r.matchPolicy(q)) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(r.matchPolicy(q)) != 1 {
		t.Fatal("loaded inverse policy lost")
	}
}
