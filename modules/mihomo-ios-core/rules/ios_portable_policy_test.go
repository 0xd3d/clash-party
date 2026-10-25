package rules_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	C "github.com/Dreamacro/clash/constant"
	R "github.com/Dreamacro/clash/rules"
	RP "github.com/Dreamacro/clash/rules/provider"
	"gopkg.in/yaml.v3"
)

// The Swift script supplies its actual generated YAML; no mirrored test matcher is used.
func TestIOSPortablePolicy(t *testing.T) {
	runtimeDir := os.Getenv("IOS_POLICY_RUNTIME_DIR")
	if runtimeDir == "" {
		t.Skip("run apps/ios/scripts/check-portable-routing.sh to supply Swift-generated profiles")
	}
	resourceDir := os.Getenv("IOS_RULE_RESOURCE_DIR")
	geoDir := os.Getenv("IOS_GEO_RESOURCE_DIR")
	if _, err := os.Stat(filepath.Join(geoDir, "country-lite.mmdb")); err != nil {
		t.Fatal("prepare the public Geo resources before this offline matching test: ", err)
	}
	previousHome, previousMode := C.Path.HomeDir(), C.GeodataMode
	C.SetHomeDir(geoDir)
	C.GeodataMode = false
	t.Cleanup(func() { C.SetHomeDir(previousHome); C.GeodataMode = previousMode })

	for _, name := range []string{"general-runtime.yaml", "desktop-runtime.yaml"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(runtimeDir, name))
			if err != nil {
				t.Fatal(err)
			}
			var profile struct {
				Rules     []string                          `yaml:"rules"`
				Providers map[string]map[string]interface{} `yaml:"rule-providers"`
			}
			if err := yaml.Unmarshal(data, &profile); err != nil {
				t.Fatal(err)
			}
			for providerName, definition := range profile.Providers {
				mapping := map[string]interface{}{"type": "file", "behavior": definition["behavior"], "path": filepath.Join(resourceDir, strings.TrimPrefix(providerName, "ios-")+".yaml")}
				provider, err := RP.ParseRuleProvider(providerName, mapping, R.ParseRule)
				if err != nil {
					t.Fatal(err)
				}
				if err := provider.Initial(); err != nil {
					t.Fatal(err)
				}
				RP.SetRuleProvider(provider)
			}
			compiled := make([]C.Rule, 0, len(profile.Rules))
			for _, text := range profile.Rules {
				fields := strings.Split(text, ",")
				var payload, target string
				var params []string
				if fields[0] == "MATCH" {
					target = fields[1]
				} else {
					payload, target = fields[1], fields[2]
					params = fields[3:]
				}
				rule, err := R.ParseRule(fields[0], payload, target, params, nil)
				if err != nil {
					t.Fatalf("parse %s: %v", text, err)
				}
				compiled = append(compiled, rule)
			}
			cases := []struct {
				name, host, destination string
				network                 C.NetWork
				target                  string
			}{
				{"public UDP to CN", "", "223.5.5.5", C.UDP, "iOS 外网"},
				{"public UDP STUN", "stun.l.google.com", "74.125.250.129", C.UDP, "iOS 外网"},
				{"public IPv6 UDP", "", "2001:4860:4860::8888", C.UDP, "iOS 外网"},
				{"private IPv4 UDP", "", "192.168.1.9", C.UDP, "DIRECT"},
				{"private IPv6 UDP", "", "fd12::9", C.UDP, "DIRECT"},
				{"Claude before CN IP", "claude.ai", "223.5.5.5", C.TCP, "iOS 外网"},
				{"QQ domestic TCP", "aqqmusic.tc.qq.com", "223.5.5.5", C.TCP, "DIRECT"},
				{"unknown overseas TCP", "unlisted-public-routing-check.org", "1.1.1.1", C.TCP, "iOS 外网"},
			}
			if name == "general-runtime.yaml" {
				cases = append(cases,
					struct {
						name, host, destination string
						network                 C.NetWork
						target                  string
					}{"unknown named host before CN IP", "unlisted-public-routing-check.org", "223.5.5.5", C.TCP, "iOS 外网"},
					struct {
						name, host, destination string
						network                 C.NetWork
						target                  string
					}{"single-label public host before CN IP", "unlisted-public-routing-host", "223.5.5.5", C.TCP, "iOS 外网"},
					struct {
						name, host, destination string
						network                 C.NetWork
						target                  string
					}{"IP-only domestic CDN", "", "223.5.5.5", C.TCP, "DIRECT"},
					struct {
						name, host, destination string
						network                 C.NetWork
						target                  string
					}{"CN domain before overseas CDN IP", "iqiyi.com", "1.1.1.1", C.TCP, "DIRECT"},
					struct {
						name, host, destination string
						network                 C.NetWork
						target                  string
					}{"public YAML provider before CN", "1password.drift.click", "223.5.5.5", C.TCP, "iOS 外网"},
					struct {
						name, host, destination string
						network                 C.NetWork
						target                  string
					}{"user service selection", "chatgpt.com", "223.5.5.5", C.TCP, "OpenAI"},
					struct {
						name, host, destination string
						network                 C.NetWork
						target                  string
					}{"local multicast", "", "224.0.0.251", C.UDP, "DIRECT"})
			}
			for _, scenario := range cases {
				t.Run(scenario.name, func(t *testing.T) {
					metadata := &C.Metadata{Host: scenario.host, DstIP: netip.MustParseAddr(scenario.destination), NetWork: scenario.network, DstPort: "443", Type: C.TUN}
					if scenario.name == "public UDP STUN" {
						metadata.DstPort = "3478"
					}
					matched, matchedRule := "", ""
					for _, rule := range compiled {
						if ok, target := rule.Match(metadata); ok {
							matched = target
							matchedRule = rule.RuleType().String() + ":" + rule.Payload()
							break
						}
					}
					if matched != scenario.target {
						t.Fatalf("first actual core match %s = %q; want %q", matchedRule, matched, scenario.target)
					}
				})
			}
		})
	}
}
