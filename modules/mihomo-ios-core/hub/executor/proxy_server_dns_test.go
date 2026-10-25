package executor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Dreamacro/clash/component/mmdb"
	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	RC "github.com/Dreamacro/clash/rules/common"
)

func TestWarmRouteDatabasesAsyncDoesNotBlockOrPanicWhenResourcesAreMissing(t *testing.T) {
	originalHomeDir := C.Path.HomeDir()
	t.Cleanup(func() {
		C.SetHomeDir(originalHomeDir)
		mmdb.ClearCache()
	})

	homeDir := filepath.Join(t.TempDir(), "mihomo-home")
	if err := os.MkdirAll(homeDir, 0o755); err != nil {
		t.Fatalf("mkdir temp home: %v", err)
	}
	C.SetHomeDir(homeDir)
	mmdb.ClearCache()

	warmRouteDatabasesAsync(nil)
}

func TestConfigUsesASNRulesOnlyWhenExplicitRuleExists(t *testing.T) {
	cfg := &config.Config{
		Rules: []C.Rule{
			RC.NewMatch("GLOBAL"),
		},
	}
	if configUsesASNRules(cfg) {
		t.Fatal("expected ordinary MATCH config not to warm ASN resources")
	}

	asnRule, err := RC.NewIPASN("15169", "GLOBAL", true)
	if err != nil {
		t.Fatalf("failed to build IP-ASN rule: %v", err)
	}
	cfg.Rules = append(cfg.Rules, asnRule)
	if !configUsesASNRules(cfg) {
		t.Fatal("expected explicit IP-ASN config to warm ASN resources")
	}
}
