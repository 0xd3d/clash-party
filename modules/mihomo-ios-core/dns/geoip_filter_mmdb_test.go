package dns

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	C "github.com/Dreamacro/clash/constant"
)

func TestGeoIPFilterMissingMMDBDoesNotExit(t *testing.T) {
	if os.Getenv("CLASH_TEST_DNS_GEOIP_MISSING_MMDB_CHILD") == "1" {
		homeDir := filepath.Join(t.TempDir(), "mihomo-home")
		if err := os.MkdirAll(homeDir, 0o755); err != nil {
			t.Fatalf("mkdir temp home: %v", err)
		}

		C.SetHomeDir(homeDir)
		C.GeodataMode = false

		if (&geoipFilter{code: "CN"}).Match(netip.MustParseAddr("1.1.1.1")) {
			t.Fatal("expected missing MMDB to behave as a DNS fallback-filter no-match")
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestGeoIPFilterMissingMMDBDoesNotExit")
	cmd.Env = append(os.Environ(), "CLASH_TEST_DNS_GEOIP_MISSING_MMDB_CHILD=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected missing MMDB DNS geoip filter lookup not to terminate the process, got %v\n%s", err, output)
	}
}
