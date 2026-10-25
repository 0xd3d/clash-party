package common

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Dreamacro/clash/component/mmdb"
	C "github.com/Dreamacro/clash/constant"
)

func TestGEOIPMatchMissingMMDBDoesNotExit(t *testing.T) {
	if os.Getenv("CLASH_TEST_GEOIP_MISSING_MMDB_CHILD") == "1" {
		homeDir := filepath.Join(t.TempDir(), "mihomo-home")
		if err := os.MkdirAll(homeDir, 0o755); err != nil {
			t.Fatalf("mkdir temp home: %v", err)
		}

		C.SetHomeDir(homeDir)
		C.GeodataMode = false
		mmdb.ClearCountryCache()

		rule := &GEOIP{
			Base:    &Base{},
			country: "CN",
			adapter: "DIRECT",
		}
		matched, _ := rule.Match(&C.Metadata{DstIP: netip.MustParseAddr("1.1.1.1")})
		if matched {
			t.Fatal("expected missing MMDB to behave as a GEOIP no-match")
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestGEOIPMatchMissingMMDBDoesNotExit")
	cmd.Env = append(os.Environ(), "CLASH_TEST_GEOIP_MISSING_MMDB_CHILD=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected missing MMDB GEOIP lookup not to terminate the process, got %v\n%s", err, output)
	}
}

func TestGEOIPMatchSkipsColdMMDBLookupOnIOSTunHotPath(t *testing.T) {
	originalHomeDir := C.Path.HomeDir()
	originalGeodataMode := C.GeodataMode
	originalGOOS := geoIPGOOS
	t.Cleanup(func() {
		C.SetHomeDir(originalHomeDir)
		C.GeodataMode = originalGeodataMode
		mmdb.ClearCountryCache()
		geoIPGOOS = originalGOOS
	})

	homeDir := filepath.Join(t.TempDir(), "mihomo-home")
	if err := os.MkdirAll(homeDir, 0o755); err != nil {
		t.Fatalf("mkdir temp home: %v", err)
	}
	C.SetHomeDir(homeDir)
	C.GeodataMode = false
	geoIPGOOS = "ios"
	mmdb.ClearCountryCache()

	rule := &GEOIP{
		Base:    &Base{},
		country: "CN",
		adapter: "DIRECT",
	}
	matched, adapter := rule.Match(&C.Metadata{
		Type:  C.TUN,
		DstIP: netip.MustParseAddr("1.1.1.1"),
	})
	if matched || adapter != "" {
		t.Fatalf("expected cold iOS TUN GEOIP lookup to no-match, got matched=%v adapter=%q", matched, adapter)
	}
}
