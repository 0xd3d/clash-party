package geodata

import (
	"os"
	"path/filepath"
	"testing"

	C "github.com/Dreamacro/clash/constant"
)

func TestInitGeoIPIgnoresMissingInvalidMMDBDuringRemoval(t *testing.T) {
	originalHomeDir := C.Path.HomeDir()
	originalGeodataMode := C.GeodataMode
	originalInitGeoIP := initGeoIP
	originalVerifyMMDB := verifyMMDB
	originalDownloadMMDB := downloadMMDB
	defer func() {
		C.SetHomeDir(originalHomeDir)
		C.GeodataMode = originalGeodataMode
		initGeoIP = originalInitGeoIP
		verifyMMDB = originalVerifyMMDB
		downloadMMDB = originalDownloadMMDB
	}()

	homeDir := t.TempDir()
	C.SetHomeDir(homeDir)
	C.GeodataMode = false
	initGeoIP = 0

	mmdbPath := filepath.Join(homeDir, "Country.mmdb")
	if err := os.WriteFile(mmdbPath, []byte("not a valid mmdb"), 0o644); err != nil {
		t.Fatalf("failed to create invalid mmdb fixture: %v", err)
	}

	verifyMMDB = func() bool {
		if err := os.Remove(mmdbPath); err != nil {
			t.Fatalf("failed to simulate concurrent mmdb cleanup: %v", err)
		}
		return false
	}
	downloadMMDB = func(path string) error {
		return nil
	}

	if err := InitGeoIP(); err != nil {
		t.Fatalf("expected InitGeoIP to ignore a missing invalid MMDB during removal, got %v", err)
	}
}
