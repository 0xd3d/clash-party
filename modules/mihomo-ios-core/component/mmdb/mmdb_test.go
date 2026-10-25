package mmdb

import (
	"os"
	"path/filepath"
	"testing"

	C "github.com/Dreamacro/clash/constant"
)

func TestLookupCountryReturnsErrorWhenMMDBIsMissing(t *testing.T) {
	originalHomeDir := C.Path.HomeDir()
	t.Cleanup(func() {
		C.SetHomeDir(originalHomeDir)
	})

	homeDir := filepath.Join(t.TempDir(), "mihomo-home")
	if err := os.MkdirAll(homeDir, 0o755); err != nil {
		t.Fatalf("mkdir temp home: %v", err)
	}
	C.SetHomeDir(homeDir)

	if _, err := LookupCountry([]byte{1, 1, 1, 1}); err == nil {
		t.Fatal("expected missing MMDB lookup to return an error")
	}
}

func TestLookupASNReturnsErrorWhenASNMMDBIsMissing(t *testing.T) {
	originalHomeDir := C.Path.HomeDir()
	t.Cleanup(func() {
		C.SetHomeDir(originalHomeDir)
		ClearASNCache()
	})

	homeDir := filepath.Join(t.TempDir(), "mihomo-home")
	if err := os.MkdirAll(homeDir, 0o755); err != nil {
		t.Fatalf("mkdir temp home: %v", err)
	}
	C.SetHomeDir(homeDir)

	if _, err := LookupASN([]byte{8, 8, 8, 8}); err == nil {
		t.Fatal("expected missing ASN MMDB lookup to return an error")
	}
}
