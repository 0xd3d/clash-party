package constant

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMMDBFallsBackToDefaultPathWhenHomeDirIsUnreadable(t *testing.T) {
	p := &path{homeDir: filepath.Join(t.TempDir(), "missing")}

	if got, want := p.MMDB(), filepath.Join(p.homeDir, "Country.mmdb"); got != want {
		t.Fatalf("expected fallback mmdb path %q, got %q", want, got)
	}
}

func TestGeoAssetPathsAcceptMetaCubeXLatestFileNames(t *testing.T) {
	homeDir := t.TempDir()
	p := &path{homeDir: homeDir}
	for _, name := range []string{"geoip-lite.dat", "geosite.dat", "country-lite.mmdb", "GeoLite2-ASN.mmdb"} {
		if err := os.WriteFile(filepath.Join(homeDir, name), []byte("fixture"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	if got, want := filepath.Base(p.GeoIP()), "geoip-lite.dat"; got != want {
		t.Fatalf("expected GeoIP path to use %q, got %q", want, got)
	}
	if got, want := filepath.Base(p.GeoSite()), "geosite.dat"; got != want {
		t.Fatalf("expected GeoSite path to use %q, got %q", want, got)
	}
	if got, want := filepath.Base(p.MMDB()), "country-lite.mmdb"; got != want {
		t.Fatalf("expected MMDB path to use %q, got %q", want, got)
	}
	if got, want := filepath.Base(p.ASN()), "GeoLite2-ASN.mmdb"; got != want {
		t.Fatalf("expected ASN path to use %q, got %q", want, got)
	}
}
