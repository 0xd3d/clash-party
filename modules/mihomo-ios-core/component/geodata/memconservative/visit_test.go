package memconservative

import (
	R "github.com/Dreamacro/clash/component/geodata/router"
	C "github.com/Dreamacro/clash/constant"
	"google.golang.org/protobuf/proto"
	"os"
	"path/filepath"
	"testing"
)

func TestSiteVisitorPreservesValuesAndAttributes(t *testing.T) {
	old := C.Path.HomeDir()
	defer C.SetHomeDir(old)
	C.SetHomeDir(t.TempDir())
	input := &R.GeoSiteList{Entry: []*R.GeoSite{{CountryCode: "CN", Domain: []*R.Domain{{Type: R.Domain_Domain, Value: "example.cn", Attribute: []*R.Domain_Attribute{{Key: "ads"}}}, {Type: R.Domain_Full, Value: "example.org"}}}}}
	wire, _ := proto.Marshal(input)
	if err := os.WriteFile(filepath.Join(C.Path.HomeDir(), C.GeositeName), wire, 0600); err != nil {
		t.Fatal(err)
	}
	loader := &memConservativeLoader{}
	var values []string
	if err := loader.VisitSiteByPath(C.GeositeName, "cn", func(d *R.Domain) error {
		values = append(values, d.Value)
		if len(values) == 1 && (len(d.Attribute) != 1 || d.Attribute[0].Key != "ads") {
			t.Fatal("attribute changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(values) != 2 || values[0] != "example.cn" || values[1] != "example.org" {
		t.Fatalf("visitor changed fields: %v", values)
	}
	if err := loader.VisitSiteByPath(C.GeositeName, "missing", func(*R.Domain) error { return nil }); err == nil {
		t.Fatal("missing country silently accepted")
	}
}
