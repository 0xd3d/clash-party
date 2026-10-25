package executor

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/adapter/outbound"
	C "github.com/Dreamacro/clash/constant"
)

func TestReadAppStoredProxySelectionsReadsRuntimeHomeFile(t *testing.T) {
	originalHomeDir := C.Path.HomeDir()
	t.Cleanup(func() {
		C.SetHomeDir(originalHomeDir)
	})

	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "runtime", "mihomo-home")
	if err := os.MkdirAll(homeDir, 0o755); err != nil {
		t.Fatalf("mkdir runtime home: %v", err)
	}

	path := filepath.Join(homeDir, "proxy-selection-preferences.json")
	if err := os.WriteFile(path, []byte(`{"GLOBAL":" HK-01 ","":"ignored","PROXY":"DIRECT"}`), 0o644); err != nil {
		t.Fatalf("write proxy selection preferences: %v", err)
	}

	C.SetHomeDir(homeDir)

	selections, resolvedPath, err := readAppStoredProxySelections()
	if err != nil {
		t.Fatalf("readAppStoredProxySelections returned error: %v", err)
	}

	expected := map[string]string{
		"GLOBAL": "HK-01",
		"PROXY":  "DIRECT",
	}
	if !reflect.DeepEqual(selections, expected) {
		t.Fatalf("expected selections %v, got %v", expected, selections)
	}
	if resolvedPath != path {
		t.Fatalf("expected resolved path %q, got %q", path, resolvedPath)
	}
}

func TestReadAppStoredProxySelectionsFallsBackToRuntimeDirectory(t *testing.T) {
	originalHomeDir := C.Path.HomeDir()
	t.Cleanup(func() {
		C.SetHomeDir(originalHomeDir)
	})

	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "runtime", "mihomo-home")
	if err := os.MkdirAll(homeDir, 0o755); err != nil {
		t.Fatalf("mkdir runtime home: %v", err)
	}

	fallbackPath := filepath.Join(filepath.Dir(homeDir), "proxy-selection-preferences.json")
	if err := os.WriteFile(fallbackPath, []byte(`{"PROXY":"US-01"}`), 0o644); err != nil {
		t.Fatalf("write fallback proxy selection preferences: %v", err)
	}

	C.SetHomeDir(homeDir)

	selections, resolvedPath, err := readAppStoredProxySelections()
	if err != nil {
		t.Fatalf("readAppStoredProxySelections returned error: %v", err)
	}

	expected := map[string]string{"PROXY": "US-01"}
	if !reflect.DeepEqual(selections, expected) {
		t.Fatalf("expected selections %v, got %v", expected, selections)
	}
	if resolvedPath != fallbackPath {
		t.Fatalf("expected fallback path %q, got %q", fallbackPath, resolvedPath)
	}
}

func TestAppStoredProxySelectionsSuppressCacheBackedSelections(t *testing.T) {
	cacheSelections := map[string]string{
		"GLOBAL":      "HK-01",
		"NODE-SELECT": "HK-01",
	}

	appSelections := map[string]string{}

	if restored := cacheSelectionsForRestore(cacheSelections, appSelections, nil); len(restored) != 0 {
		t.Fatalf("expected an existing empty app selection file to suppress cache-backed selections, got %v", restored)
	}
}

func TestMissingAppStoredProxySelectionsAllowCacheBackedSelections(t *testing.T) {
	cacheSelections := map[string]string{
		"GLOBAL": "HK-01",
	}

	restored := cacheSelectionsForRestore(cacheSelections, nil, os.ErrNotExist)
	if !reflect.DeepEqual(restored, cacheSelections) {
		t.Fatalf("expected missing app selection file to allow cache-backed selections, got %v", restored)
	}
}

func TestApplyStoredSelectionPreservesExplicitLeafProxy(t *testing.T) {
	group := newTestSelectableGroup(
		"GLOBAL",
		[]C.Proxy{
			adapter.NewProxy(outbound.NewBase(outbound.BaseOption{
				Name: "HK-01",
				Addr: "okanc.iepl.cac.cab:30401",
				Type: C.Trojan,
			})),
		},
		"",
	)

	if err := applyStoredSelection(group, "HK-01"); err != nil {
		t.Fatalf("applyStoredSelection returned error: %v", err)
	}
	if group.selected != "HK-01" {
		t.Fatalf("expected explicit leaf proxy selection to be applied, got %q", group.selected)
	}
}

func TestApplyStoredSelectionPreservesNestedGroupSelection(t *testing.T) {
	leaf := adapter.NewProxy(outbound.NewBase(outbound.BaseOption{
		Name: "HK-01",
		Addr: "okanc.iepl.cac.cab:30401",
		Type: C.Trojan,
	}))
	inner := adapter.NewProxy(newTestSelectableGroup("NODE-SELECT", []C.Proxy{leaf}, "HK-01"))
	outer := newTestSelectableGroup("GLOBAL", []C.Proxy{inner}, "")

	if err := applyStoredSelection(outer, "NODE-SELECT"); err != nil {
		t.Fatalf("applyStoredSelection returned error: %v", err)
	}
	if outer.selected != "NODE-SELECT" {
		t.Fatalf("expected nested selector to be applied, got %q", outer.selected)
	}
}

type testSelectableGroup struct {
	*outbound.Base
	proxies  []C.Proxy
	selected string
}

func newTestSelectableGroup(name string, proxies []C.Proxy, selected string) *testSelectableGroup {
	return &testSelectableGroup{
		Base: outbound.NewBase(outbound.BaseOption{
			Name: name,
			Type: C.Selector,
		}),
		proxies:  proxies,
		selected: selected,
	}
}

func (g *testSelectableGroup) GetProxies(touch bool) []C.Proxy {
	return g.proxies
}

func (g *testSelectableGroup) Set(name string) error {
	for _, proxy := range g.proxies {
		if proxy.Name() == name {
			g.selected = name
			return nil
		}
	}

	return errors.New("proxy not exist")
}

func (g *testSelectableGroup) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	for _, proxy := range g.proxies {
		if proxy.Name() == g.selected {
			return proxy
		}
	}

	if len(g.proxies) == 0 {
		return nil
	}

	return g.proxies[0]
}
