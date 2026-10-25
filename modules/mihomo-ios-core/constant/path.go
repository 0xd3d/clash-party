package constant

import (
	"os"
	P "path"
	"path/filepath"
	"strings"
)

const Name = "clash"

var (
	GeositeName = "GeoSite.dat"
	GeoipName   = "GeoIP.dat"
)

var supportedMMDBNames = []string{
	"country-lite.mmdb",
	"Country.mmdb",
}

var supportedASNNames = []string{
	"GeoLite2-ASN.mmdb",
}

var supportedGeoIPNames = []string{
	"geoip-lite.dat",
	"geoip.dat",
	"GeoIP.dat",
}

var supportedGeoSiteNames = []string{
	"geosite.dat",
	"GeoSite.dat",
}

// Path is used to get the configuration path
var Path = func() *path {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir, _ = os.Getwd()
	}

	homeDir = P.Join(homeDir, ".config", Name)
	return &path{homeDir: homeDir, configFile: "config.yaml"}
}()

type path struct {
	homeDir    string
	configFile string
}

// SetHomeDir is used to set the configuration path
func SetHomeDir(root string) {
	Path.homeDir = root
}

// SetConfig is used to set the configuration file
func SetConfig(file string) {
	Path.configFile = file
}

func (p *path) HomeDir() string {
	return p.homeDir
}

func (p *path) Config() string {
	return p.configFile
}

// Resolve return a absolute path or a relative path with homedir
func (p *path) Resolve(path string) string {
	if !filepath.IsAbs(path) {
		return filepath.Join(p.HomeDir(), path)
	}
	return path
}

func (p *path) MMDB() string {
	return p.firstExistingAsset(supportedMMDBNames, "Country.mmdb")
}

func (p *path) ASN() string {
	return p.firstExistingAsset(supportedASNNames, "GeoLite2-ASN.mmdb")
}

func (p *path) OldCache() string {
	return P.Join(p.homeDir, ".cache")
}

func (p *path) Cache() string {
	return P.Join(p.homeDir, "cache.db")
}

func (p *path) GeoIP() string {
	path := p.firstExistingAsset(supportedGeoIPNames, "GeoIP.dat")
	GeoipName = P.Base(path)
	return path
}

func (p *path) GeoSite() string {
	path := p.firstExistingAsset(supportedGeoSiteNames, "GeoSite.dat")
	GeositeName = P.Base(path)
	return path
}

func (p *path) firstExistingAsset(candidates []string, fallback string) string {
	files, err := os.ReadDir(p.homeDir)
	if err != nil {
		return P.Join(p.homeDir, fallback)
	}
	for _, fi := range files {
		if fi.IsDir() {
			// 目录则直接跳过
			continue
		}
		for _, candidate := range candidates {
			if strings.EqualFold(fi.Name(), candidate) {
				return P.Join(p.homeDir, fi.Name())
			}
		}
	}
	return P.Join(p.homeDir, fallback)
}

func (p *path) GetAssetLocation(file string) string {
	return P.Join(p.homeDir, file)
}

func (p *path) GetExecutableFullPath() string {
	exePath, err := os.Executable()
	if err != nil {
		return "clash"
	}
	res, _ := filepath.EvalSymlinks(exePath)
	return res
}
