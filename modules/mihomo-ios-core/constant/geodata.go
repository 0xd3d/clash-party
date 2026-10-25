package constant

const (
	DefaultGeoIPUrl   = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip-lite.dat"
	DefaultGeoSiteUrl = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat"
	DefaultMmdbUrl    = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country-lite.mmdb"
	DefaultASNUrl     = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb"
)

var (
	GeodataMode bool
	GeoIpUrl    string
	MmdbUrl     string
	GeoSiteUrl  string
	ASNUrl      string
)
