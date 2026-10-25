package config

import (
	"fmt"
	"github.com/Dreamacro/clash/common/mobilephase"
	"github.com/Dreamacro/clash/component/geodata"
	"os"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

// Init prepare necessary files
func Init(dir string) error {
	log.Infoln("config.Init entered.")

	// initial homedir
	log.Infoln("config.Init is checking the home directory.")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		log.Infoln("config.Init is creating the home directory.")
		if err := os.MkdirAll(dir, 0o777); err != nil {
			return fmt.Errorf("can't create config directory %s: %s", dir, err.Error())
		}
	}

	// initial config.yaml
	log.Infoln("config.Init is checking the main config file.")
	if _, err := os.Stat(C.Path.Config()); os.IsNotExist(err) {
		log.Infoln("Can't find config, create a initial config file")
		f, err := os.OpenFile(C.Path.Config(), os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("can't create file %s: %s", C.Path.Config(), err.Error())
		}
		f.Write([]byte(`mixed-port: 7890`))
		f.Close()
	}
	log.Infoln("config.Init is reading the main config file for bootstrap metadata.")
	buf, _ := os.ReadFile(C.Path.Config())
	log.Infoln("config.Init is unmarshalling the raw config for bootstrap metadata.")
	rawCfg, err := UnmarshalRawConfig(buf)
	if err != nil {
		log.Errorln(err.Error())
		return fmt.Errorf("configuration file %s test failed: %w", C.Path.Config(), err)
	}
	if !C.GeodataMode {
		C.GeodataMode = rawCfg.GeodataMode
	}
	C.GeoIpUrl = rawCfg.GeoXUrl.GeoIp
	C.GeoSiteUrl = rawCfg.GeoXUrl.GeoSite
	C.MmdbUrl = rawCfg.GeoXUrl.Mmdb
	C.ASNUrl = rawCfg.GeoXUrl.ASN
	log.Infoln("config.Init finished loading bootstrap metadata from the raw config.")

	if mobilephase.FastStartupEnabled() {
		log.Infoln("Skipping GeoIP/MMDB initialization during iOS fast startup")
		return nil
	}

	// initial GeoIP
	log.Infoln("config.Init is calling geodata.InitGeoIP.")
	if err := geodata.InitGeoIP(); err != nil {
		return fmt.Errorf("can't initial GeoIP: %w", err)
	}

	log.Infoln("config.Init completed successfully.")
	return nil
}
