package geodata

import (
	"fmt"
	clashHttp "github.com/Dreamacro/clash/component/http"
	"github.com/Dreamacro/clash/component/mmdb"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"io"
	"net/http"
	"os"
)

var initGeoSite bool
var initGeoIP int

var (
	removeFile   = os.Remove
	verifyMMDB   = mmdb.Verify
	downloadMMDB = mmdb.DownloadMMDB
)

func InitGeoSite() error {
	if _, err := os.Stat(C.Path.GeoSite()); os.IsNotExist(err) {
		log.Infoln("Can't find GeoSite.dat, start download")
		if err := downloadGeoSite(C.Path.GeoSite()); err != nil {
			return fmt.Errorf("can't download GeoSite.dat: %s", err.Error())
		}
		log.Infoln("Download GeoSite.dat finish")
		initGeoSite = false
	}
	if !initGeoSite {
		if err := Verify(C.GeositeName); err != nil {
			log.Warnln("GeoSite.dat invalid, remove and download: %s", err)
			if err := removeInvalidGeoDataFile(C.Path.GeoSite(), "GeoSite.dat"); err != nil {
				return err
			}
			if err := downloadGeoSite(C.Path.GeoSite()); err != nil {
				return fmt.Errorf("can't download GeoSite.dat: %s", err.Error())
			}
		}
		initGeoSite = true
	}
	return nil
}

func downloadGeoSite(path string) (err error) {
	if clashHttp.RequireRuleResourceDownloads {
		return clashHttp.DownloadResource(C.GeoSiteUrl, path)
	}
	resp, err := http.Get(C.GeoSiteUrl)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)

	return err
}

func downloadGeoIP(path string) (err error) {
	if clashHttp.RequireRuleResourceDownloads {
		return clashHttp.DownloadResource(C.GeoIpUrl, path)
	}
	resp, err := http.Get(C.GeoIpUrl)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)

	return err
}

func InitGeoIP() error {
	if C.GeodataMode {
		if _, err := os.Stat(C.Path.GeoIP()); os.IsNotExist(err) {
			log.Infoln("Can't find GeoIP.dat, start download")
			if err := downloadGeoIP(C.Path.GeoIP()); err != nil {
				return fmt.Errorf("can't download GeoIP.dat: %s", err.Error())
			}
			log.Infoln("Download GeoIP.dat finish")
			initGeoIP = 0
		}

		if initGeoIP != 1 {
			if err := Verify(C.GeoipName); err != nil {
				log.Warnln("GeoIP.dat invalid, remove and download: %s", err)
				if err := removeInvalidGeoDataFile(C.Path.GeoIP(), "GeoIP.dat"); err != nil {
					return err
				}
				if err := downloadGeoIP(C.Path.GeoIP()); err != nil {
					return fmt.Errorf("can't download GeoIP.dat: %s", err.Error())
				}
			}
			initGeoIP = 1
		}
		return nil
	}

	mmdbPath := C.Path.MMDB()
	if mmdbPath == "" {
		return fmt.Errorf("mmdb path is empty")
	}

	if _, err := os.Stat(mmdbPath); os.IsNotExist(err) {
		log.Infoln("Can't find MMDB, start download")
		if err := downloadMMDB(mmdbPath); err != nil {
			return fmt.Errorf("can't download MMDB: %s", err.Error())
		}
	}

	if initGeoIP != 2 {
		if !verifyMMDB() {
			log.Warnln("MMDB invalid, remove and download")
			if err := removeInvalidGeoDataFile(mmdbPath, "MMDB"); err != nil {
				return err
			}
			if err := downloadMMDB(mmdbPath); err != nil {
				return fmt.Errorf("can't download MMDB: %s", err.Error())
			}
		}
		initGeoIP = 2
	}
	return nil
}

func removeInvalidGeoDataFile(path string, description string) error {
	if err := removeFile(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("can't remove invalid %s: %s", description, err.Error())
	}
	return nil
}
