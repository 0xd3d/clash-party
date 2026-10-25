package config

import (
	"fmt"
	"github.com/Dreamacro/clash/component/geodata"
	_ "github.com/Dreamacro/clash/component/geodata/standard"
	clashHttp "github.com/Dreamacro/clash/component/http"
	"github.com/Dreamacro/clash/component/mmdb"
	C "github.com/Dreamacro/clash/constant"
	"github.com/oschwald/geoip2-golang"
	"io"
	"net/http"
	"os"
	"runtime"
)

func UpdateGeoDatabases() error {
	defer runtime.GC()
	geoLoader, err := geodata.GetGeoDataLoader("standard")
	if err != nil {
		return err
	}

	if C.GeodataMode {
		data, err := downloadForBytes(C.GeoIpUrl)
		if err != nil {
			return fmt.Errorf("can't download GeoIP database file: %w", err)
		}

		if _, err = geoLoader.LoadIPByBytes(data, "cn"); err != nil {
			return fmt.Errorf("invalid GeoIP database file: %s", err)
		}

		if err := saveFile(data, C.Path.GeoIP()); err != nil {
			return fmt.Errorf("can't save GeoIP database file: %w", err)
		}

	} else {
		data, err := downloadForBytes(C.MmdbUrl)
		if err != nil {
			return fmt.Errorf("can't download MMDB database file: %w", err)
		}

		instance, err := geoip2.FromBytes(data)
		if err != nil {
			return fmt.Errorf("invalid MMDB database file: %s", err)
		}
		_ = instance.Close()

		if err := saveFile(data, C.Path.MMDB()); err != nil {
			return fmt.Errorf("can't save MMDB database file: %w", err)
		}
	}

	data, err := downloadForBytes(C.GeoSiteUrl)
	if err != nil {
		return fmt.Errorf("can't download GeoSite database file: %w", err)
	}

	if _, err = geoLoader.LoadSiteByBytes(data, "cn"); err != nil {
		return fmt.Errorf("invalid GeoSite database file: %s", err)
	}

	if err := saveFile(data, C.Path.GeoSite()); err != nil {
		return fmt.Errorf("can't save GeoSite database file: %w", err)
	}

	if C.ASNUrl != "" {
		data, err := downloadForBytes(C.ASNUrl)
		if err != nil {
			return fmt.Errorf("can't download ASN database file: %w", err)
		}

		instance, err := geoip2.FromBytes(data)
		if err != nil {
			return fmt.Errorf("invalid ASN database file: %s", err)
		}
		_ = instance.Close()

		if err := saveFile(data, C.Path.ASN()); err != nil {
			return fmt.Errorf("can't save ASN database file: %w", err)
		}
	}

	geodata.ClearCache()
	mmdb.ClearCache()

	return nil
}

func downloadForBytes(url string) ([]byte, error) {
	resp, err := clashHttp.GetResource(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("unexpected HTTP status %s", resp.Status)
	}

	return io.ReadAll(resp.Body)
}

func saveFile(bytes []byte, path string) error {
	return os.WriteFile(path, bytes, 0o644)
}
