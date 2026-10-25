package mmdb

import (
	clashHttp "github.com/Dreamacro/clash/component/http"
	"github.com/oschwald/geoip2-golang"
	"io"
	"net/http"
	"os"
	"sync"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

var (
	mmdb      *geoip2.Reader
	asnReader *geoip2.Reader
	mmdbMu    sync.RWMutex
	asnMu     sync.RWMutex
)

func LoadFromBytes(buffer []byte) {
	reader, err := geoip2.FromBytes(buffer)
	if err != nil {
		log.Fatalln("Can't load mmdb: %s", err.Error())
	}
	setCountryReader(reader)
}

func Verify() bool {
	instance, err := geoip2.Open(C.Path.MMDB())
	if err == nil {
		instance.Close()
	}
	return err == nil
}

func Instance() *geoip2.Reader {
	if err := WarmCountryCache(); err != nil {
		log.Fatalln("Can't load mmdb: %s", err.Error())
	}

	return cachedCountryReader()
}

func LookupCountry(ip []byte) (*geoip2.Country, error) {
	if instance := cachedCountryReader(); instance != nil {
		return instance.Country(ip)
	}

	if err := WarmCountryCache(); err != nil {
		return nil, err
	}

	return cachedCountryReader().Country(ip)
}

func LookupCountryFromCache(ip []byte) (*geoip2.Country, bool, error) {
	instance := cachedCountryReader()
	if instance == nil {
		return nil, false, nil
	}
	record, err := instance.Country(ip)
	return record, true, err
}

func WarmCountryCache() error {
	if cachedCountryReader() != nil {
		return nil
	}

	mmdbMu.Lock()
	defer mmdbMu.Unlock()
	if mmdb != nil {
		return nil
	}

	instance, err := geoip2.Open(C.Path.MMDB())
	if err != nil {
		return err
	}
	mmdb = instance
	return nil
}

func ClearCountryCache() {
	mmdbMu.Lock()
	defer mmdbMu.Unlock()
	if mmdb != nil {
		_ = mmdb.Close()
		mmdb = nil
	}
}

func LookupASN(ip []byte) (*geoip2.ASN, error) {
	if err := WarmASNCache(); err != nil {
		return nil, err
	}

	asnMu.RLock()
	instance := asnReader
	asnMu.RUnlock()
	return instance.ASN(ip)
}

func LookupASNFromCache(ip []byte) (*geoip2.ASN, bool, error) {
	asnMu.RLock()
	instance := asnReader
	asnMu.RUnlock()
	if instance == nil {
		return nil, false, nil
	}
	record, err := instance.ASN(ip)
	return record, true, err
}

func WarmASNCache() error {
	if cachedASNReader() != nil {
		return nil
	}

	asnMu.Lock()
	defer asnMu.Unlock()
	if asnReader == nil {
		instance, err := geoip2.Open(C.Path.ASN())
		if err != nil {
			return err
		}
		asnReader = instance
	}

	return nil
}

func ClearASNCache() {
	asnMu.Lock()
	defer asnMu.Unlock()
	if asnReader != nil {
		_ = asnReader.Close()
		asnReader = nil
	}
}

func ClearCache() {
	ClearCountryCache()
	ClearASNCache()
}

func cachedCountryReader() *geoip2.Reader {
	mmdbMu.RLock()
	defer mmdbMu.RUnlock()
	return mmdb
}

func setCountryReader(reader *geoip2.Reader) {
	mmdbMu.Lock()
	defer mmdbMu.Unlock()
	if mmdb != nil && mmdb != reader {
		_ = mmdb.Close()
	}
	mmdb = reader
}

func cachedASNReader() *geoip2.Reader {
	asnMu.RLock()
	defer asnMu.RUnlock()
	return asnReader
}

func DownloadMMDB(path string) (err error) {
	if clashHttp.RequireRuleResourceDownloads {
		return clashHttp.DownloadResource(C.MmdbUrl, path)
	}
	resp, err := http.Get(C.MmdbUrl)
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

func DownloadASN(path string) (err error) {
	if clashHttp.RequireRuleResourceDownloads {
		return clashHttp.DownloadResource(C.ASNUrl, path)
	}
	resp, err := http.Get(C.ASNUrl)
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
