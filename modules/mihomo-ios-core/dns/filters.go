package dns

import (
	"net/netip"
	"runtime"
	"strings"
	"sync"

	"github.com/Dreamacro/clash/component/geodata"
	"github.com/Dreamacro/clash/component/geodata/router"
	"github.com/Dreamacro/clash/component/mmdb"
	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

type fallbackIPFilter interface {
	Match(netip.Addr) bool
}

type geoipFilter struct {
	code string
}

var geoIPMatcher *router.GeoIPMatcher
var geoIPFilterMMDBLookupWarnOnce sync.Once

func (gf *geoipFilter) Match(ip netip.Addr) bool {
	if !C.GeodataMode {
		record, err := mmdb.LookupCountry(ip.AsSlice())
		if err != nil {
			geoIPFilterMMDBLookupWarnOnce.Do(func() {
				log.Warnln("[GeoIPFilter] skipped MMDB lookup because Country.mmdb could not be loaded: %s", err.Error())
			})
			return false
		}
		return !strings.EqualFold(record.Country.IsoCode, gf.code) && !ip.IsPrivate()
	}

	if geoIPMatcher == nil {
		var err error
		geoIPMatcher, _, err = geodata.LoadGeoIPMatcher("CN")
		if err != nil {
			log.Errorln("[GeoIPFilter] LoadGeoIPMatcher error: %s", err.Error())
			return false
		}
	}
	return !geoIPMatcher.Match(ip.AsSlice())
}

type ipnetFilter struct {
	ipnet *netip.Prefix
}

func (inf *ipnetFilter) Match(ip netip.Addr) bool {
	return inf.ipnet.Contains(ip)
}

type fallbackDomainFilter interface {
	Match(domain string) bool
}

type domainFilter struct {
	tree *trie.DomainTrie[struct{}]
}

func NewDomainFilter(domains []string) *domainFilter {
	df := domainFilter{tree: trie.New[struct{}]()}
	for _, domain := range domains {
		_ = df.tree.Insert(domain, struct{}{})
	}
	df.tree.Optimize()
	return &df
}

func (df *domainFilter) Match(domain string) bool {
	return df.tree.Search(domain) != nil
}

type geoSiteFilter struct {
	matchers []*router.DomainMatcher
}

func NewGeoSite(group string) (fallbackDomainFilter, error) {
	return newGeoSite(group, runtime.GOOS == "ios")
}

func newGeoSite(group string, compact bool) (fallbackDomainFilter, error) {
	if compact {
		// Retain the policy while avoiding synchronous database downloads or loading
		// on the NE startup path. Missing resources temporarily use the main resolver.
		return newLazyGeoSiteFilter(func() (fallbackDomainFilter, error) {
			matcher, _, err := geodata.LoadCompactGeoSiteMatcher(group)
			if err != nil {
				return nil, err
			}
			return &geoSiteFilter{matchers: []*router.DomainMatcher{matcher}}, nil
		}), nil
	}
	if err := geodata.InitGeoSite(); err != nil {
		log.Errorln("can't initial GeoSite: %s", err)
		return nil, err
	}
	matcher, _, err := geodata.LoadGeoSiteMatcher(group)
	if err != nil {
		return nil, err
	}
	filter := &geoSiteFilter{
		matchers: []*router.DomainMatcher{matcher},
	}
	return filter, nil
}

func (gsf *geoSiteFilter) Match(domain string) bool {
	for _, matcher := range gsf.matchers {
		if matcher.ApplyDomain(domain) {
			return true
		}
	}
	return false
}
