package geodata

import (
	"fmt"
	"strings"

	"github.com/Dreamacro/clash/component/geodata/router"
	C "github.com/Dreamacro/clash/constant"
)

type siteVisitor interface {
	VisitSiteByPath(string, string, func(*router.Domain) error) error
}

// Mobile DNS streams one decoded Domain at a time; it never holds the complete
// protobuf object graph and MPH build maps simultaneously.
func LoadCompactGeoSiteMatcher(code string) (*router.DomainMatcher, int, error) {
	if code == "" {
		return nil, 0, fmt.Errorf("empty geosite group")
	}
	not := strings.HasPrefix(code, "!")
	code = strings.TrimPrefix(code, "!")
	parts := strings.Split(strings.ToLower(code), "@")
	list := strings.TrimSpace(parts[0])
	attrs := parseAttrs(parts[1:])
	impl, err := getGeoDataLoaderImplementation("memconservative")
	if err != nil {
		return nil, 0, err
	}
	visitor, ok := impl.(siteVisitor)
	if !ok {
		return nil, 0, fmt.Errorf("streaming geosite loader unavailable")
	}
	builder := new(router.CompactDomainBuilder)
	count := 0
	err = visitor.VisitSiteByPath(C.GeositeName, list, func(d *router.Domain) error {
		if !attrs.Match(d) {
			return nil
		}
		count++
		return builder.Add(d)
	})
	if err != nil {
		return nil, 0, err
	}
	return builder.Build(not), count, nil
}
