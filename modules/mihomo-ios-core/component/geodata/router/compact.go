package router

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Sorted strings avoid the large transient maps/buckets of MPH construction.
// DomainMatcher only consumes whether an index exists, not the original index.
type compactIndexMatcher struct {
	full, suffix, plain []string
	regex               []*regexp.Regexp
}
type CompactDomainBuilder struct{ matcher compactIndexMatcher }

func (b *CompactDomainBuilder) Add(d *Domain) error {
	switch d.Type {
	case Domain_Full:
		b.matcher.full = append(b.matcher.full, strings.ToLower(d.Value))
	case Domain_Domain:
		b.matcher.suffix = append(b.matcher.suffix, strings.ToLower(d.Value))
	case Domain_Plain:
		b.matcher.plain = append(b.matcher.plain, d.Value)
	case Domain_Regex:
		r, err := regexp.Compile(d.Value)
		if err != nil {
			return err
		}
		b.matcher.regex = append(b.matcher.regex, r)
	default:
		return fmt.Errorf("unsupported domain type %v", d.Type)
	}
	return nil
}
func (b *CompactDomainBuilder) Build(not bool) *DomainMatcher {
	if len(b.matcher.full)+len(b.matcher.suffix) == 0 {
		b.matcher.full = append(b.matcher.full, "empty___")
	}
	sort.Strings(b.matcher.full)
	sort.Strings(b.matcher.suffix)
	return &DomainMatcher{matchers: &b.matcher, not: not}
}
func containsSorted(list []string, s string) bool {
	i := sort.SearchStrings(list, s)
	return i < len(list) && list[i] == s
}
func (m *compactIndexMatcher) Match(s string) []uint32 {
	if containsSorted(m.full, s) {
		return []uint32{1}
	}
	for suffix := s; ; {
		if containsSorted(m.suffix, suffix) {
			return []uint32{1}
		}
		dot := strings.IndexByte(suffix, '.')
		if dot < 0 {
			break
		}
		suffix = suffix[dot+1:]
	}
	for _, p := range m.plain {
		if strings.Contains(s, p) {
			return []uint32{1}
		}
	}
	for _, r := range m.regex {
		if r.MatchString(s) {
			return []uint32{1}
		}
	}
	return nil
}
