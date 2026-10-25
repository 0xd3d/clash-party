package dns

import (
	"sync"
	"time"
)

// Loading happens outside the DNS request and startup goroutines. Never fetch a
// database from this path; the app resource manager owns validated downloads.
type lazyGeoSiteFilter struct {
	mu      sync.Mutex
	matcher fallbackDomainFilter
	loading bool
	retryAt time.Time
	load    func() (fallbackDomainFilter, error)
}

func newLazyGeoSiteFilter(load func() (fallbackDomainFilter, error)) *lazyGeoSiteFilter {
	return &lazyGeoSiteFilter{load: load}
}
func (f *lazyGeoSiteFilter) Match(domain string) bool {
	matched, ready := f.matchIfReady(domain)
	return ready && matched
}
func (f *lazyGeoSiteFilter) matchIfReady(domain string) (bool, bool) {
	f.mu.Lock()
	matcher := f.matcher
	if matcher == nil && !f.loading && !time.Now().Before(f.retryAt) {
		f.loading = true
		go func() {
			loaded, err := f.load()
			f.mu.Lock()
			defer f.mu.Unlock()
			f.loading = false
			if err == nil {
				f.matcher = loaded
			} else {
				f.retryAt = time.Now().Add(30 * time.Second)
			}
		}()
	}
	f.mu.Unlock()
	if matcher == nil {
		return false, false
	}
	return matcher.Match(domain), true
}
