package trust

import (
	"testing"

	"gopkg.in/n.v0/doh"
)

func TestRootTrustFetcher(t *testing.T) {
	var (
		err         error
		dnsResolver *doh.Resolver
		fetcher     *RootTrustFetcher
	)
	if dnsResolver, err = doh.New(); err != nil {
		t.Error(err)
	}
	if fetcher, err = NewRootTrustFetcher(WithDNSResolver(dnsResolver)); err != nil {
		t.Error(err)
	}
	if _, err = fetcher.FetchVerifyRootKeys(); err != nil {
		t.Error(err)
	}
}
