package dnssec_test

import (
	"testing"

	"github.com/miekg/dns"
	"gopkg.in/n.v0/dnssec"
	"gopkg.in/n.v0/dnssec/trust"
	"gopkg.in/n.v0/doh"
)

func TestResolver(t *testing.T) {
	var err error
	dnsResolver, err := doh.New()
	if err != nil {
		t.Error(err)
	}
	trustFetcher, err := trust.NewRootTrustFetcher(trust.WithDNSResolver(dnsResolver))
	if err != nil {
		t.Error(err)
	}
	rootKeys, err := trustFetcher.FetchVerifyRootKeys()
	if err != nil {
		t.Error(err)
	}
	resolver, err := dnssec.New(dnssec.WithTrustAnchors(rootKeys), dnssec.WithDNSResolver(dnsResolver))
	if err != nil {
		t.Error(err)
	}
	msg, err := resolver.Query("blog.cloudflare.com", dns.TypeA)
	if err != nil {
		t.Error(err)
	}
	t.Logf("%# v", msg)
}
