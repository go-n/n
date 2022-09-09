package trust

import (
	"net/http"

	"github.com/miekg/dns"
)

type config struct {
	httpClient  *http.Client
	dnsResolver DNSResolver
}

type DNSResolver interface {
	Query(msg *dns.Msg) (resp *dns.Msg, err error)
}

type Option func(*config)

func WithDNSResolver(resolver DNSResolver) Option {
	return func(c *config) {
		c.dnsResolver = resolver
	}
}
