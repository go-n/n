package dnssec

import "github.com/miekg/dns"

type config struct {
	trustAnchors map[uint16]*dns.DNSKEY
	dnsResolver  DNSResolver
}

type DNSResolver interface {
	Query(msg *dns.Msg) (resp *dns.Msg, err error)
}

type Option func(*config)

func WithTrustAnchors(keys map[uint16]*dns.DNSKEY) Option {
	return func(c *config) {
		c.trustAnchors = keys
	}
}

func WithDNSResolver(resolver DNSResolver) Option {
	return func(c *config) {
		c.dnsResolver = resolver
	}
}
