package doh

import "net/http"

var DefaultDoHServers = []string{
	"https://1.1.1.1/dns-query",
	"https://8.8.8.8/dns-query",
	"https://9.9.9.9:5053/dns-query",
}

type config struct {
	httpClient *http.Client
	dohServers []string
}

type Option func(*config)

func WithHTTPClient(client *http.Client) Option {
	return func(c *config) {
		c.httpClient = client
	}
}

func WithDoHServers(urls []string) Option {
	return func(c *config) {
		c.dohServers = append(c.dohServers, urls...)
	}
}
