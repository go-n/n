package doh

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/miekg/dns"
)

type Resolver struct {
	config
}

func New(options ...Option) (resolver *Resolver, err error) {
	resolver = new(Resolver)
	for _, opt := range options {
		opt(&resolver.config)
	}
	if resolver.httpClient == nil {
		resolver.httpClient = http.DefaultClient
	}
	if len(resolver.dohServers) < 1 {
		resolver.dohServers = append(resolver.dohServers, DefaultDoHServers...)
	}
	return
}

func (resolver *Resolver) Query(msg *dns.Msg) (resp *dns.Msg, err error) {
	var (
		data    []byte
		lastErr error
	)
	if data, err = msg.Pack(); err != nil {
		return
	}
	if len(resolver.dohServers) < 1 {
		err = fmt.Errorf("DoH resolver has no servers configured")
		return
	}
	for _, server := range resolver.dohServers {
		if resp, err = resolver.queryServer(server, data); err == nil {
			break
		}
		lastErr = err
	}
	if resp == nil {
		err = lastErr
	}
	return
}

func (resolver *Resolver) queryServer(server string, data []byte) (msg *dns.Msg, err error) {
	var resp *http.Response
	if resp, err = resolver.httpClient.Post(server, "application/dns-message", bytes.NewReader(data)); err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected status code %d when query DoH server %s", resp.StatusCode, server)
		return
	}
	if data, err = ioutil.ReadAll(resp.Body); err != nil {
		return
	}
	ret := new(dns.Msg)
	if err = ret.Unpack(data); err != nil {
		return
	}
	msg = ret
	return
}
