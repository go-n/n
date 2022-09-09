package trust

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"go.mozilla.org/pkcs7"
	"gopkg.in/n.v0/dnssec"
)

var (
	cachedRootKeys      map[uint16]*dns.DNSKEY
	cachedRootKeysMutex sync.RWMutex
)

type RootTrustFetcher struct {
	config
}

func NewRootTrustFetcher(options ...Option) (fetcher *RootTrustFetcher, err error) {
	fetcher = new(RootTrustFetcher)
	for _, opt := range options {
		opt(&fetcher.config)
	}
	if fetcher.httpClient == nil {
		fetcher.httpClient = http.DefaultClient
	}
	if fetcher.dnsResolver == nil {
		err = fmt.Errorf("no DNS resolver provided for creating RootTrustFetcher")
		return
	}
	return
}

func (rtf *RootTrustFetcher) FetchVerifyRootKeys() (rootKeys map[uint16]*dns.DNSKEY, err error) {
	var (
		msg                   *dns.Msg
		trustAnchors          TrustAnchor
		trustAnchorsXML       []byte
		trustAnchorsSignature []byte
		trustAnchorsP7        *pkcs7.PKCS7
		trustKeyDigests       map[uint16]*KeyDigest
	)

	cachedRootKeysMutex.RLock()
	rootKeys = cachedRootKeys
	cachedRootKeysMutex.RUnlock()

	if len(rootKeys) > 0 {
		return
	}

	if trustAnchorsXML, err = rtf.fetchURL(URL_ROOT_ANCHORS); err != nil {
		return
	}
	if trustAnchorsSignature, err = rtf.fetchURL(URL_ROOT_ANCHORS_SIGNATURE); err != nil {
		return
	}
	if trustAnchorsP7, err = pkcs7.Parse(trustAnchorsSignature); err != nil {
		return
	}
	// attach content that was being signed
	trustAnchorsP7.Content = trustAnchorsXML
	if err = trustAnchorsP7.VerifyWithChain(ICANN_ROOT_CA_POOL); err != nil {
		return
	}
	if err = xml.Unmarshal(trustAnchorsXML, &trustAnchors); err != nil {
		return
	}

	// filter out invalid trust anchors by valid time ranges
	trustKeyDigests = make(map[uint16]*KeyDigest)
	for i := range trustAnchors.KeyDigest {
		keyDigest := &trustAnchors.KeyDigest[i]
		if err = keyDigest.Verify(); err != nil {
			err = nil
			continue
		}
		trustKeyDigests[keyDigest.KeyTag] = keyDigest
	}

	msg = new(dns.Msg)
	msg.SetEdns0(4096, true)
	msg.SetQuestion(".", dns.TypeDNSKEY)
	if msg, err = rtf.dnsResolver.Query(msg); err != nil {
		return
	}

	rootKeys = make(map[uint16]*dns.DNSKEY)

	for _, ans := range msg.Answer {
		if dnskey, ok := ans.(*dns.DNSKEY); ok {
			if keyDigest, ok := trustKeyDigests[dnskey.KeyTag()]; ok {
				ds := dnskey.ToDS(keyDigest.DigestType)
				if strings.EqualFold(ds.Digest, keyDigest.Digest) {
					rootKeys[dnskey.KeyTag()] = dnskey
				}
			}
		}
	}
	if len(rootKeys) < 1 {
		err = fmt.Errorf("failed to find any DNSSEC root key")
		return
	}

	if msg, err = dnssec.VerifyMsgSignature(msg, ".", rootKeys); err != nil {
		return
	}

	for _, rr := range msg.Answer {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			rootKeys[dnskey.KeyTag()] = dnskey
		}
	}

	cachedRootKeysMutex.Lock()
	cachedRootKeys = rootKeys
	cachedRootKeysMutex.Unlock()
	return
}

func (rtf *RootTrustFetcher) fetchURL(url string) (data []byte, err error) {
	resp, err := rtf.httpClient.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected status code %d when getting %s", resp.StatusCode, url)
		return
	}
	if data, err = io.ReadAll(resp.Body); err != nil {
		err = fmt.Errorf("failed to read body from http response of %s: %w", url, err)
		return
	}
	return
}
