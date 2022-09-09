package dnssec

import (
	"sync"

	"github.com/miekg/dns"
)

type KeyStore struct {
	mutex          sync.RWMutex
	store          map[string]map[uint16]*dns.DNSKEY
	signingZoneMap map[string]string
}

func NewKeyStore(keys map[uint16]*dns.DNSKEY) *KeyStore {
	ks := &KeyStore{
		store:          make(map[string]map[uint16]*dns.DNSKEY),
		signingZoneMap: make(map[string]string),
	}
	for _, key := range keys {
		ks.addLocked(key)
	}
	return ks
}

func (ks *KeyStore) Get(fqdn string) (signingZoneFqdn string, signingZoneKeys map[uint16]*dns.DNSKEY) {
	ks.mutex.RLock()
	signingZoneFqdn = ks.signingZoneMap[fqdn]
	signingZoneKeys = ks.store[fqdn]
	ks.mutex.RUnlock()
	return
}

func (ks *KeyStore) Add(childZoneFqdn, signingZoneFqdn string, signingZoneKeys map[uint16]*dns.DNSKEY) {
	ks.mutex.Lock()
	ks.signingZoneMap[childZoneFqdn] = signingZoneFqdn
	for _, key := range signingZoneKeys {
		ks.addLocked(key)
	}
	ks.mutex.Unlock()
}

func (ks *KeyStore) SetEmptyZone(fqdn string) {
	ks.mutex.Lock()
	signingZoneFqdn := ks.signingZoneMap[fqdn]
	delete(ks.store, signingZoneFqdn)
	delete(ks.signingZoneMap, fqdn)
	ks.mutex.Unlock()
}

func (ks *KeyStore) addLocked(key *dns.DNSKEY) {
	fqdn := dns.Fqdn(key.Hdr.Name)
	if ks.store[fqdn] == nil {
		ks.store[fqdn] = make(map[uint16]*dns.DNSKEY)
	}
	ks.store[fqdn][key.KeyTag()] = key
}
