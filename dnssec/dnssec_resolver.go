package dnssec

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

type Resolver struct {
	config
	keystore *KeyStore
}

func New(options ...Option) (resolver *Resolver, err error) {
	resolver = new(Resolver)
	for _, opt := range options {
		opt(&resolver.config)
	}
	if len(resolver.trustAnchors) < 1 {
		err = fmt.Errorf("no DNSSEC trust anchor keys provided for creating DNSSEC resolver")
		return
	}
	if resolver.dnsResolver == nil {
		err = fmt.Errorf("no DNS resolver provided for creating DNSSEC resolver")
		return
	}
	resolver.keystore = NewKeyStore(resolver.trustAnchors)
	return
}

func (resolver *Resolver) Query(name string, typ uint16) (msg *dns.Msg, err error) {
	fqdn := dns.Fqdn(name)
	msg = new(dns.Msg)
	msg.SetEdns0(4096, true)
	msg.SetQuestion(fqdn, typ)
	if msg, err = resolver.dnsResolver.Query(msg); err != nil {
		return
	}
	signingZoneFQDN, signingZoneKeys, err := resolver.GetVerifiedZoneKeys(fqdn)
	if err != nil {
		return
	}
	if _, err = VerifyMsgSignature(msg, signingZoneFQDN, signingZoneKeys); err != nil {
		return
	}
	return
}

func (resolver *Resolver) GetVerifiedZoneKeys(fqdn string) (signingZoneFQDN string, signingZoneKeys map[uint16]*dns.DNSKEY, err error) {
	signingZoneFQDN, signingZoneKeys = resolver.keystore.Get(fqdn)
	if signingZoneKeys != nil {
		return
	}
	if fqdn == "." {
		err = fmt.Errorf("could not find and verify root DNS keys, probably no root trust anchor was provided")
		return
	}
	var parentZoneFqdn string
	var parentKeys map[uint16]*dns.DNSKEY
	if parentZoneFqdn, parentKeys, err = resolver.GetVerifiedZoneKeys(getParentFQDN(fqdn)); err != nil {
		return
	}

	var dnskeyMsg, dsMsg *dns.Msg

	msg := new(dns.Msg)
	msg.SetEdns0(4096, true)
	msg.SetQuestion(fqdn, dns.TypeDNSKEY)
	if dnskeyMsg, err = resolver.dnsResolver.Query(msg); err != nil {
		return
	}

	msg = new(dns.Msg)
	msg.SetEdns0(4096, true)
	msg.SetQuestion(fqdn, dns.TypeDS)
	if dsMsg, err = resolver.dnsResolver.Query(msg); err != nil {
		return
	}

	// [rfc4035] 5.2. Authenticating Referrals

	// Once the apex DNSKEY RRset for a signed parent zone has been
	// authenticated, DS RRsets can be used to authenticate the delegation
	// to a signed child zone.  A DS RR identifies a DNSKEY RR in the child
	// zone's apex DNSKEY RRset and contains a cryptographic digest of the
	// child zone's DNSKEY RR.  Use of a strong cryptographic digest
	// algorithm ensures that it is computationally infeasible for an
	// adversary to generate a DNSKEY RR that matches the digest.  Thus,
	// authenticating the digest allows a resolver to authenticate the
	// matching DNSKEY RR.  The resolver can then use this child DNSKEY RR
	// to authenticate the entire child apex DNSKEY RRset.

	// Given a DS RR for a delegation, the child zone's apex DNSKEY RRset
	// can be authenticated if all of the following hold:

	// o  The DS RR has been authenticated using some DNSKEY RR in the
	//    parent's apex DNSKEY RRset (see Section 5.3).

	if dsMsg, err = VerifyMsgSignature(dsMsg, parentZoneFqdn, parentKeys); err != nil {
		return
	}

	if len(dsMsg.Answer) == 0 {
		// try to verify no answer with NSEC RR in Ns section
		for _, rr := range dsMsg.Ns {
			if nsec, ok := rr.(*dns.NSEC); ok {
				if strings.EqualFold(nsec.Header().Name, fqdn) {
					// fqdn has no zone, should use its parent zone
					signingZoneFQDN = parentZoneFqdn
					signingZoneKeys = parentKeys
					resolver.keystore.Add(fqdn, signingZoneFQDN, signingZoneKeys)
					return
				}
			}
		}
		// what no NSEC? Could be bogus
		err = ErrBogus
		return
	}

	dsRRMap := make(map[uint16]*dns.DS)
	for _, rr := range dsMsg.Answer {
		if ds, ok := rr.(*dns.DS); ok {
			dsRRMap[ds.KeyTag] = ds
		}
	}

	dnskeyRRMap := make(map[uint16]*dns.DNSKEY)
	for _, rr := range dnskeyMsg.Answer {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			dnskeyRRMap[dnskey.KeyTag()] = dnskey
		}
	}

	// o  The Algorithm and Key Tag in the DS RR match the Algorithm field
	//    and the key tag of a DNSKEY RR in the child zone's apex DNSKEY
	//    RRset, and, when the DNSKEY RR's owner name and RDATA are hashed
	//    using the digest algorithm specified in the DS RR's Digest Type
	//    field, the resulting digest value matches the Digest field of the
	//    DS RR.

	zoneKeys := make(map[uint16]*dns.DNSKEY)

	for _, dnskey := range dnskeyRRMap {
		// o  The matching DNSKEY RR in the child zone has the Zone Flag bit
		//    set.
		if dnskey.Flags&dns.ZONE != 0 {
			if ds := dsRRMap[dnskey.KeyTag()]; ds != nil && dnskey.Algorithm == ds.Algorithm {
				dsExpect := dnskey.ToDS(ds.DigestType)
				if strings.EqualFold(ds.Digest, dsExpect.Digest) {
					zoneKeys[dnskey.KeyTag()] = dnskey
				}
			}
		}
	}

	// o  The corresponding private key has signed the child zone's
	//    apex DNSKEY RRset, and the resulting RRSIG RR authenticates the
	//    child zone's apex DNSKEY RRset.

	if dnskeyMsg, err = VerifyMsgSignature(dnskeyMsg, fqdn, zoneKeys); err != nil {
		return
	}

	for _, rr := range dnskeyMsg.Answer {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			zoneKeys[dnskey.KeyTag()] = dnskey
		}
	}

	signingZoneFQDN = fqdn
	signingZoneKeys = zoneKeys
	resolver.keystore.Add(fqdn, signingZoneFQDN, signingZoneKeys)
	return
}

func getParentFQDN(fqdn string) string {
	parentZoneIndex, _ := dns.NextLabel(fqdn, 0)
	return dns.Fqdn(fqdn[parentZoneIndex:])
}
