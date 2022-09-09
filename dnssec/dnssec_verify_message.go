package dnssec

import (
	"errors"

	"github.com/miekg/dns"
)

// [rfc4035] 4.3.  Determining Security Status of Data
//
// A security-aware resolver MUST be able to determine whether it should expect
// a particular RRset to be signed. More precisely, a security-aware resolver
// must be able to distinguish between four cases:
type SecurityStatus error

var (
	// An RRset for which the resolver is able to build a chain of signed DNSKEY
	// and DS RRs from a trusted security anchor to the RRset. In this case, the
	// RRset should be signed and is subject to signature validation.
	Secure SecurityStatus = nil

	// An RRset for which the resolver knows that it has no chain of signed
	// DNSKEY and DS RRs from any trusted starting point to the RRset. This can
	// occur when the target RRset lies in an unsigned zone or in a descendent
	// of an unsigned zone.  In this case, the RRset may or may not be signed,
	// but the resolver will not be able to verify the signature.
	ErrInsecure SecurityStatus = errors.New("insecure RRSet, DNSSEC not enabled in part of the chain of trust")

	// An RRset for which the resolver believes that it ought to be able to
	// establish a chain of trust but for which it is unable to do so, either
	// due to signatures that for some reason fail to validate or due to missing
	// data that the relevant DNSSEC RRs indicate should be present.  This case
	// may indicate an attack but may also indicate a configuration error or
	// some form of data corruption.
	ErrBogus SecurityStatus = errors.New("bogus RRSet, DNSSEC maybe hijacked or misconfigured")

	// An RRset for which the resolver is not able to determine whether the
	// RRset should be signed, as the resolver is not able to obtain the
	// necessary DNSSEC RRs. This can occur when the security-aware resolver is
	// not able to contact security-aware name servers for the relevant zones.
	ErrIndeterminate SecurityStatus = errors.New("indeterminated security status, DNSSEC info not availiable due to network error")
)

func VerifyMsgSignature(msgToVerify *dns.Msg, expectedSignerFqdn string, trustedSignerKeys map[uint16]*dns.DNSKEY) (signedMsg *dns.Msg, err error) {
	// [rfc4035] 5.3. Authenticating an RRset with an RRSIG RR
	// 5.3.1. Checking the RRSIG RR Validity

	var (
		rrset       []dns.RR
		rrsigs      = make(map[uint16]*dns.RRSIG)
		rrsetSigned = make(map[uint16][]dns.RR)
		msg         = &dns.Msg{
			MsgHdr:   msgToVerify.MsgHdr,
			Compress: msgToVerify.Compress,
			Question: msgToVerify.Question,
			Extra:    msgToVerify.Extra,
		}
	)

	if len(msgToVerify.Answer) > 0 {
		rrset = msgToVerify.Answer
	} else {
		rrset = msgToVerify.Ns
	}

	for _, rr := range rrset {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			rrsigs[rrsig.KeyTag] = rrsig
		}
	}

	if len(rrsigs) == 0 {
		err = ErrBogus
		return
	}

	err = ErrInsecure

	for keytag, rrsig := range rrsigs {
		if len(rrsetSigned[rrsig.TypeCovered]) > 0 {
			continue
		}
		if dnskey, ok := trustedSignerKeys[keytag]; ok {
			// A security-aware resolver can use an RRSIG RR to authenticate an
			// RRset if all of the following conditions hold:

			// o  The RRSIG RR and the RRset MUST have the same owner name and
			//    the same class.

			subrrset := extractRRSet(rrset, rrsig.TypeCovered)
			if len(subrrset) == 0 {
				continue
			}

			if err = rrsig.Verify(dnskey, subrrset); err != nil {
				return
			} else {
				rrsetSigned[rrsig.TypeCovered] = subrrset
				err = Secure
			}
		}
	}

	if err == Secure && len(rrsetSigned) > 0 {
		for _, rrset := range rrsetSigned {
			if len(msgToVerify.Answer) > 0 {
				msg.Answer = append(msg.Answer, rrset...)
			} else {
				msg.Ns = append(msg.Ns, rrset...)
			}
		}
		signedMsg = msg
	}

	return
}

func extractRRSet(in []dns.RR, t uint16) (out []dns.RR) {
	for _, rr := range in {
		if rr.Header().Rrtype == t {
			out = append(out, rr)
		}
	}
	return
}
