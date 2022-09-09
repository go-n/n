package trust

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

type TrustAnchor struct {
	ID        string `xml:"id,attr"`
	Source    string `xml:"source,attr"`
	Zone      string
	KeyDigest []KeyDigest
}

type KeyDigest struct {
	dns.DS
	ID         string     `xml:"id,attr"`
	ValidFrom  *time.Time `xml:"validFrom,attr,omitempty"`
	ValidUntil *time.Time `xml:"validUntil,attr,omitempty"`
}

func (keyDigest KeyDigest) Verify() (err error) {
	if keyDigest.ValidFrom == nil {
		err = fmt.Errorf("KeyDigest %s doesn't have a valid from time", keyDigest.ID)
		return
	}
	now := time.Now()
	if now.Before(*keyDigest.ValidFrom) || (keyDigest.ValidUntil != nil && now.After(*keyDigest.ValidUntil)) {
		err = fmt.Errorf("KeyDigest %s is invalid at the time %v", keyDigest.ID, now)
		return
	}
	return
}
