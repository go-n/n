package trust

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
)

var (
	//go:embed ICANN_ROOT_CA.crt
	ICANN_ROOT_CA_PEM  []byte
	ICANN_ROOT_CA_POOL *x509.CertPool
)

const (
	URL_ROOT_ANCHORS           = "https://data.iana.org/root-anchors/root-anchors.xml"
	URL_ROOT_ANCHORS_SIGNATURE = "https://data.iana.org/root-anchors/root-anchors.p7s"
	URL_ROOT_ZONE              = "https://www.internic.net/domain/root.zone"
)

func init() {
	p, _ := pem.Decode(ICANN_ROOT_CA_PEM)
	ca, _ := x509.ParseCertificate(p.Bytes)
	ICANN_ROOT_CA_POOL = x509.NewCertPool()
	ICANN_ROOT_CA_POOL.AddCert(ca)
}
