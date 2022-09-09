package torcert

import (
	"crypto/ed25519"
	"time"
)

type Ed25519Cert struct {
	Version CERT_VERSION

	CertType CERT_TYPE

	// A time after which this certificate will no longer be valid.
	ExpirationDate time.Time

	CertKeyType CERT_KEY_TYPE

	// The key authenticated by this certificate
	CertifiedEd25519Key ed25519.PublicKey
	CertifiedKeyHash    []byte

	Extensions []Extension

	Signature []byte

	// The key that signed this certificate. This value may be unset if the
	// certificate has never been checked, and didn't include its own key.
	// SiningKey ed25519.PublicKey

	// The encoded representation of this certificate
	// encoded []byte
}

type CERT_VERSION uint8

const (
	CERT_VERSION_1 CERT_VERSION = 0x01
)

type CERT_TYPE uint8

const (
	// Reserved to avoid conflict with types used in CERTS cells.
	CERT_TYPE_RESERVED_0 CERT_TYPE = 0x00
	CERT_TYPE_RESERVED_1 CERT_TYPE = 0x01
	CERT_TYPE_RESERVED_2 CERT_TYPE = 0x02
	CERT_TYPE_RESERVED_3 CERT_TYPE = 0x03

	// Ed25519 signing key with an identity key
	CERT_TYPE_ID_SIGNING CERT_TYPE = 0x04

	// TLS link certificate signed with ed25519 signing key
	CERT_TYPE_SIGNING_LINK CERT_TYPE = 0x05

	// Ed25519 authentication key signed with ed25519 signing key
	CERT_TYPE_SIGNING_AUTH CERT_TYPE = 0x06

	// Reserved for RSA identity cross-certification
	CERT_TYPE_RSA_ED_CROSSCERT CERT_TYPE = 0x07

	// Onion service: short-term descriptor signing key, signed with blinded public key
	CERT_TYPE_SIGNING_HS_DESC CERT_TYPE = 0x08

	// Onion service: intro point authentication key, cross-certifying the descriptor signing key
	CERT_TYPE_AUTH_HS_IP_KEY CERT_TYPE = 0x09

	// ntor onion key cross-certifying ed25519 identity key
	CERT_TYPE_ONION_ID CERT_TYPE = 0x0A

	// Onion service: ntor-extra encryption key, cross-certifying descriptor signing key
	CERT_TYPE_CROSS_HS_IP_KEYS CERT_TYPE = 0x0B
)

type CERT_KEY_TYPE uint8

const (
	CERT_KEY_TYPE_ED25519        CERT_KEY_TYPE = 0x01
	CERT_KEY_TYPE_SHA256_OF_RSA  CERT_KEY_TYPE = 0x02
	CERT_KEY_TYPE_SHA256_OF_X509 CERT_KEY_TYPE = 0x03
)
