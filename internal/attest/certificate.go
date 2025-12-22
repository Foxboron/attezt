package attest

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	encasn1 "encoding/asn1"
	"time"

	"github.com/google/go-tpm/tpm2"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidSAN                 = encasn1.ObjectIdentifier{2, 5, 29, 17}
	oidTCGKpAIKCertificate = encasn1.ObjectIdentifier{2, 23, 133, 8, 3}
)

type AKCertificate struct {
	cert *x509.Certificate
}

func NewAKCertificate(ak *tpm2.TPMTPublic) (*AKCertificate, error) {
	key, err := tpm2.Pub(*ak)
	if err != nil {
		return nil, err
	}
	return &AKCertificate{
		&x509.Certificate{
			PublicKey:          key,
			IsCA:               false,
			NotBefore:          time.Now().Add(-10 * time.Second),
			NotAfter:           time.Now().AddDate(10, 0, 0),
			UnknownExtKeyUsage: []encasn1.ObjectIdentifier{oidTCGKpAIKCertificate},
			Extensions:         []pkix.Extension{},
			ExtraExtensions:    []pkix.Extension{},
		},
	}, nil
}

func (a *AKCertificate) PublicKey() crypto.PublicKey {
	return a.cert.PublicKey
}

// Cert returns the x509 cert
func (a *AKCertificate) Cert() *x509.Certificate {
	return a.cert
}

func (a *AKCertificate) SetExtensions(uri string, t *TPMInfo) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(asn1.Tag(6).ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(uri))
		})
		b.AddASN1(asn1.Tag(4).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddBytes(t.MarshalASN())
		})
	})
	by := b.BytesOrPanic()
	a.cert.ExtraExtensions = append(a.cert.ExtraExtensions, pkix.Extension{
		Id:       oidSAN,
		Critical: false,
		Value:    by,
	})
}
