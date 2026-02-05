package testutils

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/foxboron/attezt/internal/attest"
	"github.com/foxboron/attezt/internal/certs"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// TPMSigner is only used for testing
type TPMSigner struct {
	pub crypto.PublicKey
}

func (t *TPMSigner) Public() crypto.PublicKey {
	return t.pub
}

func (t *TPMSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	panic("not implemented")
}

var _ crypto.Signer = &TPMSigner{}

// SetEKCertificate sets a fake EK certificate so we can pass attestation checks in tests
func SetEKCertificate(rwc transport.TPMCloser) error {
	// TODO: We should create RSA and ECC
	certHandle := tpm2.TPMHandle(0x01C0000A)

	_, err := tpm2.NVReadPublic{
		NVIndex: certHandle,
	}.Execute(rwc)
	if err == nil {
		// abort ek cert creation
		// it already exists
		return nil
	}

	// TODO: Abstract this away so we can mock an EK signing chain
	rootCert := certs.NewRootCertificate()

	_, tpub, err := attest.GetEK(rwc, tpm2.TPMAlgECC)
	if err != nil {
		return err
	}

	cpub, _ := tpm2.Pub(*tpub)

	// We assume the test suite will clean this up.
	// Not great. Not terrible.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, string(rootCert.Raw()))
	}))

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Attestation Intermediate CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365 * 10),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		IssuingCertificateURL: []string{ts.URL},
	}
	cert := certs.NewCertificate(template, rootCert.Certificate(), &TPMSigner{cpub}, rootCert.Signer())

	cert.Bytes()

	def := tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex: certHandle, NameAlg: tpm2.TPMAlgSHA256,
				Attributes: tpm2.TPMANV{
					// The expected attributes of this nvindex
					// PolicyWrite:  true,
					// PolicyDelete: true,
					// WriteAll:     true,
					// PPRead:       true,
					// OwnerRead:    true,
					// AuthRead:     true,
					// PolicyRead:   true,
					// Written:        true,
					// PlatformCreate: true,

					NT:         tpm2.TPMNTOrdinary,
					OwnerWrite: true,
					OwnerRead:  true,
					AuthWrite:  true,
					AuthRead:   true,
					NoDA:       true,
				},
				DataSize: uint16(len(cert.Raw())),
			}),
	}
	if _, err := def.Execute(rwc); err != nil {
		return err
	}

	pub, err := def.PublicInfo.Contents()
	if err != nil {
		return err
	}
	nvName, err := tpm2.NVName(pub)
	if err != nil {
		return err
	}

	_, err = tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth([]byte{})),
		},

		NVIndex: tpm2.NamedHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
		},
		Data: tpm2.TPM2BMaxNVBuffer{
			Buffer: cert.Raw(),
		},
		Offset: 0,
	}.Execute(rwc)
	if err != nil {
		return err
	}
	return nil
}
