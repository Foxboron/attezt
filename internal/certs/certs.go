package certs

// TODO: All of this should be replaced with a proper CA component *somehow*
// This is mostly just to bootstrap something to test out this entire thing.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"
)

type Signer struct {
	signer crypto.Signer
}

var _ crypto.Signer = &Signer{}

func (s *Signer) Public() crypto.PublicKey {
	return s.signer.Public()
}

func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.signer.Sign(rand, digest, opts)
}

func (s *Signer) Bytes() []byte {
	b, err := x509.MarshalPKCS8PrivateKey(s.signer)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	})
}

func UnmarshalSigner(b []byte) (*Signer, error) {
	key, err := x509.ParsePKCS8PrivateKey(b)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("not a crypto.Signer")
	}
	return &Signer{signer}, nil
}

type Certificate struct {
	cert      *x509.Certificate
	certBytes []byte
	signer    *Signer
}

func ReadCertificates(priv, pub []byte) (*Certificate, error) {
	cert := &Certificate{}
	if err := cert.readPriv(priv); err != nil {
		return nil, err
	}
	if err := cert.readPub(pub); err != nil {
		return nil, err
	}
	return cert, nil
}

func (c *Certificate) readPub(b []byte) error {
	block, _ := pem.Decode(b)
	cert, err := x509.ParseCertificate(block.Bytes)
	c.cert = cert
	c.certBytes = cert.Raw
	return err
}

func (c *Certificate) readPriv(b []byte) error {
	block, _ := pem.Decode(b)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return fmt.Errorf("not a crypto.Signer")
	}
	c.signer = &Signer{signer}
	return nil
}

func (c *Certificate) Bytes() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.certBytes,
	})
}

func (c *Certificate) SignerBytes() []byte {
	return c.signer.Bytes()
}

func (c *Certificate) NewIntermediateCert() *Certificate {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("failed creating key")
	}
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
	}
	return NewCertificate(template, c.cert, pk, c.signer)
}

func NewCertificate(template, parent *x509.Certificate, templateSigner crypto.Signer, parentSigner crypto.Signer) *Certificate {
	certbytes, err := x509.CreateCertificate(rand.Reader, template, parent, templateSigner.Public(), parentSigner)
	if err != nil {
		panic("failed creating root ca")
	}
	cert, err := x509.ParseCertificate(certbytes)
	if err != nil {
		panic("failed parsing new certificate")
	}
	return &Certificate{
		cert:      cert,
		certBytes: certbytes,
		signer:    &Signer{templateSigner},
	}
}

func NewRootCertificate() *Certificate {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("failed creating key")
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Attestation CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365 * 10),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
	}
	return NewCertificate(rootTemplate, rootTemplate, pk, pk)
}

type CertificateChain struct {
	root         *Certificate
	intermediate *Certificate
}

func ReadChainFromDir(_ string) (*CertificateChain, error) {
	rootKey, err := os.ReadFile("root_ca.key")
	if err != nil {
		return nil, fmt.Errorf("railed reading root_ca.key: %v", err)
	}
	rootcrt, err := os.ReadFile("root_ca.pem")
	if err != nil {
		return nil, fmt.Errorf("railed reading root_ca.pem: %v", err)
	}
	rootCert, err := ReadCertificates(rootKey, rootcrt)
	if err != nil {
		return nil, fmt.Errorf("failed ReadCertificate for root cert: %v", err)
	}
	interkey, err := os.ReadFile("intermediate_ca.key")
	if err != nil {
		return nil, fmt.Errorf("railed reading intermediate_ca.key: %v", err)
	}
	intercrt, err := os.ReadFile("intermediate_ca.pem")
	if err != nil {
		return nil, fmt.Errorf("railed reading intermediate_ca.pem: %v", err)
	}
	interCert, err := ReadCertificates(interkey, intercrt)
	if err != nil {
		return nil, fmt.Errorf("failed ReadCertificate for intermediate ca cert: %v", err)
	}
	return &CertificateChain{
		root:         rootCert,
		intermediate: interCert,
	}, nil
}

func NewCA() *CertificateChain {
	root := NewRootCertificate()
	inter := root.NewIntermediateCert()
	return &CertificateChain{
		root:         root,
		intermediate: inter,
	}
}

func (c *CertificateChain) Sign(cert *x509.Certificate, pub crypto.PublicKey) ([]byte, error) {
	return x509.CreateCertificate(rand.Reader, cert, c.intermediate.cert, pub, c.intermediate.signer)
}

func (c *CertificateChain) Verify(cert *x509.Certificate) ([][]*x509.Certificate, error) {
	rootPool := x509.NewCertPool()
	rootPool.AddCert(c.root.cert)
	interPool := x509.NewCertPool()
	interPool.AddCert(c.intermediate.cert)
	return cert.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: interPool,
		CurrentTime:   time.Now().Truncate(time.Second),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
}

func (c *CertificateChain) IntermediateCertificate() *x509.Certificate {
	return c.intermediate.cert
}

func (c *CertificateChain) NewRootCertificate() *x509.Certificate {
	return c.root.cert
}

func (c *CertificateChain) SaveCertificates(root, intermediate io.Writer) error {
	// TODO: Error
	root.Write(c.root.Bytes())
	intermediate.Write(c.intermediate.Bytes())
	return nil
}

func (c *CertificateChain) SaveKeys(root, intermediate io.Writer) error {
	// TODO: error
	root.Write(c.root.SignerBytes())
	intermediate.Write(c.intermediate.SignerBytes())
	return nil
}
