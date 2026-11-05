package certs

// TODO: All of this should be replaced with a proper CA component *somehow*
// This is mostly just to bootstrap something to test out this entire thing.

import (
	"bytes"
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
	"path/filepath"
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
	if block == nil {
		return fmt.Errorf("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	c.cert = cert
	c.certBytes = cert.Raw
	return err
}

func (c *Certificate) readPriv(b []byte) error {
	block, _ := pem.Decode(b)
	if block == nil {
		return fmt.Errorf("invalid private key PEM")
	}
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

func (c *Certificate) Raw() []byte {
	return c.certBytes
}

func (c *Certificate) SignerBytes() []byte {
	return c.signer.Bytes()
}

func (c *Certificate) Signer() crypto.Signer {
	return c.signer
}

func (c *Certificate) Certificate() *x509.Certificate {
	return c.cert
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

func ReadChainWithSigner(rootPath, intermediatePath string, signer crypto.Signer) (*CertificateChain, error) {
	root, intermediate := &Certificate{}, &Certificate{}
	for path, cert := range map[string]*Certificate{rootPath: root, intermediatePath: intermediate} {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := cert.readPub(data); err != nil {
			return nil, err
		}
	}
	if root.cert == nil || intermediate.cert == nil || !intermediate.cert.IsCA || intermediate.cert.KeyUsage&x509.KeyUsageCertSign == 0 || signer == nil {
		return nil, fmt.Errorf("root, intermediate CA and signer are required")
	}
	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(spki, intermediate.cert.RawSubjectPublicKeyInfo) {
		return nil, fmt.Errorf("signer does not match intermediate certificate")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root.cert)
	if _, err := intermediate.cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, fmt.Errorf("invalid intermediate chain: %w", err)
	}
	intermediate.signer = &Signer{signer}
	return &CertificateChain{root: root, intermediate: intermediate}, nil
}

func ReadChainFromDir(directory string) (*CertificateChain, error) {
	interkey, err := os.ReadFile(filepath.Join(directory, "intermediate_ca.key"))
	if err != nil {
		return nil, fmt.Errorf("railed reading intermediate_ca.key: %v", err)
	}
	intermediate := &Certificate{}
	if err := intermediate.readPriv(interkey); err != nil {
		return nil, err
	}
	return ReadChainWithSigner(filepath.Join(directory, "root_ca.pem"), filepath.Join(directory, "intermediate_ca.pem"), intermediate.signer)
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
	if cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		return nil, fmt.Errorf("only leaf certificates may be issued")
	}
	template := *cert
	if template.NotBefore.Before(c.intermediate.cert.NotBefore) {
		template.NotBefore = c.intermediate.cert.NotBefore
	}
	if template.NotAfter.After(c.intermediate.cert.NotAfter) {
		template.NotAfter = c.intermediate.cert.NotAfter
	}
	if !template.NotAfter.After(time.Now()) || !template.NotAfter.After(template.NotBefore) {
		return nil, fmt.Errorf("issuer or requested certificate validity has expired")
	}
	return x509.CreateCertificate(rand.Reader, &template, c.intermediate.cert, pub, c.intermediate.signer)
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

func (c *CertificateChain) RootCertificate() *x509.Certificate {
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
