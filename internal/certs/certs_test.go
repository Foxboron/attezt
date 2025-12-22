package certs_test

import (
	"crypto/x509"
	"testing"

	"github.com/foxboron/attezt/internal/attest"
	"github.com/foxboron/attezt/internal/certs"
	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestNewCA(t *testing.T) {
	caChain := certs.NewCA()
	rwc, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	handle, pub, err := attest.GetAK(rwc)
	if err != nil {
		t.Fatal(err)
	}
	defer keyfile.FlushHandle(rwc, handle)
	akPub, err := pub.OutPublic.Contents()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := attest.NewAKCertificate(akPub)
	if err != nil {
		t.Fatal(err)
	}
	// cert.SetExtensions(a.ekuri(), a.TPMInfo)
	b, err := caChain.Sign(cert.Cert(), cert.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	akCert, err := x509.ParseCertificate(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := caChain.Verify(akCert); err != nil {
		t.Fatal(err)
	}
}
