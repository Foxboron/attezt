//go:build linux && tpmsimulator

package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/tpmkms"
	"go.step.sm/crypto/tpm"
	"go.step.sm/crypto/tpm/simulator"
	"go.step.sm/crypto/tpm/storage"
)

func TestExistingTPMIntermediateSigner(t *testing.T) {
	sim, err := simulator.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := sim.Open(); err != nil {
		t.Fatal(err)
	}
	defer sim.Close()
	device, err := tpm.New(tpm.WithSimulator(sim), tpm.WithStore(storage.NewDirstore(t.TempDir())))
	if err != nil {
		t.Fatal(err)
	}
	kms, err := tpmkms.NewWithTPM(t.Context(), device)
	if err != nil {
		t.Fatal(err)
	}
	defer kms.Close()
	name := "tpmkms:name=attestation-intermediate"
	if _, err := kms.CreateSigner(&apiv1.CreateSignerRequest{SigningKey: name}); err == nil {
		t.Fatal("missing key was silently created")
	}
	created, err := kms.CreateKey(&apiv1.CreateKeyRequest{Name: name, SignatureAlgorithm: apiv1.ECDSAWithSHA256})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := kms.CreateSigner(&apiv1.CreateSignerRequest{SigningKey: name})
	if err != nil {
		t.Fatal(err)
	}
	root := NewRootCertificate()
	now := time.Now().Truncate(time.Second)
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Intermediate CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}
	issuerDER, err := x509.CreateCertificate(rand.Reader, template, root.cert, created.PublicKey, root.signer)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rootPath, intermediatePath := filepath.Join(dir, "root.crt"), filepath.Join(dir, "intermediate.crt")
	if err := os.WriteFile(rootPath, root.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	writeIntermediate := func(der []byte) {
		t.Helper()
		if err := os.WriteFile(intermediatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeIntermediate(issuerDER)
	chain, err := ReadChainWithSigner(rootPath, intermediatePath, signer)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: now, NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{{2, 23, 133, 8, 3}}}
	der, err := chain.Sign(leaf, &leafKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Verify(issued); err != nil {
		t.Fatal(err)
	}
	if !issued.NotAfter.Equal(template.NotAfter) {
		t.Fatal("leaf outlives intermediate")
	}
	if !leaf.NotAfter.Equal(now.Add(24 * time.Hour)) {
		t.Fatal("signing mutated caller template")
	}
	leaf.IsCA = true
	if _, err := chain.Sign(leaf, &leafKey.PublicKey); err == nil {
		t.Fatal("subordinate CA accepted")
	}
	if _, err := ReadChainWithSigner(rootPath, intermediatePath, leafKey); err == nil {
		t.Fatal("wrong signing key accepted")
	}
	if err := os.WriteFile(rootPath, NewRootCertificate().Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadChainWithSigner(rootPath, intermediatePath, signer); err == nil {
		t.Fatal("wrong root accepted")
	}
	if err := os.WriteFile(rootPath, root.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	template.NotBefore, template.NotAfter = now.Add(-2*time.Hour), now.Add(-time.Hour)
	issuerDER, err = x509.CreateCertificate(rand.Reader, template, root.cert, created.PublicKey, root.signer)
	if err != nil {
		t.Fatal(err)
	}
	writeIntermediate(issuerDER)
	if _, err := ReadChainWithSigner(rootPath, intermediatePath, signer); err == nil {
		t.Fatal("expired intermediate accepted")
	}
}
