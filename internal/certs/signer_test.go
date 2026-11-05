package certs

import (
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.step.sm/crypto/kms"
	"go.step.sm/crypto/kms/apiv1"
)

func TestPEMSignerWithoutRootPrivateKey(t *testing.T) {
	ca := NewCA()
	dir := t.TempDir()
	root := filepath.Join(dir, "root_ca.pem")
	intermediate := filepath.Join(dir, "intermediate_ca.pem")
	key := filepath.Join(dir, "intermediate_ca.key")
	for path, data := range map[string][]byte{root: ca.root.Bytes(), intermediate: ca.intermediate.Bytes(), key: ca.intermediate.SignerBytes()} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	manager, err := kms.New(t.Context(), apiv1.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	signer, err := manager.CreateSigner(&apiv1.CreateSignerRequest{SigningKey: key})
	if err != nil {
		t.Fatal(err)
	}
	chain, err := ReadChainWithSigner(root, intermediate, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadChainFromDir(dir); err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := chain.Sign(leaf, ca.root.signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Verify(cert); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadChainWithSigner(root, intermediate, ca.root.signer); err == nil {
		t.Fatal("mismatched signer accepted")
	}
	issuer := *ca.intermediate.cert
	issuer.KeyUsage = x509.KeyUsageDigitalSignature
	badDER, err := x509.CreateCertificate(rand.Reader, &issuer, ca.root.cert, signer.Public(), ca.root.signer)
	if err != nil {
		t.Fatal(err)
	}
	bad := &Certificate{certBytes: badDER}
	if err := os.WriteFile(intermediate, bad.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadChainWithSigner(root, intermediate, signer); err == nil {
		t.Fatal("issuer without certSign accepted")
	}
	if err := os.WriteFile(intermediate, []byte("invalid PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadChainWithSigner(root, intermediate, signer); err == nil {
		t.Fatal("malformed PEM accepted")
	}
}
