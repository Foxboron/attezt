package truststore_test

import (
	"crypto/x509"
	"os"
	"testing"

	"github.com/foxboron/attezt/internal/attest"
	"github.com/foxboron/attezt/internal/transport"
	"github.com/foxboron/attezt/internal/truststore"
	"github.com/google/go-tpm/tpm2"
)

func TestTruststoreFromDir(t *testing.T) {
	ts, err := truststore.NewTrustStoreFromDirectory(os.DirFS("tests/"))
	if err != nil {
		t.Fatal(err)
	}
	der, err := os.ReadFile("tests/devicecert.cer")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ts.VerifyCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEKChain(t *testing.T) {
	rwc, err := transport.GetTPM()
	if err != nil {
		t.Fatal(err)
	}
	defer rwc.Close()

	ts := truststore.NewTrustStore(true)

	cert, err := attest.GetEKCert(rwc, tpm2.TPMAlgECC)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ts.VerifyWithIssuingCert(cert)
	if err != nil {
		t.Fatal(err)
	}
}
