package attest_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/foxboron/attezt/internal/attest"
	"github.com/foxboron/attezt/internal/transport"
	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
)

func TestEncap(t *testing.T) {
	rwc, err := transport.GetTPM()
	if err != nil {
		t.Fatal(err)
	}
	defer rwc.Close()

	ap, err := attest.NewAttestationParametersWithAlg(rwc, tpm2.TPMAlgECC)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := attest.GetEKCert(rwc, tpm2.TPMAlgECC)
	if err != nil {
		t.Fatal(err)
	}

	ll := attest.NewCryptoPublicEncapKey(cert.PublicKey)

	creat, err := ap.CreateAttestation.Attested.Creation()
	if err != nil {
		t.Fatal(err)
	}

	sec := []byte{1, 2, 3, 4, 5}
	id, secret, err := tpm2.CreateCredential(rand.Reader, ll, creat.ObjectName.Buffer, sec)
	if err != nil {
		t.Fatal(err)
	}

	akHandle, _, err := attest.GetAK(rwc, tpm2.TPMAlgECC)
	if err != nil {
		t.Fatal(err)
	}
	defer keyfile.FlushHandle(rwc, akHandle)

	ekHandle, _, err := attest.GetEK(rwc, tpm2.TPMAlgECC)
	if err != nil {
		t.Fatal(err)
	}
	defer keyfile.FlushHandle(rwc, ekHandle.Handle)

	ac, err := tpm2.ActivateCredential{
		ActivateHandle: akHandle,
		KeyHandle: tpm2.AuthHandle{
			Handle: ekHandle.Handle,
			Name:   ekHandle.Name,
			Auth:   tpm2.Policy(tpm2.TPMAlgSHA256, 16, attest.EkPolicy),
		},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: id},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: secret},
	}.Execute(rwc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ac.CertInfo.Buffer, sec) {
		t.Fatal("buffers are not equal")
	}
}
