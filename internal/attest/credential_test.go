package attest

import (
	"bytes"
	"crypto/rand"
	"testing"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

func TestEncap(t *testing.T) {
	rwc, err := linuxtpm.Open("/dev/tpmrm0")
	if err != nil {
		t.Fatal(err)
	}
	defer rwc.Close()

	ap, err := NewAttestationParametersWithAlg(rwc, tpm2.TPMAlgECC)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := getEKCert(rwc, tpm2.TPMAlgECC)
	if err != nil {
		t.Fatal(err)
	}

	ll := NewCryptoPublicEncapKey(cert.PublicKey)

	creat, err := ap.CreateAttestation.Attested.Creation()
	if err != nil {
		t.Fatal(err)
	}

	sec := []byte{1, 2, 3, 4, 5}
	id, secret, err := tpm2.CreateCredential(rand.Reader, ll, creat.ObjectName.Buffer, sec)
	if err != nil {
		t.Fatal(err)
	}

	akHandle, _, err := GetAK(rwc, tpm2.TPMAlgECC)
	if err != nil {
		t.Fatal(err)
	}
	defer keyfile.FlushHandle(rwc, akHandle)

	ekHandle, _, err := GetEK(rwc, tpm2.TPMAlgECC)
	if err != nil {
		t.Fatal(err)
	}
	defer keyfile.FlushHandle(rwc, ekHandle.Handle)

	ac, err := tpm2.ActivateCredential{
		ActivateHandle: akHandle,
		KeyHandle: tpm2.AuthHandle{
			Handle: ekHandle.Handle,
			Name:   ekHandle.Name,
			Auth:   tpm2.Policy(tpm2.TPMAlgSHA256, 16, ekPolicy),
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
