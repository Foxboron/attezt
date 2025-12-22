package attest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/go-tpm-keyfiles/template"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type Attestation struct {
	TPMInfo *TPMInfo
	// TODO: What is the proper type for this?
	EKCerts      [][]byte
	EKPub        crypto.PublicKey
	AKCert       []byte
	AttestParams *AttestationParameters
}

// attestationRequest is the JSON serialized version of Attestation
type attestationRequest struct {
	TPMInfo      *TPMInfo               `json:"tpmInfo"`
	EKPub        []byte                 `json:"ek,omitempty"`
	EKCerts      [][]byte               `json:"ekCerts,omitempty"`
	AKCert       []byte                 `json:"akCert,omitempty"`
	AttestParams *AttestationParameters `json:"params"`
}

// CreateCredential creates an encrypted credential to be used for ActivateCredential
func (a *Attestation) CreateCredential(secret []byte) (*AttestationResponse, error) {
	ll := NewCryptoPublicEncapKey(a.EKPub)

	creat, err := a.AttestParams.CreateAttestation.Attested.Creation()
	if err != nil {
		return nil, err
	}

	id, secret, err := tpm2.CreateCredential(rand.Reader, ll, creat.ObjectName.Buffer, secret)
	if err != nil {
		return nil, err
	}
	return &AttestationResponse{
		tpm2.Marshal(tpm2.TPM2BIDObject{Buffer: id}),
		tpm2.Marshal(tpm2.TPM2BEncryptedSecret{Buffer: secret}),
	}, nil
}

func (a *Attestation) ActivateCredential(rwc transport.TPMCloser, cred, secret []byte) ([]byte, error) {
	// TODO: We should check that we are attesting ak and EK as we expect
	akHandle, _, err := GetAK(rwc)
	if err != nil {
		return nil, err
	}
	defer keyfile.FlushHandle(rwc, akHandle)

	ekHandle, _, err := GetEK(rwc)
	if err != nil {
		return nil, err
	}
	defer keyfile.FlushHandle(rwc, ekHandle.Handle)

	ac, err := tpm2.ActivateCredential{
		ActivateHandle: akHandle,
		KeyHandle: tpm2.AuthHandle{
			Handle: ekHandle.Handle,
			Name:   ekHandle.Name,
			Auth:   tpm2.Policy(tpm2.TPMAlgSHA256, 16, ekPolicy),
		},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: cred},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: secret},
	}.Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("failed credential activation: %v", err)
	}
	return ac.CertInfo.Buffer, nil
}

func HashPub(b crypto.PublicKey) string {
	key, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		panic("Attestation.ekuri: not a valid ekpub")
	}
	hash := sha256.Sum256(key)
	return "urn:ek:sha256:" + base64.StdEncoding.EncodeToString(hash[:])
}

func (a *Attestation) ekuri() string {
	return HashPub(a.EKPub)
}

func (a *Attestation) AKCertificate() (*AKCertificate, error) {
	cert, err := NewAKCertificate(a.AttestParams.Public)
	if err != nil {
		return nil, err
	}
	cert.SetExtensions(a.ekuri(), a.TPMInfo)
	return cert, nil
}

func (a *Attestation) UnmarshalJSON(b []byte) error {
	var obj attestationRequest
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	a.TPMInfo = obj.TPMInfo
	pub, err := x509.ParsePKIXPublicKey(obj.EKPub)
	if err != nil {
		return err
	}
	a.EKCerts = obj.EKCerts
	a.EKPub = pub
	a.AKCert = obj.AKCert
	a.AttestParams = obj.AttestParams
	return nil
}

func (a *Attestation) MarshalJSON() ([]byte, error) {
	var ekPub []byte
	var err error
	fmt.Println(a.EKPub)
	if ekPub, err = x509.MarshalPKIXPublicKey(a.EKPub); err != nil {
		panic(fmt.Sprintf("failed marshaling public key: %v", err))
	}
	return json.Marshal(&attestationRequest{
		TPMInfo:      a.TPMInfo,
		EKPub:        ekPub,
		EKCerts:      a.EKCerts,
		AttestParams: a.AttestParams,
	})
}

func NewAttestation(rwc transport.TPMCloser) (*Attestation, error) {
	ap, err := NewAttestationParameters(rwc)
	if err != nil {
		return nil, fmt.Errorf("failed getting attestation parameters: %w", err)
	}

	cert, err := getEKCert(rwc)
	if err != nil {
		return nil, fmt.Errorf("failed getting endorsement key certificate: %w", err)
	}

	return &Attestation{
		// TODO: Fill the information, but I don't think anything read this
		TPMInfo: &TPMInfo{
			FirmwareVersion: "test",
		},
		// TODO: This should be ECC and RSA certs
		EKCerts: [][]byte{cert.Raw},
		EKPub:   cert.PublicKey,
		// TODO: Not used?
		// AKCert:       []byte{},
		AttestParams: ap,
		// Internal stuff
	}, nil
}

type AttestationParameters struct {
	Public            *tpm2.TPMTPublic
	CreateData        []byte
	CreateAttestation *tpm2.TPMSAttest
	CreateSignature   []byte
}

type attestationParameters struct {
	Public []byte `json:"public,omitempty"`
	// Smallstep thing, need to figur eout
	UseTCSDActivationFormat bool   `json:"useTCSDActivationFormat,omitempty"`
	CreateData              []byte `json:"createData,omitempty"`
	CreateAttestation       []byte `json:"createAttestation,omitempty"`
	CreateSignature         []byte `json:"createSignature,omitempty"`
}

func NewAttestationParameters(rwc transport.TPMCloser) (*AttestationParameters, error) {
	akHandle, AKrsp, err := GetAK(rwc)
	if err != nil {
		return nil, err
	}
	defer keyfile.FlushHandle(rwc, akHandle)

	pub, err := AKrsp.OutPublic.Contents()
	if err != nil {
		return nil, err
	}

	var inScheme tpm2.TPMTSigScheme

	switch pub.Type {
	case tpm2.TPMAlgECC:
		inScheme = tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		}
	case tpm2.TPMAlgRSA:
		inScheme = tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		}
	default:
		return nil, fmt.Errorf("unsupported AK for CertifyCreation")
	}

	// TODO: hashed session
	ccRsp, err := tpm2.CertifyCreation{
		SignHandle: tpm2.AuthHandle{
			Handle: akHandle.Handle,
			Name:   akHandle.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		ObjectHandle: tpm2.NamedHandle{
			Handle: akHandle.Handle,
			Name:   akHandle.Name,
		},
		CreationHash:   AKrsp.CreationHash,
		CreationTicket: AKrsp.CreationTicket,
		InScheme:       inScheme,
	}.Execute(rwc)
	if err != nil {
		return nil, err
	}

	akpub, err := AKrsp.OutPublic.Contents()
	if err != nil {
		return nil, err
	}

	ca, err := ccRsp.CertifyInfo.Contents()
	if err != nil {
		return nil, err
	}

	return &AttestationParameters{
		Public:            akpub,
		CreateData:        tpm2.Marshal(AKrsp.CreationData),
		CreateAttestation: ca,
		CreateSignature:   tpm2.Marshal(ccRsp.Signature),
	}, nil
}

func verifySignature(pub *tpm2.TPMTPublic, b []byte, sig *tpm2.TPMTSignature) (bool, error) {
	pk, err := template.FromTPMPublicToPubkey(pub)
	if err != nil {
		return false, fmt.Errorf("not a valid private key")
	}
	switch p := pk.(type) {
	case *ecdsa.PublicKey:
		eccsig, err := sig.Signature.ECDSA()
		if err != nil {
			return false, err
		}
		h, err := eccsig.Hash.Hash()
		if err != nil {
			return false, err
		}
		sh := h.New()
		sh.Write(b)
		return ecdsa.Verify(p, sh.Sum(nil), new(big.Int).SetBytes(eccsig.SignatureR.Buffer), new(big.Int).SetBytes(eccsig.SignatureS.Buffer)), nil
	default:
		// TODO: Implement RSA
		return false, fmt.Errorf("not supported")
	}
}

func (a *AttestationParameters) VerifyCreation(restricted bool) (bool, error) {
	attest := a.CreateAttestation

	if attest.Type != tpm2.TPMSTAttestCreation {
		return false, fmt.Errorf("doesn't attest for creation")
	}
	h, err := a.Public.NameAlg.Hash()
	if err != nil {
		return false, err
	}
	hh := h.New()
	// Strip length prefix as we use tpm2.Marshal
	hh.Write(a.CreateData[2:])
	creation, err := attest.Attested.Creation()
	if err != nil {
		return false, err
	}

	if !bytes.Equal(creation.CreationHash.Buffer, hh.Sum(nil)) {
		return false, fmt.Errorf("incorrect public key")
	}

	if attest.Magic != tpm2.TPMGeneratedValue {
		return false, fmt.Errorf("key not created on tpm")
	}

	if !a.Public.ObjectAttributes.FixedTPM {
		return false, fmt.Errorf("AK is exportable")
	}

	if !a.Public.ObjectAttributes.Restricted && restricted {
		return false, fmt.Errorf("key is not limited to attestation")
	}

	if !a.Public.ObjectAttributes.FixedParent || !a.Public.ObjectAttributes.SensitiveDataOrigin {
		return false, fmt.Errorf("key is not bound to TPM")
	}

	name, err := tpm2.ObjectName(a.Public)
	if err != nil {
		return false, err
	}

	if !bytes.Equal(name.Buffer, creation.ObjectName.Buffer) {
		return false, fmt.Errorf("createion attestation is for another key")
	}

	sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](a.CreateSignature)
	if err != nil {
		return false, err
	}

	// We omit the length variable from CreateAttestation marshal
	return verifySignature(a.Public, tpm2.Marshal(a.CreateAttestation)[2:], sig)
}

func (a *AttestationParameters) Verify() (bool, error) {
	ok, err := a.VerifyCreation(true)
	if err != nil {
		return false, fmt.Errorf("failed AK validation: %v", err)
	}
	if !ok {
		return false, nil
	}
	return true, nil
}

func (a *AttestationParameters) ToJSON() *attestationParameters {
	return &attestationParameters{
		Public:                  tpm2.Marshal(a.Public),
		UseTCSDActivationFormat: false,
		CreateData:              a.CreateData,
		CreateAttestation:       tpm2.Marshal(a.CreateAttestation),
		CreateSignature:         a.CreateSignature,
	}
}

func (a *AttestationParameters) UnmarshalJSON(b []byte) error {
	var obj attestationParameters
	if err := json.Unmarshal(b, &obj); err != nil {
		return fmt.Errorf("failed ap unmarshal: %v", err)
	}

	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](obj.Public)
	if err != nil {
		return err
	}

	attest2b, err := tpm2.Unmarshal[tpm2.TPMSAttest](obj.CreateAttestation)
	if err != nil {
		return fmt.Errorf("tpm2battest: %v", err)
	}

	// attest, err := attest2b.Contents()
	// if err != nil {
	// 	return fmt.Errorf("attest.contents: %v", err)
	// }

	a.Public = pub
	a.CreateData = obj.CreateData
	a.CreateAttestation = attest2b
	a.CreateSignature = obj.CreateSignature
	return nil
}

func (a *AttestationParameters) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.ToJSON())
}
