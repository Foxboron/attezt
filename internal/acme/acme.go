package acme

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/foxboron/attezt/internal/attest"
	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-jose/go-jose/v3"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
)

type AttestationPayload struct {
	AttObj string `json:"attObj"`
}

type AttestationObject struct {
	Format       string         `json:"fmt"`
	AttStatement map[string]any `json:"attStmt"`
}

func CreateAttestationObject(chain []*x509.Certificate, alg tpm2.TPMAlgID, params *attest.AttestationParameters) ([]byte, error) {
	chainb := make([][]byte, len(chain))
	for i, cert := range chain {
		chainb[i] = cert.Raw
	}

	var calg int64
	switch alg {
	case tpm2.TPMAlgRSA:
		calg = -257 // RS256 COSE Algorithm Identifier
	case tpm2.TPMAlgECC:
		calg = -7 // ES256 COSE Algorithm Identifier
	default:
		return nil, fmt.Errorf("unsupported TPM public key type: 0x%x", alg)
	}

	obj := &AttestationObject{
		Format: "tpm",
		AttStatement: map[string]interface{}{
			"ver":      "2.0",
			"alg":      calg,
			"x5c":      chainb,
			"sig":      params.CreateSignature,
			"certInfo": tpm2.Marshal(params.CreateAttestation),
			"pubArea":  tpm2.Marshal(params.Public),
		},
	}
	return cbor.Marshal(obj)
}

func CreateAttestationPayload(chain []*x509.Certificate, alg tpm2.TPMAlgID, params *attest.AttestationParameters) (any, error) {
	attObj, err := CreateAttestationObject(chain, alg, params)
	if err != nil {
		return nil, err
	}
	challengeBody := struct {
		AttObj string `json:"attObj"`
	}{
		AttObj: base64.RawURLEncoding.EncodeToString(attObj),
	}
	return challengeBody, nil
}

func JwkThumbprint(token string, pub crypto.PublicKey) ([]byte, error) {
	webkey := &jose.JSONWebKey{Key: pub}
	thumbprint, err := webkey.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	p := base64.RawURLEncoding.EncodeToString(thumbprint)
	s := sha256.Sum256([]byte(fmt.Sprintf("%s.%s", token, p)))

	return s[:], nil
}

type ACMEClient struct {
	rwc          transport.TPMCloser
	attestClient *attest.AttestClient
	acmeAccount  *acme.Account
	acmeClient   *acmez.Client
	// acmeServer   string
	subject string
}

func (a *ACMEClient) RequestACMECertificate(ctx context.Context, tpmalg tpm2.TPMAlgID) ([]*x509.Certificate, error) {
	// privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// if err != nil {
	// 	return nil, err
	// }

	// account := acme.Account{
	// 	TermsOfServiceAgreed: true,
	// 	PrivateKey:           privateKey,
	// }
	//
	// client := acmez.Client{
	// 	Client: &acme.Client{
	// 		Directory: acmeServer,
	// 	},
	// }
	// account, err = client.NewAccount(ctx, account)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed creating new account: %v", err)
	// }

	t := time.Now()
	tafter := t.Add(24 * time.Hour)
	order := acme.Order{
		Identifiers: []acme.Identifier{{
			Type:  "permanent-identifier",
			Value: a.subject,
		}},
		NotBefore: &t,
		NotAfter:  &tafter,
	}

	order, err := a.acmeClient.NewOrder(ctx, *a.acmeAccount, order)
	if err != nil {
		return nil, fmt.Errorf("failed client.NewOrder: %v", err)
	}

	url := order.Authorizations[0]

	authz, err := a.acmeClient.GetAuthorization(ctx, *a.acmeAccount, url)
	if err != nil {
		return nil, fmt.Errorf("failed client.GetAuthorization: %v", err)
	}

	challenge := authz.Challenges[0]

	// TPM CHALLENGE RESLOUTION HERE
	akHandle, akrsp, err := attest.GetAK(a.rwc, tpmalg)
	if err != nil {
		return nil, fmt.Errorf("failed getting Attestation Key: %v", err)
	}
	defer keyfile.FlushHandle(a.rwc, akHandle)

	s, err := a.acmeAccount.Thumbprint()
	if err != nil {
		return nil, fmt.Errorf("thumbprint: %v", err)
	}
	data := fmt.Sprintf("%s.%s", challenge.Token, s)
	hashedData := sha256.Sum256([]byte(data))

	aconf := &attest.AttestationConfig{
		AKHandle: akHandle,
		AKRsp:    akrsp,
		KeyAlg:   tpmalg,
		Name:     []byte("app-test"),
	}

	att, err := attest.NewAttestation(a.rwc, aconf)
	if err != nil {
		return nil, fmt.Errorf("failed NewAttestation: %v", err)
	}
	certs, err := a.attestClient.GetAttestWithAlg(a.rwc, att)
	if err != nil {
		return nil, fmt.Errorf("failed GetAttest: %v", err)
	}

	// Create a new key and attest with AK
	key, _, err := keyfile.NewLoadableKeyWithResponse(a.rwc, tpmalg, 2048, []byte(""))
	if err != nil {
		return nil, err
	}

	keyhandle, parenthandle, err := keyfile.LoadKey(keyfile.NewTPMSession(a.rwc), key, []byte(nil))
	if err != nil {
		return nil, err
	}

	tkey, err := key.Pubkey.Contents()
	if err != nil {
		return nil, err
	}

	// Certify the creation of it by loading it
	dkattestparams, err := attest.CertifyKey(a.rwc, *aconf.AKHandle, tpm2.NamedHandle{Handle: keyhandle.Handle, Name: keyhandle.Name}, tkey, hashedData[:])
	if err != nil {
		return nil, err
	}

	// TODO: Certify should be part of go-tpm-keys
	// Flush before Signer
	// else we'll run out of memory
	keyfile.FlushHandle(a.rwc, keyhandle)
	keyfile.FlushHandle(a.rwc, parenthandle)

	payloadBytes, err := CreateAttestationPayload(certs, aconf.KeyAlg, dkattestparams)
	if err != nil {
		return nil, err
	}
	challenge.Payload = payloadBytes

	csr := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: a.subject,
		},
	}

	signer, err := key.Signer(a.rwc, []byte(""), []byte(""))
	if err != nil {
		return nil, err
	}
	csrbytes, err := x509.CreateCertificateRequest(rand.Reader, csr, signer)
	if err != nil {
		return nil, err
	}

	// STOP TPM

	challenge, err = a.acmeClient.InitiateChallenge(ctx, *a.acmeAccount, challenge)
	if err != nil {
		return nil, err
	}

	order, err = a.acmeClient.FinalizeOrder(ctx, *a.acmeAccount, order, csrbytes)
	if err != nil {
		return nil, err
	}

	certChains, err := a.acmeClient.GetCertificateChain(ctx, *a.acmeAccount, order.Certificate)
	if err != nil {
		return nil, err
	}

	certsPem := make([]*x509.Certificate, len(certChains))
	for n, c := range certChains {
		block, _ := pem.Decode(c.ChainPEM)
		xcert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certsPem[n] = xcert
	}
	return certsPem, nil
}
