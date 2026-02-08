package attezt

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/foxboron/attezt/internal/attest"
	ijson "github.com/foxboron/attezt/internal/json"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Hardcoded to ALGRSA
var TPMALG = tpm2.TPMAlgRSA

type AttestClient struct {
	url string
	c   *http.Client
}

func NewClient(url string) *AttestClient {
	return &AttestClient{
		url: url,
		c:   new(http.Client),
	}
}

func (a *AttestClient) GetAttestURL() string {
	return fmt.Sprintf("%s/%s", a.url, "attest")
}

func (a *AttestClient) GetSecretURL() string {
	return fmt.Sprintf("%s/%s", a.url, "secret")
}

func (a *AttestClient) GetAttestWithAlg(rwc transport.TPMCloser, alg tpm2.TPMAlgID) ([]*x509.Certificate, error) {
	ap, err := attest.NewAttestationWithAlg(rwc, alg)
	if err != nil {
		return nil, err
	}

	b, err := json.Marshal(ap)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", a.GetAttestURL(), bytes.NewBuffer(b))
	if err != nil {
		return nil, fmt.Errorf("failed building attest request: %v", err)
	}

	resp, err := a.c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed doing attest: %v", err)
	}
	arReq, err := ijson.Decode[attest.AttestationResponse](resp.Body)
	if err != nil {
		return nil, err
	}

	secret, err := ap.ActivateCredentialWithAlg(rwc, alg, arReq.Credential, arReq.Secret)
	if err != nil {
		return nil, err
	}

	jj, err := json.Marshal(attest.SecretRequest{
		Secret: secret,
	})
	if err != nil {
		return nil, err
	}

	req, err = http.NewRequest("POST", a.GetSecretURL(), bytes.NewBuffer(jj))
	if err != nil {
		return nil, fmt.Errorf("failed building attest request: %v", err)
	}

	resp, err = a.c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed doing attest: %v", err)
	}

	cert, err := ijson.Decode[attest.SecretResponse](resp.Body)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate

	for _, c := range cert.CertificateChain {
		cc, err := x509.ParseCertificate(c)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cc)
	}

	return certs, nil
}

func (a *AttestClient) GetAttest(rwc transport.TPMCloser) ([]*x509.Certificate, error) {
	return a.GetAttestWithAlg(rwc, tpm2.TPMAlgRSA)
}
