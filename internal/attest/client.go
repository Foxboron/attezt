package attest

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"

	ijson "github.com/foxboron/attezt/internal/json"
	"github.com/google/go-tpm/tpm2/transport"
)

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

func (a *AttestClient) GetAttestWithAlg(rwc transport.TPMCloser, ap *Attestation) ([]*x509.Certificate, error) {
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
	arReq, err := ijson.Decode[AttestationResponse](resp.Body)
	if err != nil {
		return nil, err
	}

	secret, err := ap.ActivateCredentialWithAlg(rwc, ap.Alg(), arReq.Credential, arReq.Secret)
	if err != nil {
		return nil, err
	}

	jj, err := json.Marshal(SecretRequest{
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

	cert, err := ijson.Decode[SecretResponse](resp.Body)
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
