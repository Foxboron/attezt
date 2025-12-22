package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/foxboron/attezt/internal/attest"
	"github.com/foxboron/attezt/internal/certs"
	ijson "github.com/foxboron/attezt/internal/json"
	ssim "github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

// TPM represents a connection to a TPM simulator.
type TPM struct {
	transport io.ReadWriteCloser
}

// Send implements the TPM interface.
func (t *TPM) Send(input []byte) ([]byte, error) {
	return tpmutil.RunCommandRaw(t.transport, input)
}

// Close implements the TPM interface.
func (t *TPM) Close() error {
	return t.transport.Close()
}

func OpenSimulator() (transport.TPMCloser, error) {
	sim, err := ssim.GetWithFixedSeedInsecure(1234)
	if err != nil {
		return nil, err
	}
	return &TPM{
		transport: sim,
	}, nil
}

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

func (a *AttestClient) GetAttest(rwc transport.TPMCloser) (any, error) {
	ap, err := attest.NewAttestation(rwc)
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

	secret, err := ap.ActivateCredential(rwc, arReq.Credential, arReq.Secret)
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

	fmt.Println(len(cert.CertificateChain))
	return nil, nil
}

var mkKeys = flag.Bool("create-certs", false, "creater certificates")

func main() {
	flag.Parse()

	if *mkKeys {
		chain := certs.NewCA()
		rootKey, _ := os.OpenFile("root_ca.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		defer rootKey.Close()
		rootCrt, _ := os.OpenFile("root_ca.crt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		defer rootCrt.Close()
		interKey, _ := os.OpenFile("intermediate_ca.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		defer interKey.Close()
		interCrt, _ := os.OpenFile("intermediate_ca.crt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		defer interCrt.Close()
		chain.SaveKeys(rootKey, interKey)
		chain.SaveCertificates(rootCrt, interCrt)
		os.Exit(0)
	}

	rwc, err := transport.OpenTPM()
	if err != nil {
		log.Fatal(err)
	}

	c := NewClient("http://127.0.0.1:8080")
	k, err := c.GetAttest(rwc)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(k)
}
