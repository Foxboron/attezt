package attezt

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/foxboron/attezt/internal/attest"
	"github.com/foxboron/attezt/internal/certs"
	"github.com/foxboron/attezt/internal/inventory"
	ijson "github.com/foxboron/attezt/internal/json"
	tt "github.com/foxboron/attezt/internal/transport"
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

// ca flags
var (
	certificateCmd = flag.NewFlagSet("certificate", flag.ExitOnError)
)

func CertificateMain(args []string) {
	certificateCmd.Usage = func() {
		fmt.Printf(`Usage:
	ak	Request an Attestation Key (AK)
`)
	}
	if len(args) == 0 {
		certificateCmd.Usage()
		os.Exit(0)
	}
	certificateCmd.Parse(args)
	switch args[0] {
	case "ak":
		log.Println("Requesting an attestation key...")

		rwc, err := tt.GetTPM()
		if err != nil {
			log.Fatal(err)
		}
		defer rwc.Close()

		c := NewClient("http://127.0.0.1:8080")
		certs, err := c.GetAttestWithAlg(rwc, TPMALG)
		if err != nil {
			log.Fatal(err)
		}

		file, err := os.Create("device_certificate.pem")
		if err != nil {
			log.Fatalf("failed writing cert chain: %v", err)
		}
		defer file.Close()

		for _, cert := range certs {
			if err := pem.Encode(file, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}); err != nil {
				log.Fatalf("failed writing cert")
			}
		}
		os.Exit(0)
	}
}

// ca flags
var (
	caCmd = flag.NewFlagSet("ca", flag.ExitOnError)
)

func CAMain(args []string, backend inventory.Inventory) {
	caCmd.Usage = func() {
		fmt.Printf(`Usage:
	create	Create an CA certificate chain
`)
	}
	if len(args) == 0 {
		caCmd.Usage()
		os.Exit(0)
	}
	caCmd.Parse(args)
	switch args[0] {
	case "list":
		// TODO: Implement
	case "lookup":
		// TODO: Implement
		if len(args) != 2 {
			caCmd.Usage()
			os.Exit(0)
		}
	case "enroll":
		// TODO: Implement
		if len(args) != 2 {
			caCmd.Usage()
			os.Exit(0)
		}
		fmt.Println(args[1])
	case "remove":
		// TODO: Implement
		if len(args) != 2 {
			caCmd.Usage()
			os.Exit(0)
		}
	case "create":
		log.Println("Creating certificate authority certificates...")
		chain := certs.NewCA()
		rootKey, _ := os.OpenFile("root_ca.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		defer rootKey.Close()
		rootCrt, _ := os.OpenFile("root_ca.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		defer rootCrt.Close()
		interKey, _ := os.OpenFile("intermediate_ca.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		defer interKey.Close()
		interCrt, _ := os.OpenFile("intermediate_ca.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		defer interCrt.Close()
		chain.SaveKeys(rootKey, interKey)
		chain.SaveCertificates(rootCrt, interCrt)
		os.Exit(0)
	}
}

// Main flags
var (
	rootCmd = flag.NewFlagSet("attezt", flag.ExitOnError)
	backend = rootCmd.String("backend", "default", "inventory backend to use (default: sqlite)")
)

func Main() {
	rootCmd.Usage = func() {
		fmt.Printf(`Usage:
	ca		Manage the certificate authority
	certificate	Manage device certificates
`)
	}
	rootCmd.Parse(os.Args[1:])
	if len(os.Args) < 2 {
		rootCmd.Usage()
		os.Exit(0)
	}

	switch os.Args[1] {
	case "ca":
		backend, err := inventory.GetBackend(*backend)
		if err != nil {
			log.Fatal(err)
		}

		if err := backend.Init(nil); err != nil {
			log.Fatal(err)
		}
		CAMain(os.Args[2:], backend)
	case "certificate":
		CertificateMain(os.Args[2:])
	default:
		rootCmd.Usage()
	}
}
