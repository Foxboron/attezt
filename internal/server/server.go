package server

import (
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net/http"
	"sync"

	"github.com/foxboron/attezt/internal/attest"
	"github.com/foxboron/attezt/internal/certs"
	"github.com/foxboron/attezt/internal/inventory"
	ijson "github.com/foxboron/attezt/internal/json"
	"github.com/google/go-tpm/tpm2"
)

type TPMAttestServer struct {
	chain *certs.CertificateChain
	// config *Config
	state     *sync.Map
	inventory inventory.Inventory
}

func NewTPMAttestServer(chain *certs.CertificateChain, inventory inventory.Inventory) *TPMAttestServer {
	return &TPMAttestServer{
		chain:     chain,
		state:     new(sync.Map),
		inventory: inventory,
	}
}

func (t *TPMAttestServer) attestHandler(w http.ResponseWriter, r *http.Request) {
	params, err := ijson.Decode[attest.Attestation](r.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	secret := make([]byte, 32)
	_, err = rand.Read(secret)
	if err != nil {
		fmt.Fprintf(w, "failed to obtain random challenge: %v", err)
		return
	}

	ok, err := params.Verify()
	if !ok {
		if err != nil {
			fmt.Println(err)
		}
		fmt.Fprintf(w, "attestation verification failed")
		return
	}

	ok, err = t.inventory.Lookup(&params)
	if !ok {
		if err != nil {
			fmt.Println(err)
		}
		// We did not find the device in the inventory
		fmt.Fprintf(w, "invetory lookup failed")
		return
	}

	rsp, err := params.CreateCredential(secret)
	if err != nil {
		fmt.Println(err)
		return
	}

	rakpub, _ := tpm2.Pub(*params.AttestParams.Public)
	fmt.Printf("Remote AKPublic: %s\n", attest.HashPub(rakpub))

	t.state.Store(string(secret), &params)

	if err := ijson.Encode(w, 200, rsp); err != nil {
		fmt.Println(err)
		fmt.Fprintf(w, "can't return challenge")
		return
	}
}

func (t *TPMAttestServer) secretHandler(w http.ResponseWriter, r *http.Request) {
	req, err := ijson.Decode[*attest.SecretRequest](r.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	// TODO: We should do more validation then just the lookup.
	val, ok := t.state.Load(string(req.Secret))
	if !ok {
		fmt.Println(err)
		return
	}

	state := val.(*attest.Attestation)
	cert, err := state.AKCertificate()
	if err != nil {
		fmt.Println(err)
		return
	}

	certbytes, err := t.chain.Sign(cert.Cert(), cert.PublicKey())
	if err != nil {
		fmt.Println(err)
		return
	}

	// This is the chain. Signed certificate last.
	sec := &attest.SecretResponse{
		CertificateChain: [][]byte{
			certbytes,
			t.chain.IntermediateCertificate().Raw,
		},
	}
	if err := ijson.Encode(w, 200, sec); err != nil {
		fmt.Println(err)
		fmt.Fprintf(w, "can't return challenge")
		return
	}
}

func (t *TPMAttestServer) serveRootCertificate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(200)
	cert := t.chain.RootCertificate()
	if err := pem.Encode(w, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}); err != nil {
		fmt.Println(err)
		fmt.Fprintf(w, "can't return root certificate")
	}
}

func (t *TPMAttestServer) Handlers() *http.ServeMux {
	var mux http.ServeMux
	mux.HandleFunc("/attest", t.attestHandler)
	mux.HandleFunc("/secret", t.secretHandler)
	mux.HandleFunc("/root.pem", t.serveRootCertificate)
	return &mux
}
