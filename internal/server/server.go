package server

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/foxboron/attezt/internal/attest"
	"github.com/foxboron/attezt/internal/certs"
	"github.com/foxboron/attezt/internal/inventory"
	ijson "github.com/foxboron/attezt/internal/json"
	"github.com/foxboron/attezt/internal/truststore"
)

type TPMAttestServer struct {
	chain *certs.CertificateChain
	// config *Config
	mu        sync.Mutex
	state     map[string]activation
	inventory inventory.Inventory
	ts        *truststore.TrustStore
}

type activation struct {
	params  *attest.Attestation
	expires time.Time
}

func NewTPMAttestServer(chain *certs.CertificateChain, ts *truststore.TrustStore, inventory inventory.Inventory) *TPMAttestServer {
	return &TPMAttestServer{
		chain:     chain,
		state:     make(map[string]activation),
		inventory: inventory,
		ts:        ts,
	}
}

func (t *TPMAttestServer) attestHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	params, err := ijson.Decode[attest.Attestation](r.Body)
	if err != nil {
		http.Error(w, "invalid attestation request", http.StatusBadRequest)
		return
	}
	if params.TPMInfo == nil || params.AttestParams == nil || params.AttestParams.Public == nil || params.AttestParams.CreateData == nil || params.AttestParams.CreateAttestation == nil {
		http.Error(w, "incomplete attestation", http.StatusBadRequest)
		return
	}
	if len(params.EKCerts) > 0 {
		if t.ts == nil {
			http.Error(w, "EK certificate trust store required", http.StatusForbidden)
			return
		}
		ekpub, err := x509.MarshalPKIXPublicKey(params.EKPub)
		if err != nil {
			http.Error(w, "invalid EK public key", http.StatusBadRequest)
			return
		}
		matched := false
		for _, cert := range params.EKCerts {
			matched = matched || bytes.Equal(ekpub, cert.RawSubjectPublicKeyInfo)
		}
		if !matched {
			http.Error(w, "EK does not match its certificate", http.StatusForbidden)
			return
		}
	}

	secret := make([]byte, 32)
	_, err = rand.Read(secret)
	if err != nil {
		http.Error(w, "challenge unavailable", http.StatusInternalServerError)
		return
	}

	// Validate that we trust the EK certificate roots
	if t.ts != nil {
		for _, ekcert := range params.EKCerts {
			_, err = t.ts.VerifyCertificate(ekcert)
			if err != nil {
				http.Error(w, "untrusted EK certificate", http.StatusForbidden)
				return
			}
		}
	}

	ok, err := params.Verify()
	if err != nil || !ok {
		if err != nil {
			fmt.Println(err)
		}
		http.Error(w, "attestation verification failed", http.StatusForbidden)
		return
	}

	ok, err = t.inventory.Lookup(&params)
	if err != nil || !ok {
		if err != nil {
			fmt.Println(err)
		}
		// We did not find the device in the inventory
		http.Error(w, "device not approved", http.StatusForbidden)
		return
	}

	t.mu.Lock()
	for key, state := range t.state {
		if !state.expires.After(time.Now()) {
			delete(t.state, key)
		}
	}
	if len(t.state) >= 128 {
		t.mu.Unlock()
		http.Error(w, "too many pending activations", http.StatusTooManyRequests)
		return
	}
	rsp, err := params.CreateCredential(secret)
	if err != nil {
		t.mu.Unlock()
		fmt.Println(err)
		http.Error(w, "credential creation failed", http.StatusInternalServerError)
		return
	}

	t.state[string(secret)] = activation{params: &params, expires: time.Now().Add(2 * time.Minute)}
	t.mu.Unlock()

	if err := ijson.Encode(w, 200, rsp); err != nil {
		fmt.Println(err)
		fmt.Fprintf(w, "can't return challenge")
		return
	}
}

func (t *TPMAttestServer) secretHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	req, err := ijson.Decode[*attest.SecretRequest](r.Body)
	if err != nil {
		http.Error(w, "invalid activation request", http.StatusBadRequest)
		return
	}

	if req == nil || len(req.Secret) != 32 {
		http.Error(w, "invalid activation", http.StatusForbidden)
		return
	}
	t.mu.Lock()
	val, ok := t.state[string(req.Secret)]
	delete(t.state, string(req.Secret))
	t.mu.Unlock()
	if !ok || !val.expires.After(time.Now()) {
		http.Error(w, "invalid or expired activation", http.StatusForbidden)
		return
	}

	state := val.params
	if approved, err := t.inventory.Lookup(state); err != nil || !approved {
		http.Error(w, "device not approved", http.StatusForbidden)
		return
	}
	cert, err := state.AKCertificate()
	if err != nil {
		fmt.Println(err)
		http.Error(w, "certificate creation failed", http.StatusInternalServerError)
		return
	}

	certbytes, err := t.chain.Sign(cert.Cert(), cert.PublicKey())
	if err != nil {
		fmt.Println(err)
		http.Error(w, "certificate signing failed", http.StatusInternalServerError)
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
	mux.HandleFunc("POST /attest", t.attestHandler)
	mux.HandleFunc("POST /secret", t.secretHandler)
	mux.HandleFunc("GET /root.pem", t.serveRootCertificate)
	return &mux
}
