package server

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/foxboron/attezt/internal/attest"
	"github.com/foxboron/attezt/internal/certs"
	"github.com/foxboron/attezt/internal/truststore"
	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

type approvedInventory struct {
	deniedInventory
	ek string
}

func (d *approvedInventory) Lookup(a *attest.Attestation) (bool, error) {
	return a.EKPubHash() == d.ek, nil
}

func TestApprovedEKActivationIssuesBoundCertificate(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()
	ak, created, err := attest.GetAK(tpm, tpm2.TPMAlgRSA)
	if err != nil {
		t.Fatal(err)
	}
	defer keyfile.FlushHandle(tpm, ak)
	conf := &attest.AttestationConfig{AKHandle: ak, AKRsp: created, KeyAlg: tpm2.TPMAlgRSA}
	params, err := attest.NewAttestationParametersWithAlg(tpm, conf)
	if err != nil {
		t.Fatal(err)
	}
	ek, ekPublic, err := attest.GetEK(tpm, tpm2.TPMAlgRSA)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := tpm2.Pub(*ekPublic)
	if err != nil {
		t.Fatal(err)
	}
	keyfile.FlushHandle(tpm, ek)
	a := &attest.Attestation{TPMInfo: &attest.TPMInfo{Manufacturer: "SIM", Model: "test", Version: 2, FirmwareVersion: "1"}, EKPub: pub, AttestParams: params}
	ca := certs.NewCA()
	db := &approvedInventory{ek: a.EKPubHash()}
	s := NewTPMAttestServer(ca, nil, db)
	post := func(path string, in any) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		s.Handlers().ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body)))
		return w
	}
	a.EKCerts = []*x509.Certificate{ca.RootCertificate()}
	s.ts = truststore.NewTrustStore(false)
	if w := post("/attest", a); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "EK does not match") {
		t.Fatal("unrelated EK certificate accepted")
	}
	a.EKCerts = nil
	w := post("/attest", a)
	if w.Code != http.StatusOK {
		t.Fatalf("attest: %d %s", w.Code, w.Body.String())
	}
	var challenge attest.AttestationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	activationEK, _, err := attest.GetEK(tpm, tpm2.TPMAlgRSA)
	if err != nil {
		t.Fatal(err)
	}
	defer keyfile.FlushHandle(tpm, activationEK)
	activated, err := (tpm2.ActivateCredential{
		ActivateHandle: ak,
		KeyHandle:      tpm2.AuthHandle{Handle: activationEK.Handle, Name: activationEK.Name, Auth: tpm2.Policy(tpm2.TPMAlgSHA256, 16, attest.EkPolicy)},
		CredentialBlob: challenge.Credential, Secret: challenge.Secret,
	}).Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}
	request := attest.SecretRequest{Secret: activated.CertInfo.Buffer}
	w = post("/secret", request)
	if w.Code != http.StatusOK {
		t.Fatalf("activate: %d %s", w.Code, w.Body.String())
	}
	var response attest.SecretResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.CertificateChain) != 2 {
		t.Fatal("missing chain")
	}
	leaf, err := x509.ParseCertificate(response.CertificateChain[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Verify(leaf); err != nil {
		t.Fatal(err)
	}
	akPublic, err := tpm2.Pub(*params.Public)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(akPublic)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(spki, leaf.RawSubjectPublicKeyInfo) || len(leaf.URIs) != 1 {
		t.Fatal("certificate binding missing")
	}
	if w := post("/secret", request); w.Code != http.StatusForbidden {
		t.Fatal("activation replay accepted")
	}
	db.ek = "unapproved"
	if w := post("/attest", a); w.Code != http.StatusForbidden {
		t.Fatal("unapproved EK accepted")
	}
}
