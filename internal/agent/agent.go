package agent

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	aacme "github.com/foxboron/attezt/internal/acme"
	"github.com/foxboron/attezt/internal/attest"
	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
	"github.com/smallstep/go-p11-kit/p11kit"
	"github.com/varlink/go/varlink"
)

type ObjectHandler struct {
	objects []p11kit.Object
}

func (o *ObjectHandler) GetObjects() ([]p11kit.Object, error) {
	// TODO: Needs a mutex?
	if len(o.objects) == 0 {
		return nil, fmt.Errorf("no certificate objects")
	}
	return o.objects, nil
}

func (o *ObjectHandler) SetTPMKey(signer crypto.Signer, cert *x509.Certificate) error {
	obj, err := p11kit.NewPrivateKeyObject(signer)
	if err != nil {
		return err
	}

	if err := obj.SetCertificate(cert); err != nil {
		return err
	}
	obj.SetLabel("Attezt TPM key")

	certobj, err := p11kit.NewX509CertificateObject(cert)
	if err != nil {
		return err
	}
	certobj.SetLabel("Attezt TPM Certificate")

	o.objects = append(o.objects, certobj, obj)
	return nil
}

func (o *ObjectHandler) SetIntermediate(cert *x509.Certificate) error {
	obj, err := p11kit.NewPublicKeyObject(cert.PublicKey)
	if err != nil {
		return err
	}

	if err := obj.SetCertificate(cert); err != nil {
		return err
	}
	obj.SetLabel("Intermediate Certificate Public Key")

	certobj, err := p11kit.NewX509CertificateObject(cert)
	if err != nil {
		return err
	}
	certobj.SetLabel("Intermediate Certificate")

	o.objects = append(o.objects, certobj, obj)
	return nil
}

func NewObjecHandler() *ObjectHandler {
	return &ObjectHandler{objects: []p11kit.Object{}}
}

type AtteztAgent struct {
	rwc      transport.TPMCloser
	ctx      context.Context
	varlink  *varlink.Service
	obj      *ObjectHandler
	p11      net.Listener
	wg       *sync.WaitGroup
	statedir string
	// atteztServer string
	// acmeServer   string
}

func (a *AtteztAgent) Close() error {
	// Close context
	err := errors.Join(a.p11.Close(), a.varlink.Shutdown())
	a.wg.Wait()
	return err
}

func (a *AtteztAgent) GetCertificate() error {
	subject, err := os.Hostname()
	if err != nil {
		return err
	}

	// TODO: Make this configurable
	atteztServer := "http://attezt.local:8080"
	acmeServer := "https://ca.home.arpa/acme/acme-da/directory"

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	account := acme.Account{
		TermsOfServiceAgreed: true,
		PrivateKey:           privateKey,
	}

	client := acmez.Client{
		Client: &acme.Client{
			Directory: acmeServer,
		},
	}
	account, err = client.NewAccount(a.ctx, account)
	if err != nil {
		return err
	}

	t := time.Now()
	tafter := t.Add(24 * time.Hour)
	order := acme.Order{
		Identifiers: []acme.Identifier{{
			Type:  "permanent-identifier",
			Value: subject,
		}},
		NotBefore: &t,
		NotAfter:  &tafter,
	}

	order, err = client.NewOrder(a.ctx, account, order)
	if err != nil {
		return err
	}

	url := order.Authorizations[0]

	authz, err := client.GetAuthorization(a.ctx, account, url)
	if err != nil {
		return err
	}

	challenge := authz.Challenges[0]

	TPMALG := tpm2.TPMAlgRSA
	// TPM CHALLENGE RESLOUTION HERE
	c := attest.NewClient(atteztServer)

	// Turn into signer
	akHandle, akrsp, err := attest.GetAK(a.rwc, TPMALG)
	if err != nil {
		return err
	}
	defer keyfile.FlushHandle(a.rwc, akHandle)

	s, err := account.Thumbprint()
	if err != nil {
		return err
	}
	data := fmt.Sprintf("%s.%s", challenge.Token, s)
	hashedData := sha256.Sum256([]byte(data))

	aconf := &attest.AttestationConfig{
		AKHandle: akHandle,
		AKRsp:    akrsp,
		KeyAlg:   TPMALG,
		Name:     []byte("app-test"),
	}

	att, err := attest.NewAttestation(a.rwc, aconf)
	if err != nil {
		return err
	}

	certs, err := c.GetAttestWithAlg(a.rwc, att)
	if err != nil {
		return err
	}

	// Create a new key and attest with AK
	key, _, err := keyfile.NewLoadableKeyWithResponse(a.rwc, TPMALG, 2048, []byte(""))
	if err != nil {
		return err
	}

	keyhandle, parenthandle, err := keyfile.LoadKey(keyfile.NewTPMSession(a.rwc), key, []byte(nil))
	if err != nil {
		return err
	}

	tkey, err := key.Pubkey.Contents()
	if err != nil {
		return err
	}

	// Certify the creation of it by loading it
	dkattestparams, err := attest.CertifyKey(a.rwc, *aconf.AKHandle, tpm2.NamedHandle{Handle: keyhandle.Handle, Name: keyhandle.Name}, tkey, hashedData[:])
	if err != nil {
		return err
	}

	// TODO: Cerify should be part of go-tpm-keys
	// Flush before Signer
	// else we'll run out of memory
	keyfile.FlushHandle(a.rwc, keyhandle)
	keyfile.FlushHandle(a.rwc, parenthandle)

	payloadBytes, err := aacme.CreateAttestationPayload(certs, aconf.KeyAlg, dkattestparams)
	if err != nil {
		return err
	}
	challenge.Payload = payloadBytes

	csr := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: subject,
		},
	}

	signer, err := key.Signer(a.rwc, []byte(""), []byte(""))
	if err != nil {
		return err
	}
	csrbytes, err := x509.CreateCertificateRequest(rand.Reader, csr, signer)
	if err != nil {
		return fmt.Errorf("create certificate request: %v", err)
	}

	// STOP TPM

	challenge, err = client.InitiateChallenge(a.ctx, account, challenge)
	if err != nil {
		return fmt.Errorf("initiating challenge %q: %v", challenge.URL, err)
	}

	order, err = client.FinalizeOrder(a.ctx, account, order, csrbytes)
	if err != nil {
		return err
	}

	certChains, err := client.GetCertificateChain(a.ctx, account, order.Certificate)
	if err != nil {
		return fmt.Errorf("downloading certs: %v", err)
	}

	if err := a.SaveKeys(key.Bytes(), certChains[0].ChainPEM); err != nil {
		return err
	}

	// Set client certificate
	cbytes := certChains[0]
	b, rest := pem.Decode(cbytes.ChainPEM)
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return err
	}
	if err := a.obj.SetTPMKey(signer, cert); err != nil {
		return err
	}

	// Set intermediate cert
	b, _ = pem.Decode(rest)
	cert, err = x509.ParseCertificate(b.Bytes)
	if err != nil {
		return err
	}
	if err := a.obj.SetIntermediate(cert); err != nil {
		return err
	}
	return nil
}

func NewAtteztAgent(ctx context.Context, rwc transport.TPMCloser, varlink, p11sock, statedir string) (*AtteztAgent, error) {
	var wg sync.WaitGroup
	objhandler := &ObjectHandler{}

	slot := p11kit.Slot{
		ID:              0x01,
		Description:     "Attezt Attestation Agent",
		Label:           "Attestation Trust",
		Manufacturer:    "attezt",
		Model:           "attezt-agent",
		Serial:          "12345678",
		HardwareVersion: p11kit.Version{Major: 0, Minor: 1},
		FirmwareVersion: p11kit.Version{Major: 0, Minor: 1},
		GetObjects:      objhandler.GetObjects,
	}

	handler := p11kit.Handler{
		Manufacturer:   "attezt",
		Library:        "attezt-agent",
		LibraryVersion: p11kit.Version{Major: 0, Minor: 1},
		Slots:          []p11kit.Slot{slot},
	}

	l, err := net.Listen("unix", p11sock)
	if err != nil {
		return nil, err
	}
	wg.Go(func() {
		for {
			select {
			case <-ctx.Done():
				log.Println("stopping p11-kit agent")
				return
			default:
				conn, err := l.Accept()
				if err != nil {
					continue
				}
				go func() {
					if err := handler.Handle(conn); err != nil {
						log.Printf("cannot handle request, %v", err)
					}
					conn.Close()
				}()
			}
		}
	})

	agent := &AtteztAgent{
		rwc:      rwc,
		ctx:      ctx,
		p11:      l,
		wg:       &wg,
		statedir: statedir,
		obj:      objhandler,
	}

	vs, err := NewVarlinkServer(ctx, agent)
	if err != nil {
		return nil, err
	}

	// TODO: There might be a circular dependency here at some point
	agent.varlink = vs

	addressURI := "unix:" + varlink

	wg.Go(func() {
		if err := vs.Listen(ctx, addressURI, 0); err != nil {
			log.Fatal(err)
		}
		log.Println("stopping varlink service")
	})

	return agent, nil
}

func (a *AtteztAgent) LoadKeys(key []byte, cert []byte) error {
	tpmkey, err := keyfile.Decode(key)
	if err != nil {
		return err
	}

	b, rest := pem.Decode(cert)
	certx509, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return err
	}

	signer, err := tpmkey.Signer(a.rwc, []byte(""), []byte(""))
	if err != nil {
		return err
	}

	if err := a.obj.SetTPMKey(signer, certx509); err != nil {
		return err
	}

	// Set intermediate cert
	b, _ = pem.Decode(rest)
	certx509, err = x509.ParseCertificate(b.Bytes)
	if err != nil {
		return err
	}
	if err := a.obj.SetIntermediate(certx509); err != nil {
		return err
	}

	return nil
}

func (a *AtteztAgent) SaveKeys(key []byte, cert []byte) error {
	devicecrt, err := os.OpenFile("device.crt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer devicecrt.Close()
	if _, err := devicecrt.Write(cert); err != nil {
		return err
	}

	devicetss, err := os.OpenFile("device.tss", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer devicetss.Close()
	if _, err := devicetss.Write(key); err != nil {
		return err
	}
	return nil
}
