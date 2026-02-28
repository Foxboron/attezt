package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"net"
	"os"
	"path/filepath"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/smallstep/go-p11-kit/p11kit"
)

type TPMObj struct {
	Data []byte `json:"data"`
}

type TPMKey struct {
	Private []byte `json:"KeyBlob"`
	Public  []byte `json:"Public"`
}

func TPMObjToKey(b []byte) (*keyfile.TPMKey, error) {
	var t TPMObj
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, err
	}

	var tkey TPMKey
	if err := json.Unmarshal(t.Data, &tkey); err != nil {
		return nil, err
	}

	pub2b := tpm2.BytesAs2B[tpm2.TPMTPublic](tkey.Public)
	priv2b := tpm2.TPM2BPrivate{Buffer: tkey.Private}

	return keyfile.NewTPMKey(
		keyfile.OIDLoadableKey,
		pub2b, priv2b,
		keyfile.WithParent(tpm2.TPMHandle(0x81000001)),
	), nil
}

func main() {
	rwc, err := linuxtpm.Open("/dev/tpmrm0")
	if err != nil {
		log.Fatal(err)
	}
	defer rwc.Close()

	b, err := os.ReadFile("device.crt")
	if err != nil {
		log.Fatal(err)
	}

	var certs []*x509.Certificate
	block := b
	for {
		p, rest := pem.Decode(block)
		if p == nil {
			break
		}
		if p.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(p.Bytes)
			if err != nil {
				log.Fatal(err)
			} else {
				certs = append(certs, cert)
			}
		}
		block = rest
		if len(block) == 0 {
			break
		}
	}

	// Top certificate is ours, 2nd is the intermediate root
	c := certs[0]

	tpmobjb, err := os.ReadFile("key-device.tpmobj")
	if err != nil {
		log.Fatal(err)
	}

	tpmkey, err := TPMObjToKey(tpmobjb)
	if err != nil {
		log.Fatal(err)
	}

	signer, err := tpmkey.Signer(rwc, []byte(""), []byte(""))
	if err != nil {
		log.Fatal(err)
	}

	obj, err := p11kit.NewPrivateKeyObject(signer)
	if err != nil {
		log.Fatal(err)
	}

	if err := obj.SetCertificate(c); err != nil {
		log.Fatal(err)
	}
	obj.SetLabel("Attezt TPM key")

	certobj, err := p11kit.NewX509CertificateObject(c)
	if err != nil {
		log.Fatal(err)
	}
	certobj.SetLabel("Attezt TPM Certificate")

	objs := []p11kit.Object{certobj, obj}

	slot := p11kit.Slot{
		ID:              0x01,
		Description:     "Attezt Attestation Agent",
		Label:           "Attestation Trust",
		Manufacturer:    "attezt",
		Model:           "attezt-agent",
		Serial:          "12345678",
		HardwareVersion: p11kit.Version{Major: 0, Minor: 1},
		FirmwareVersion: p11kit.Version{Major: 0, Minor: 1},
		Objects:         objs,
	}

	handler := p11kit.Handler{
		Manufacturer:   "attezt",
		Library:        "attezt-agent",
		LibraryVersion: p11kit.Version{Major: 0, Minor: 1},
		Slots:          []p11kit.Slot{slot},
	}

	dir, _ := os.Getwd()
	path := filepath.Join(dir, "p11kit.sock")
	defer os.RemoveAll(path)

	l, err := net.Listen("unix", path)
	if err != nil {
		log.Fatalf("listening on %s: %v", path, err)
	}
	defer l.Close()

	log.Printf("export P11_KIT_SERVER_ADDRESS=unix:path=%s", path)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("cannot accept, %v", err)
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
