package certs_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/foxboron/attezt/internal/attest"
	"github.com/foxboron/attezt/internal/certs"
	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestNewCA(t *testing.T) {
	caChain := certs.NewCA()
	rwc, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	handle, pub, err := attest.GetAK(rwc)
	if err != nil {
		t.Fatal(err)
	}
	defer keyfile.FlushHandle(rwc, handle)
	akPub, err := pub.OutPublic.Contents()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := attest.NewAKCertificate(akPub)
	if err != nil {
		t.Fatal(err)
	}
	// cert.SetExtensions(a.ekuri(), a.TPMInfo)
	b, err := caChain.Sign(cert.Cert(), cert.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	akCert, err := x509.ParseCertificate(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := caChain.Verify(akCert); err != nil {
		t.Fatal(err)
	}
}

type otherName struct {
	TypeID asn1.ObjectIdentifier
	Value  asn1.RawValue
}

func forEachSAN(extension []byte, callback func(ext asn1.RawValue) error) error {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(extension, &seq)
	if err != nil {
		return err
	} else if len(rest) != 0 {
		return errors.New("x509: trailing data after X.509 extension")
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		return asn1.StructuralError{Msg: "bad SAN sequence"}
	}

	rest = seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return err
		}

		if err := callback(v); err != nil {
			return err
		}
	}

	return nil
}

// https://datatracker.ietf.org/doc/html/rfc5280#page-35
func parseSubjectAltName(ext pkix.Extension) (dirNames []pkix.Name, otherNames []otherName, err error) {
	err = forEachSAN(ext.Value, func(generalName asn1.RawValue) error {
		switch generalName.Tag {
		case 0: // otherName
			var on otherName
			if _, err := asn1.UnmarshalWithParams(generalName.FullBytes, &on, "tag:0"); err != nil {
				return fmt.Errorf("failed unmarshaling otherName: %w", err)
			}
			otherNames = append(otherNames, on)
		case 4: // directoryName
			var rdns pkix.RDNSequence
			// fmt.Println(string(generalName.Bytes))
			if _, err := asn1.Unmarshal(generalName.Bytes, &rdns); err != nil {
				return fmt.Errorf("failed unmarshaling directoryName: %w", err)
			}
			var dirName pkix.Name
			dirName.FillFromRDNSequence(&rdns)
			dirNames = append(dirNames, dirName)
		default:
			// skipping the other tag values intentionally
		}
		return nil
	})
	return
}

func TestRDNS(t *testing.T) {
	//
	by, err := os.ReadFile("../../ak_test_proper")
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(by)
	if err != nil {
		t.Fatal(err)
	}

	oidExtensionSubjectAltName := []int{2, 5, 29, 17}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidExtensionSubjectAltName) {
			_, _, err := parseSubjectAltName(ext)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}
