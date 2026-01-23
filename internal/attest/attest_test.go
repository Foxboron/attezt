package attest_test

import (
	"bytes"
	"crypto/x509"
	encasn1 "encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/cryptobyte/asn1"

	"github.com/foxboron/attezt/internal/attest"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"golang.org/x/crypto/cryptobyte"
)

func TestAttestationParameters_Verify(t *testing.T) {
	rwc, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer rwc.Close()
	tests := []struct {
		name    string
		want    bool
		wantErr bool
	}{
		{"should be true", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := attest.NewAttestationParametersWithAlg(rwc, tpm2.TPMAlgECC)
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}
			got, gotErr := a.Verify()
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Verify() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Verify() succeeded unexpectedly")
			}
			if got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

var oidSAN = encasn1.ObjectIdentifier{2, 5, 29, 17}

var (
	directoryNameTag = asn1.Tag(4).Constructed().ContextSpecific()
	uriTag           = asn1.Tag(6).ContextSpecific()
)

var akCertTest = []byte(`
-----BEGIN CERTIFICATE-----
MIIDnDCCAoSgAwIBAgIRAJ/4lUjTZkKcqJdB7mGbgPswDQYJKoZIhvcNAQELBQAw
JjEkMCIGA1UEAxMbVFBNIFRlc3RpbmcgSW50ZXJtZWRpYXRlIENBMB4XDTI1MTIy
MDE2MzUwM1oXDTI1MTIyMTE2MzUwM1owADCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBALjttPQYVR2IOuX8/sbpEMrciw4ToxARBO6zI0wsX325wBujJ7c3
Ku7XKLS/aH8FRdpzeVA6pNk3DyBpTBKgHsLTR3IwdgAxuimMwHnf3ZprbslkY45H
xbKvelnTv79MeuBgVdwTQ7EcoaAf0RflUzSCA5CfxjqRa+PkLyVe40r9kAJD7YoT
V0R2i5HxivjeiLKxWAN9j6eWl3vPkaojvz6nHIMoOdDc3DMidYeM/hydcNt5GjGb
EBrewmFE80CeLrnzqa2ELPI+ml1TTjKDRXuTpdNTf+PfiaLCf7SZoe6YdhoPc97i
emCmw8nbrD1cmZR+bZksqSLPspU0SCZddAMCAwEAAaOB6jCB5zAQBgNVHSUECTAH
BgVngQUIAzAdBgNVHQ4EFgQUTB2ZyOeT1lt8VKiJ7WQHAZM8+MswHwYDVR0jBBgw
FoAUYXJGM0pjeBVnJ5nVcGKwZn4V3lQwgZIGA1UdEQEB/wSBhzCBhIY6dXJuOmVr
OnNoYTI1NjpMa09RdG1POW9zTTJXTklUREpxNDhyMEhxYVU0MXNrQ0cwNy82SFpZ
Tk9BPaRGMEQxFTATBgVngQUCARMKMTQxNDc0NzIxNTEaMBgGBWeBBQICEw9TTEIg
OTY3MCBUUE0yLjAxDzANBgVngQUCAxMENy41NTANBgkqhkiG9w0BAQsFAAOCAQEA
trK7kRb4Q0enwQksAbanJMlVi5s6KLbOxlK6YMazn8yGtSm5FPIx5mzwTaKDjHEh
WmliBi3l+6tT3ta0PSq6G7ZHb13EupuAe8o2vzOoBJvAiCOkTJvRiyWrtx7C3A+4
DLRjmtrw6E28gzEbK1ToMCUpQTP6vpkUcmpdryf5yDP3A771kVZrXwPCqGYp1h01
OkFMgiA+5Ut1JZNsCJGvdlx2KFlRF4BhxEZ0Y1Bhi5DFEwCuQtKzTSMv9QiZD/2k
8IQja3YsSTFjSgvNYAgXltRXpaXjvmYk2CBlanwvSjPzCkyy9HFozqiqAF8ZWyCu
aMul/T5p5hVQ3yH6TwGmyw==
-----END CERTIFICATE-----
`)

func TestReadAKCert(t *testing.T) {
	block, _ := pem.Decode(akCertTest)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidSAN) {
			continue
		}
		s := cryptobyte.String(ext.Value)
		var sanSeq cryptobyte.String
		if !s.ReadASN1(&sanSeq, asn1.SEQUENCE) {
			t.Fatal("failed parsing asn1")
		}
		for !sanSeq.Empty() {
			var tag asn1.Tag
			var v cryptobyte.String
			if !sanSeq.ReadAnyASN1(&v, &tag) {
				t.Fatal("failed parsing asn1")
			}
			switch tag {
			case uriTag:
				_ = string(v)
			case directoryNameTag:
				tpminfo := attest.NewTPMInfoFromASN(v)
				b := tpminfo.MarshalASN()
				if !bytes.Equal(b, v) {
					t.Fatal("these are not equal")
				}
			}
		}
	}
}

var attestJSON = []byte(`{"tpmInfo":{"version":2,"manufacturer":"1314145024","model":"NPCT75x\u0000\"!!4rls","firmwareVersion":"7.2"},"ek":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwJ+utdrsZBS2wsSm6Ftzn1jrdWCClnvJDtgng1oN9/+EzBmXDbePj98o4NWb/QLoq82zrJ+kCSmk5d5JWfeQYJc6BPexP2OXiMjonPbkovahwWlbReDSKX9NHDfmbqk4tjcabvkTLUmImiAsYVXVMcZ8iM2KL9Ov0j2WCFAmn6E2kBH+nqO41OxavEfzVARJxlYCsijYzHxUujrUtY+nFzhZvN2IDUM5RVYZRD6vLtIbSLItbd+ovdY3ryug/0OHrUCjxD7q+BuA37P0iba3qVHgffhF+HFqPDBIUhmvd17U0aBMUQaivdHKg/v1cgd9iRvPfwukpZv6YBxXETlGcQIDAQAB","ekCerts":["MIIDUDCCAvagAwIBAgIKJ0Y0DvmXqtNd2jAKBggqhkjOPQQDAjBVMVMwHwYDVQQDExhOdXZvdG9uIFRQTSBSb290IENBIDIxMTEwJQYDVQQKEx5OdXZvdG9uIFRlY2hub2xvZ3kgQ29ycG9yYXRpb24wCQYDVQQGEwJUVzAeFw0yMDEwMDcwMTI5MjJaFw00MDEwMDMwMTI5MjJaMAAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAn6612uxkFLbCxKboW3OfWOt1YIKWe8kO2CeDWg33/4TMGZcNt4+P3yjg1Zv9AuirzbOsn6QJKaTl3klZ95BglzoE97E/Y5eIyOic9uSi9qHBaVtF4NIpf00cN+ZuqTi2Nxpu+RMtSYiaICxhVdUxxnyIzYov06/SPZYIUCafoTaQEf6eo7jU7Fq8R/NUBEnGVgKyKNjMfFS6OtS1j6cXOFm83YgNQzlFVhlEPq8u0htIsi1t36i91jevK6D/Q4etQKPEPur4G4Dfs/SJtrepUeB9+EX4cWo8MEhSGa93XtTRoExRBqK90cqD+/VyB32JG89/C6Slm/pgHFcROUZxAgMBAAGjggE2MIIBMjBQBgNVHREBAf8ERjBEpEIwQDE+MBQGBWeBBQIBEwtpZDo0RTU0NDMwMDAQBgVngQUCAhMHTlBDVDc1eDAUBgVngQUCAxMLaWQ6MDAwNzAwMDIwDAYDVR0TAQH/BAIwADAQBgNVHSUECTAHBgVngQUIATAfBgNVHSMEGDAWgBQj9OIq0743SkSXcpVKooOu11JXLjAOBgNVHQ8BAf8EBAMCBSAwIgYDVR0JBBswGTAXBgVngQUCEDEOMAwMAzIuMAIBAAICAIowaQYIKwYBBQUHAQEEXTBbMFkGCCsGAQUFBzAChk1odHRwczovL3d3dy5udXZvdG9uLmNvbS9zZWN1cml0eS9OVEMtVFBNLUVLLUNlcnQvTnV2b3RvbiBUUE0gUm9vdCBDQSAyMTExLmNlcjAKBggqhkjOPQQDAgNIADBFAiBg0oi1qkJ6IDPbN8/J83q5oS5AQTNkD4bd/186XGTFaAIhAMUTyPiULokTPnVFU4yInkCD3RSKb1lqx7QeA+yf3xoq"],"params":{"public":"AAEACwAFBHIAAAAQABQACwgAAAAAAAEAsrfG/HFFMPn9Euz6S9URIrJ7rocJBw77SkuVlfeuNWPitbArHF9w2ke/+arEob1zeE9nL4CxwZ6Wg42zg4G7kiNoG0W+FgLBYjlreABRu9F8K4qdoCdIZPE5S5o5V0C81U615aaWoIPj0Zg48HCzsAvuXUtwRBsAylX8scrvh+D9XENlv2aRlSdYGEwSdQlDwS+5ZG7ZFHOvwmF9uzVp11fvjshSPltaodbmMnog+ySGiG728k7wJ1NywwC5dM1ZPCuWtVn6C8Op7hWDmbOTKAJxc+3bVosjRc6sA5HK5lD7NEkGHbSKFwJU+xC4Xb056VDv572Zo259isVSPPQErQ==","createData":"AAAAAAAg47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFUBAAsAIgAL0KRv0xR2QQRCbbsFrX9H5vl2dCTZAM9kH8VVguDHQCMAIgALYr+fpRtKkDaAzFkJ9aG6OnFYjYNXa16CYfhD/fJdil8AAA==","createAttestation":"/1RDR4AaACIACwIOkO4POd7S/q6+EVezghrQmlAkCHW7Nm0sLeAEPoUuAAAAAAAW3zvU/ciI+1MYtjOqAeRysO1kRRFsACIAC4P/TrDg3hU4AtGNMso4nI9BMv86DT5vOb5qDkP2bj9HACDUKH7lMwdyMOP1glyO+nSuxa5b3AUGRCaGtH7zMvufGw==","createSignature":"ABQACwEAYBBKZujBMb/L8vFg8aq7SinQCBHA/1RrE+u8WDtJsOVLAb+kyHyMwKo1kJuiKEiO9S/bPkBdZZ5/FlMum2NtQqzuKonWyVcayjiIqX1OyMtJgNihfihsnouxCLWQ7+6siSP8pC1bHxji+Kg0xCH8bAV3uLg0jthpGYnifrBRyHgMlk9vqkH6JvS7ipoaXXEK6kQFMSiw4V0hZQjq5IBh44IJvGGN0s6RcRnHdUnf1z/BwMX6JTJ0lJkmOxhlRL+wfDtKRFLAALbfdxtfBffKx5qPSVw7yuZ3Z+jlCtDhMtUPjXwtxK32FxOndZYc3QVUVt7KdPJ81hxMfGhI+jWXpw=="}}`)

func TestCertifyAttestationJSON(t *testing.T) {
	var attestation attest.Attestation
	if err := json.Unmarshal(attestJSON, &attestation); err != nil {
		t.Fatalf("failed to unmarshal")
	}

	ok, err := attestation.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("failed to verify json blob")
	}
}
