package attest_test

import (
	"bytes"
	"crypto/x509"
	encasn1 "encoding/asn1"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/cryptobyte/asn1"

	"github.com/foxboron/attezt/internal/attest"
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
			a, err := attest.NewAttestationParameters(rwc)
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
			if got == tt.want {
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
