package attest

import (
	"crypto/x509/pkix"
	encasn1 "encoding/asn1"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidTPMManufacturer = encasn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidTPMModel        = encasn1.ObjectIdentifier{2, 23, 133, 2, 2}
	oidTPMVersion      = encasn1.ObjectIdentifier{2, 23, 133, 2, 3}
)

type TPMInfo struct {
	Manufacturer    string `json:"manufacturer,omitempty"`
	Model           string `json:"model,omitempty"`
	Version         uint8  `json:"version,omitempty"`
	FirmwareVersion string `json:"firmwareVersion,omitempty"`
}

func (t *TPMInfo) MarshalASN() []byte {
	var b cryptobyte.Builder
	add := func(b *cryptobyte.Builder, oid encasn1.ObjectIdentifier, d string) {
		b.AddASN1(asn1.SET, func(b *cryptobyte.Builder) {
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oid)
				// Per the TPM specc these should be asn1.PrintableString
				b.AddASN1(asn1.PrintableString, func(b *cryptobyte.Builder) {
					b.AddBytes([]byte(d))
				})
			})
		})
	}
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		add(b, oidTPMManufacturer, t.Manufacturer)
		add(b, oidTPMModel, "lol")
		add(b, oidTPMVersion, t.FirmwareVersion)
	})
	return b.BytesOrPanic()
}

func NewTPMInfoFromASN(b []byte) *TPMInfo {
	var t TPMInfo
	var name pkix.RDNSequence
	if _, err := encasn1.Unmarshal(b, &name); err != nil {
		panic("invalid")
	}
	for _, n := range name {
		// TODO: We only parse the string values
		// this is not going to work for TPMInfo.Version
		sec := n[0]
		val, ok := sec.Value.(string)
		if !ok {
			continue
		}
		switch {
		case sec.Type.Equal(oidTPMModel):
			t.Model = val
		case sec.Type.Equal(oidTPMManufacturer):
			t.Manufacturer = val
		case sec.Type.Equal(oidTPMVersion):
			t.FirmwareVersion = val
		}
	}
	return &t
}
