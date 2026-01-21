package attest

import (
	"crypto/x509/pkix"
	encasn1 "encoding/asn1"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
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
		add(b, oidTPMModel, sanitizeString(t.Model))
		add(b, oidTPMVersion, t.FirmwareVersion)
	})
	return b.BytesOrPanic()
}

func NewTPMInfo(rwc transport.TPMCloser) (*TPMInfo, error) {
	var tpminfo TPMInfo
	var vendorString string
	vprops := []tpm2.TPMPT{
		tpm2.TPMPTVendorString1,
		tpm2.TPMPTVendorString2,
		tpm2.TPMPTVendorString3,
		tpm2.TPMPTVendorString4,
	}
	for _, p := range vprops {
		cap, err := tpm2.GetCapability{
			Capability:    tpm2.TPMCapTPMProperties,
			Property:      uint32(p),
			PropertyCount: 1,
		}.Execute(rwc)
		if err != nil {
			return nil, err
		}
		prop, err := cap.CapabilityData.Data.TPMProperties()
		if err != nil {
			return nil, err
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, prop.TPMProperty[0].Value)
		// Seems some end the string with null byte, so strip all segments
		vendorString += strings.Trim(string(b), "\x00")
	}
	tpminfo.Model = sanitizeString(vendorString)
	cap, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTManufacturer),
		PropertyCount: 1,
	}.Execute(rwc)
	if err != nil {
		return nil, err
	}
	prop, err := cap.CapabilityData.Data.TPMProperties()
	if err != nil {
		return nil, err
	}
	tpminfo.Manufacturer = TCGVendorID(prop.TPMProperty[0].Value).String()
	tpminfo.Version = 2

	cap, err = tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTFirmwareVersion1),
		PropertyCount: 1,
	}.Execute(rwc)
	if err != nil {
		return nil, err
	}
	prop, err = cap.CapabilityData.Data.TPMProperties()
	if err != nil {
		return nil, err
	}
	fw := prop.TPMProperty[0].Value

	major := int((fw & 0xffff0000) >> 16)
	minor := int(fw & 0x0000ffff)
	tpminfo.FirmwareVersion = fmt.Sprintf("%d.%d", major, minor)

	return &tpminfo, nil
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
			t.Model = sanitizeString(val)
		case sec.Type.Equal(oidTPMManufacturer):
			t.Manufacturer = val
		case sec.Type.Equal(oidTPMVersion):
			t.FirmwareVersion = val
		}
	}
	return &t
}

// Taken from go-attestation and updated with new values

type TCGVendorID uint32

var vendors = map[TCGVendorID]string{
	1095582720: "AMD",
	1095652352: "Ant Group",
	1096043852: "Atmel",
	1112687437: "Broadcom",
	1129530191: "Cisco",
	1179408723: "Flyslice Technologies",
	1196379975: "Google",
	1213221120: "HPI",
	1213220096: "HPE",
	1212765001: "Huawei",
	1229081856: "IBM",
	1229346816: "Infineon",
	1229870147: "Intel",
	1279610368: "Lenovo",
	1297303124: "Microsoft",
	1314082080: "National Semiconductor",
	1314150912: "Nationz",
	1314145024: "Nuvoton Technology",
	1363365709: "Qualcomm",
	1397576526: "Samsung",
	1397048133: "SecEdge",
	1397641984: "Sinosun",
	1397576515: "SMSC",
	1398033696: "STMicroelectronics",
	1415073280: "Texas Instruments",
	1464156928: "Winbond",
	1397047628: "Wisekey",
	1380926275: "Fuzhou Rockchip",
}

func (id TCGVendorID) String() string {
	return vendors[id]
}

// Helper things to sanitize the data we are working with

func sanitizeString(s string) string {
	for _, r := range s {
		if !isPrintable(byte(r)) {
			s = strings.ReplaceAll(s, string(r), "")
		}
	}
	return s
}

// Validate all fields is printable string, as the asn1 encoding in step-ca checks this.
// Taken from go/golang/crypto
func isPrintable(b byte) bool {
	return 'a' <= b && b <= 'z' ||
		'A' <= b && b <= 'Z' ||
		'0' <= b && b <= '9' ||
		'\'' <= b && b <= ')' ||
		'+' <= b && b <= '/' ||
		b == ' ' ||
		b == ':' ||
		b == '=' ||
		b == '?'
}
