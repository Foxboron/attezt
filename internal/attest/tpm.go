package attest

import (
	"crypto"
	"crypto/x509"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

var (
	ECCSRK_H2_Template = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			Restricted:          true,
			Decrypt:             true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
			},
		),
	}
	ECCSAK_H2_Template = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			Restricted:          true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
				Y: tpm2.TPM2BECCParameter{
					Buffer: make([]byte, 0),
				},
			},
		),
	}

	RSAAKTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			Restricted:          true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: make([]byte, 256),
			},
		),
	}
)

func GetAK(rwc transport.TPMCloser) (*tpm2.NamedHandle, *tpm2.CreatePrimaryResponse, error) {
	akRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(RSAAKTemplate),
	}.Execute(rwc)
	if err != nil {
		return nil, nil, err
	}
	return &tpm2.NamedHandle{
		Handle: akRsp.ObjectHandle,
		Name:   akRsp.Name,
	}, akRsp, nil
}

func GetAKWithHandel(rwc transport.TPMCloser, handel *tpm2.NamedHandle) (*tpm2.NamedHandle, *tpm2.CreateLoadedResponse, error) {
	akRsp, err := tpm2.CreateLoaded{
		ParentHandle: handel,
		InPublic:     tpm2.New2BTemplate(&RSAAKTemplate),
	}.Execute(rwc)
	if err != nil {
		return nil, nil, err
	}
	return &tpm2.NamedHandle{
		Handle: akRsp.ObjectHandle,
		Name:   akRsp.Name,
	}, akRsp, nil
}

func GetEK(rwc transport.TPMCloser) (*tpm2.NamedHandle, *tpm2.TPMTPublic, error) {
	createRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
		// InPublic: tpm2.New2B(tpm2.ECCEKTemplate),
	}.Execute(rwc)
	if err != nil {
		return nil, nil, err
	}
	tpublic, err := createRsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, err
	}
	return &tpm2.NamedHandle{
		Handle: createRsp.ObjectHandle,
		Name:   createRsp.Name,
	}, tpublic, err
}

func ekPolicy(t transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
	cmd := tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		PolicySession: handle,
		NonceTPM:      nonceTPM,
	}
	_, err := cmd.Execute(t)
	return err
}

func nvReadEX(rwc transport.TPM, index tpm2.TPMHandle) ([]byte, error) {
	// From: https://github.com/salrashid123/tpm2/blob/b3b54cc8c48bb9296212291675a929128b4265c1/ek_cert_key/main.go
	readPubRsp, err := tpm2.NVReadPublic{
		NVIndex: index,
	}.Execute(rwc)
	if err != nil {
		return nil, err
	}
	c, err := readPubRsp.NVPublic.Contents()
	if err != nil {
		return nil, err
	}

	getCmd := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTNVBufferMax),
		PropertyCount: 1,
	}
	getRsp, err := getCmd.Execute(rwc)
	if err != nil {
		return nil, err
	}

	tp, err := getRsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return nil, err
	}

	blockSize := int(tp.TPMProperty[0].Value)

	outBuff := make([]byte, 0, int(c.DataSize))
	for len(outBuff) < int(c.DataSize) {
		readSize := blockSize
		if readSize > (int(c.DataSize) - len(outBuff)) {
			readSize = int(c.DataSize) - len(outBuff)
		}

		readRsp, err := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Name:   tpm2.HandleName(tpm2.TPMRHOwner),
				Auth:   tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth([]byte{})),
			},
			NVIndex: tpm2.NamedHandle{
				Handle: index,
				Name:   readPubRsp.NVName,
			},
			Size:   uint16(readSize),
			Offset: uint16(len(outBuff)),
		}.Execute(rwc)
		if err != nil {
			return nil, err
		}
		data := readRsp.Data.Buffer
		outBuff = append(outBuff, data...)
	}
	return outBuff, nil
}

func GetEKHandle(rwc transport.TPMCloser) (crypto.PublicKey, error) {
	rsp, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(0x81010001),
	}.Execute(rwc)
	if err != nil {
		return nil, err
	}
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, err
	}
	return tpm2.Pub(*pub)
}

func getEKCert(rwc transport.TPMCloser) (*x509.Certificate, error) {
	// TODO: Add ECC as well
	// TODO: Smallstep does a lookup for all endorsement certs
	// We should consider the same, but only pass cert from NV until further notice
	// But check this if we somehow fail any checks
	// ECC
	// bb, err := nvReadEX(rwc, tpm2.TPMHandle(0x01C0000A))
	bb, err := nvReadEX(rwc, tpm2.TPMHandle(0x01C00002))
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(bb)
}

func GetSRKPrimary(rwc transport.TPMCloser) (*tpm2.NamedHandle, *tpm2.TPMTPublic, error) {
	handel := tpm2.TPMHandle(0x81000001)
	rsp, err := tpm2.ReadPublic{
		ObjectHandle: handel,
	}.Execute(rwc)
	if err != nil {
		return nil, nil, err
	}
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, nil, err
	}
	return &tpm2.NamedHandle{
		Handle: handel,
		Name:   rsp.Name,
	}, pub, nil
}
