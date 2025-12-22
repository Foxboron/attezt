package attest

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-tpm/tpm2"
)

// WARNING: All of the code below is just taken from go-tpm and just written with a bunch of assumptions.
// TODO: Get the remote end to give us a TPMTPublic so we can stop this.

type RSAPublicEncapKey struct {
	rsaPub *rsa.PublicKey
}

var _ tpm2.LabeledEncapsulationKey = &RSAPublicEncapKey{}

func (pub *RSAPublicEncapKey) Encapsulate(random io.Reader, label string) (secret []byte, ciphertext []byte, err error) {
	nameHash, err := pub.NameAlg().Hash()
	if err != nil {
		return nil, nil, err
	}
	secret = make([]byte, nameHash.Size())
	n, err := random.Read(secret)
	if err != nil {
		return nil, nil, err
	}
	if n != len(secret) {
		return nil, nil, fmt.Errorf("only read %d bytes but %d were needed", n, len(secret))
	}

	ciphertext, err = pub.encapsulateDerandomized(random, secret, label)
	if err != nil {
		return nil, nil, err
	}
	return secret, ciphertext, err
}

func (pub *RSAPublicEncapKey) encapsulateDerandomized(oaepSaltReader io.Reader, secret []byte, label string) (ciphertext []byte, err error) {
	// Ensure label is null-terminated.
	if !strings.HasSuffix(label, "\x00") {
		label = label + "\x00"
	}

	nameHash, err := pub.NameAlg().Hash()
	if err != nil {
		return nil, err
	}

	if len(secret) != nameHash.Size() {
		return nil, fmt.Errorf("secret was only %d bytes but %d were needed", len(secret), nameHash.Size())
	}

	ciphertext, err = rsa.EncryptOAEP(nameHash.New(), oaepSaltReader, pub.rsaPub, secret, []byte(label))
	if err != nil {
		return nil, err
	}
	return ciphertext, err
}

// NameAlg implements LabeledEncapsulationKey.
func (pub *RSAPublicEncapKey) NameAlg() tpm2.TPMAlgID {
	return tpm2.TPMAlgSHA256
}

// SymmetricParameters implements LabeledEncapsulationkey.
func (pub *RSAPublicEncapKey) SymmetricParameters() *tpm2.TPMTSymDefObject {
	// TODO: This is all fake
	return &tpm2.TPMTSymDefObject{
		Algorithm: tpm2.TPMAlgAES,
		KeyBits: tpm2.NewTPMUSymKeyBits(
			tpm2.TPMAlgAES,
			tpm2.TPMKeyBits(128),
		),
		Mode: tpm2.NewTPMUSymMode(
			tpm2.TPMAlgAES,
			tpm2.TPMAlgCFB,
		),
	}
}

type ECDHPublicEncapKey struct {
	eccPub *ecdh.PublicKey
}

var _ tpm2.LabeledEncapsulationKey = &ECDHPublicEncapKey{}

func (pub *ECDHPublicEncapKey) Encapsulate(random io.Reader, label string) (secret []byte, ciphertext []byte, err error) {
	ephemeralPriv, err := pub.eccPub.Curve().GenerateKey(random)
	if err != nil {
		return nil, nil, err
	}
	return pub.encapsulateDerandomized(ephemeralPriv, label)
}

// getXY gets the big-endian X/Y coordinates as full-length buffers.
func getXY(pub *ecdh.PublicKey) ([]byte, []byte, error) {
	// Check and strip the leading 0x04 byte, which indicates an uncompressed ECC point.
	rawPub := pub.Bytes()
	if len(rawPub) == 0 || rawPub[0] != 0x04 {
		return nil, nil, fmt.Errorf("could not decode %x as an uncompressed point", rawPub)
	}
	rawPub = rawPub[1:]
	return rawPub[:len(rawPub)/2], rawPub[len(rawPub)/2:], nil
}

// borrowed from go-tpm
func (pub *ECDHPublicEncapKey) encapsulateDerandomized(ephPrivate *ecdh.PrivateKey, label string) (secret []byte, ciphertext []byte, err error) {
	nameHash, err := pub.NameAlg().Hash()
	if err != nil {
		return nil, nil, err
	}
	pubX, _, err := getXY(pub.eccPub)
	if err != nil {
		return nil, nil, err
	}
	ephX, ephY, err := getXY(ephPrivate.PublicKey())
	if err != nil {
		return nil, nil, err
	}
	z, err := ephPrivate.ECDH(pub.eccPub)
	if err != nil {
		return nil, nil, err
	}
	secret = tpm2.KDFe(nameHash, z, label, ephX, pubX, nameHash.Size()*8)
	ciphertext = tpm2.Marshal(tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{
			Buffer: ephX,
		},
		Y: tpm2.TPM2BECCParameter{
			Buffer: ephY,
		},
	})
	return secret, ciphertext, nil
}

// NameAlg implements LabeledEncapsulationKey.
func (pub *ECDHPublicEncapKey) NameAlg() tpm2.TPMAlgID {
	// YOLO
	return tpm2.TPMAlgSHA256
}

// SymmetricParameters implements LabeledEncapsulationkey.
func (pub *ECDHPublicEncapKey) SymmetricParameters() *tpm2.TPMTSymDefObject {
	// TODO: This is all fake
	return &tpm2.TPMTSymDefObject{
		Algorithm: tpm2.TPMAlgAES,
		KeyBits: tpm2.NewTPMUSymKeyBits(
			tpm2.TPMAlgAES,
			tpm2.TPMKeyBits(128),
		),
		Mode: tpm2.NewTPMUSymMode(
			tpm2.TPMAlgAES,
			tpm2.TPMAlgCFB,
		),
	}
}

func NewCryptoPublicEncapKey(pub crypto.PublicKey) tpm2.LabeledEncapsulationKey {
	var ecdhPubKey *ecdh.PublicKey
	var err error

	switch pk := pub.(type) {
	case *ecdsa.PublicKey:
		// For NIST curves (P256, P384, P521), use the ECDH() method
		ecdhPubKey, err = pk.ECDH()
		if err != nil {
			panic(fmt.Sprintf("failed to convert ECDSA public key to ECDH public key: %v", err))
		}
		return &ECDHPublicEncapKey{ecdhPubKey}
	case *ecdh.PublicKey:
		return &ECDHPublicEncapKey{pk}
	case *rsa.PublicKey:
		return &RSAPublicEncapKey{pk}
	default:
		panic(fmt.Sprintf("unsupported public key type: %T", pub))
	}
}
