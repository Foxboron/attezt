package truststore

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

// TrustStore implements the list of trusted root and intermediate certificates.
type TrustStore struct {
	remoteFetch   bool
	intermediates *x509.CertPool
	roots         *x509.CertPool
}

func NewTrustStore(remote bool) *TrustStore {
	return &TrustStore{
		remoteFetch:   remote,
		roots:         x509.NewCertPool(),
		intermediates: x509.NewCertPool(),
	}
}

// NewTrustStoreFromDirectory preloads a trust store with certificates from a directory
func NewTrustStoreFromDirectory(dir fs.FS) (*TrustStore, error) {
	// If we are only looking at the directory we ignore fetching remote roots
	ts := NewTrustStore(false)
	if err := fs.WalkDir(dir, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type().IsDir() {
			return nil
		}
		if filepath.Ext(d.Name()) != ".cer" {
			return nil
		}
		der, err := fs.ReadFile(dir, path)
		if err != nil {
			return err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		if strings.Contains(path, "RootCA") {
			ts.AddRoot(cert)
		}
		if strings.Contains(path, "IntermediateCA") {
			ts.AddIntermediate(cert)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return ts, nil
}

func (t *TrustStore) AddRoot(cert *x509.Certificate) {
	t.roots.AddCert(cert)
}

func (t *TrustStore) AddIntermediate(cert *x509.Certificate) {
	t.intermediates.AddCert(cert)
}

// Clone returns a clone of the trust store
func (t *TrustStore) Clone() *TrustStore {
	return &TrustStore{
		roots:         t.roots.Clone(),
		intermediates: t.intermediates.Clone(),
	}
}

func (t *TrustStore) verify(cert *x509.Certificate) ([][]*x509.Certificate, error) {
	// Clean away the invalid SAN extension
	oidExtensionSubjectAltName := []int{2, 5, 29, 17}
	var exts []asn1.ObjectIdentifier
	for _, ext := range cert.UnhandledCriticalExtensions {
		if ext.Equal(oidExtensionSubjectAltName) {
			continue
		}
		exts = append(exts, ext)
	}
	cert.UnhandledCriticalExtensions = exts

	return cert.Verify(x509.VerifyOptions{
		Roots:         t.roots,
		Intermediates: t.intermediates,
		CurrentTime:   time.Now().Truncate(time.Second),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
}

func (t *TrustStore) VerifyCertificate(cert *x509.Certificate) ([][]*x509.Certificate, error) {
	if t.remoteFetch {
		return t.VerifyWithIssuingCert(cert)
	}
	return t.verify(cert)
}

func (t *TrustStore) VerifyWithIssuingCert(cert *x509.Certificate) ([][]*x509.Certificate, error) {
	// TODO: Are we only fetching CA roots here?
	if len(cert.IssuingCertificateURL) == 0 {
		return nil, fmt.Errorf("endorsement Certificate does not have issuing url for root CA")
	}

	// TODO: Add context here
	rsp, err := http.Get(cert.IssuingCertificateURL[0])
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(rsp.Body)
	if err != nil {
		return nil, err
	}

	rootCert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, err
	}

	// Clone the truststore so we don't pollute the state
	ts := t.Clone()
	ts.AddRoot(rootCert)

	return ts.verify(cert)
}
