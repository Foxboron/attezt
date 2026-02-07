package attest_test

import (
	"testing"

	"github.com/foxboron/attezt/internal/attest"
	"github.com/foxboron/attezt/internal/testutils"
	"github.com/foxboron/attezt/internal/transport"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func Test_getEKCert(t *testing.T) {
	rwc, err := transport.GetTPM()
	if err != nil {
		t.Fatal(err)
	}
	defer rwc.Close()
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "get RSA",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, gotErr := attest.GetEKCert(rwc, tpm2.TPMAlgECC)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("getEKCert() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("getEKCert() succeeded unexpectedly")
			}
		})
	}
}

func TestSetEKCert(t *testing.T) {
	// Use simulator, we want to test the creation
	rwc, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer rwc.Close()

	if err := testutils.SetEKCertificate(rwc); err != nil {
		t.Fatal(err)
	}

	_, err = attest.GetEKCert(rwc, tpm2.TPMAlgECC)
	if err != nil {
		t.Fatal(err)
	}
}
