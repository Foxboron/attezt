package attest

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

func Test_getEKCert(t *testing.T) {
	rwc, err := linuxtpm.Open("/dev/tpmrm0")
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
			_, gotErr := getEKCert(rwc, tpm2.TPMAlgRSA)
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
