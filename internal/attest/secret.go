package attest

import (
	"encoding/json"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// AttestationResponse is the serialized Credential Activation
type AttestationResponse struct {
	Credential tpm2.TPM2BIDObject        `json:"credential"`
	Secret     tpm2.TPM2BEncryptedSecret `json:"secret"`
}

func (a *AttestationResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Credential []byte `json:"credential"`
		Secret     []byte `json:"secret"`
	}{
		Credential: tpm2.Marshal(a.Credential),
		Secret:     tpm2.Marshal(a.Secret),
	})
}

func (a *AttestationResponse) UnmarshalJSON(b []byte) error {
	var obj struct {
		Credential []byte `json:"credential"`
		Secret     []byte `json:"secret"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return fmt.Errorf("failed ap unmarshal: %v", err)
	}
	cred2b, err := tpm2.Unmarshal[tpm2.TPM2BIDObject](obj.Credential)
	if err != nil {
		return fmt.Errorf("failed to unmarshal credential: %v", err)
	}

	sec2b, err := tpm2.Unmarshal[tpm2.TPM2BEncryptedSecret](obj.Secret)
	if err != nil {
		return fmt.Errorf("failed to unmarshal secret: %v", err)
	}

	a.Credential = *cred2b
	a.Secret = *sec2b
	return nil
}

func NewAttestationResponse() *AttestationResponse {
	return &AttestationResponse{}
}

type SecretRequest struct {
	Secret []byte `json:"secret"` // decrypted secret
}

type SecretResponse struct {
	CertificateChain [][]byte `json:"chain"`
}
