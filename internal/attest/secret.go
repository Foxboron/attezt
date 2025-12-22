package attest

// AttestationResponse is the serialized Credential Activation
type AttestationResponse struct {
	Credential []byte `json:"credential"`
	Secret     []byte `json:"secret"`
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
