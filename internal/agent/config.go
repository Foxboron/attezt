package agent

import (
	"encoding/json"
	"io"
)

type AgentConfig struct {
	AcmeServer        string
	AttestationServer string
}

func (a *AgentConfig) Save(w io.Writer) error {
	return json.NewEncoder(w).Encode(a)
}

func NewAgentConfig(acme, attestation string) *AgentConfig {
	return &AgentConfig{
		AcmeServer:        acme,
		AttestationServer: attestation,
	}
}

func ReadAgentConfig(r io.Reader) (*AgentConfig, error) {
	var a AgentConfig
	err := json.NewDecoder(r).Decode(&a)
	return &a, err
}
