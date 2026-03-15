package agent

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/foxboron/attezt/internal/agent/devatteztagent"
	"github.com/varlink/go/varlink"
)

// Create the bindings
//go:generate go tool varlink-go-interface-generator devatteztagent/dev.attezt.Agent.varlink

func NewVarlinkServer(ctx context.Context, agent *AtteztAgent) (*varlink.Service, error) {
	service, err := varlink.NewService(
		"attezt",
		"Agent",
		"1",
		"https://github.com/foxboron/attezt",
	)
	if err != nil {
		return nil, err
	}

	if err := service.RegisterInterface(NewAgentVarlinkHandler(agent)); err != nil {
		return nil, fmt.Errorf("failed to register varlink interface: %v", err)
	}

	return service, nil
}

type AgentVarlinkHandler struct {
	devatteztagent.VarlinkInterface
	agent *AtteztAgent
}

func NewAgentVarlinkHandler(agent *AtteztAgent) *devatteztagent.VarlinkInterface {
	return devatteztagent.VarlinkNew(&AgentVarlinkHandler{agent: agent})
}

func (a *AgentVarlinkHandler) GetStatus(ctx context.Context, c devatteztagent.VarlinkCall) error {
	log.Println("called getstatus")
	var ret devatteztagent.Status
	ret.Ek = "12345"
	ret.Enrolled = false
	ret.AcmeServer = "test"
	ret.AttestationServer = "test12"
	return c.ReplyGetStatus(ctx, ret)
}

func (a *AgentVarlinkHandler) EnrollDevice(ctx context.Context, c devatteztagent.VarlinkCall) error {
	log.Println("called enrolldevice")
	log.Println("acquiring a new certificate")
	if err := a.agent.ProvisionCertificate(); err != nil {
		log.Println(err)
		return c.ReplyError(ctx, "dev.attezt.Agent.Error", nil)
	}
	log.Println("acquired new certificate")
	log.Println("enrolled device")
	return c.ReplyEnrollDevice(ctx)
}

func (a *AgentVarlinkHandler) GetCertificate(ctx context.Context, c devatteztagent.VarlinkCall) error {
	log.Println("called getcertificate")
	var ret devatteztagent.CertificateChain
	device, intermediate := a.agent.GetCertificate()
	ret.Device = base64.StdEncoding.EncodeToString(device.Raw)
	ret.Intermediate = base64.StdEncoding.EncodeToString(intermediate.Raw)
	return c.ReplyGetCertificate(ctx, ret)
}

func (a *AgentVarlinkHandler) RenewCertificate(ctx context.Context, c devatteztagent.VarlinkCall) error {
	log.Println("called renew")
	if err := a.agent.ProvisionCertificate(); err != nil {
		return c.ReplyError(ctx, "dev.attezt.Agent.Error", nil)
	}
	return c.ReplyRenewCertificate(ctx)
}

func NewClient(address string) (*varlink.Connection, error) {
	// TODO: We should allow other addresses
	addressURI := "unix:" + address
	conn, err := varlink.NewConnection(context.Background(), addressURI)
	if err != nil {
		return nil, fmt.Errorf("failed connecting to varlink: %v", err)
	}
	return conn, nil
}
