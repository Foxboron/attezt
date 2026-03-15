package agent

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/foxboron/attezt/internal/agent/devatteztagent"
	"github.com/foxboron/attezt/internal/attest"
	"github.com/google/go-tpm/tpm2"
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
	cert, err := attest.GetEKCert(a.agent.rwc, tpm2.TPMAlgRSA)
	if err != nil {
		log.Println("could not read endorsment certificate")
		log.Println(err)
		return c.ReplyError(ctx, "dev.attezt.Agent.Error", nil)
	}
	ret.Ek = fmt.Sprintf("%x", attest.HashPub(cert.PublicKey))
	ret.Enrolled = a.agent.Enrolled()
	if a.agent.Enrolled() {
		ret.AcmeServer = a.agent.config.AcmeServer
		ret.AttestationServer = a.agent.config.AttestationServer
	}

	return c.ReplyGetStatus(ctx, ret)
}

func (a *AgentVarlinkHandler) EnrollDevice(ctx context.Context, c devatteztagent.VarlinkCall, e devatteztagent.Enrollment) error {
	log.Println("called enrolldevice")
	u, _ := url.JoinPath(e.AttestationCA, "attest")
	resp, err := http.Get(u)
	if err != nil {
		log.Println("could not reach attesation ca")
		log.Println(err)
		return c.ReplyError(ctx, "dev.attezt.Agent.Error", nil)
	}
	resp.Body.Close()

	u, _ = url.JoinPath(e.AcmeServer, "directory")
	resp, err = http.Get(u)
	if err != nil {
		log.Println("could not reach acme ca")
		log.Println(err)
		return c.ReplyError(ctx, "dev.attezt.Agent.Error", nil)
	}
	resp.Body.Close()

	a.agent.SetConfig(NewAgentConfig(e.AcmeServer, e.AttestationCA))
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
	if !a.agent.Enrolled() {
		return c.ReplyGetCertificate(ctx, ret)
	}
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
