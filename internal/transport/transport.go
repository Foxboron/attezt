package transport

import (
	"io"
	"testing"

	"github.com/foxboron/attezt/internal/testutils"
	ssim "github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpmutil"
)

// TPM represents a connection to a TPM simulator.
type TPM struct {
	transport io.ReadWriteCloser
}

// Send implements the TPM interface.
func (t *TPM) Send(input []byte) ([]byte, error) {
	return tpmutil.RunCommandRaw(t.transport, input)
}

// Close implements the TPM interface.
func (t *TPM) Close() error {
	return t.transport.Close()
}

func OpenSimulator() (transport.TPMCloser, error) {
	sim, err := ssim.GetWithFixedSeedInsecure(1234)
	if err != nil {
		return nil, err
	}
	return &TPM{
		transport: sim,
	}, nil
}

func GetTPM() (transport.TPMCloser, error) {
	if testing.Testing() {
		rwc, err := OpenSimulator()
		if err != nil {
			return nil, err
		}
		// Ensure we set an EK Cert if we use the simulator
		if err := testutils.SetEKCertificate(rwc); err != nil {
			return nil, err
		}
		return rwc, err
	}
	rwc, err := linuxtpm.Open("/dev/tpmrm0")
	if err != nil {
		return nil, err
	}
	return rwc, nil
}
