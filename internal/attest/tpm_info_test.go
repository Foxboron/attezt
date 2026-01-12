package attest_test

import (
	"fmt"
	"testing"

	"github.com/foxboron/attezt/internal/attest"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func TestNewTPMInfo(t *testing.T) {
	rwc, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer rwc.Close()
	tpminfo, err := attest.NewTPMInfo(rwc)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(tpminfo.Model)
}
