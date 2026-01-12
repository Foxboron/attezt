package main_tests

import (
	"testing"

	attezt "github.com/foxboron/attezt/cmd/attezt/cmd"
	atteztd "github.com/foxboron/attezt/cmd/atteztd/cmd"
	"github.com/google/go-tpm/tpm2"
	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"attezt": func() {
			// This is faster for tests
			attezt.TPMALG = tpm2.TPMAlgECC
			attezt.Main()
		},
		"atteztd": func() {
			atteztd.Main()
		},
	})
}

func TestPlugin(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata",
		Setup: func(e *testscript.Env) error {
			// e.Vars = append(e.Vars, "_AGE_TPM_SIMULATOR=1")
			return nil
		},
	})
}
