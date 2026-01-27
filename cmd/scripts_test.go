package main_tests

import (
	"log"
	"testing"

	attezt "github.com/foxboron/attezt/cmd/attezt/cmd"
	atteztd "github.com/foxboron/attezt/cmd/atteztd/cmd"
	"github.com/foxboron/attezt/internal/attest"
	"github.com/foxboron/attezt/internal/inventory/sqlite"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
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
		"enrollekcert": func() {
			rwc, err := linuxtpm.Open("/dev/tpmrm0")
			if err != nil {
				log.Fatal(err)
			}
			defer rwc.Close()

			a, err := attest.NewAttestationWithAlg(rwc, tpm2.TPMAlgECC)
			if err != nil {
				log.Fatal(err)
			}

			db := sqlite.NewSqlite()
			if err := db.Init(nil); err != nil {
				log.Fatal(err)
			}
			if err := db.Enroll(map[string]any{
				"ek_cert": a.EKPubHash(),
			}); err != nil {
				log.Fatal(err)
			}
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
