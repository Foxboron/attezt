package main_tests

import (
	"log"
	"testing"

	attezt "github.com/foxboron/attezt/cmd/attezt/cmd"
	atteztd "github.com/foxboron/attezt/cmd/atteztd/cmd"
	"github.com/foxboron/attezt/internal/attest"
	"github.com/foxboron/attezt/internal/inventory/sqlite"
	tt "github.com/foxboron/attezt/internal/transport"
	keyfile "github.com/foxboron/go-tpm-keyfiles"
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
		"enrollekcert": func() {
			rwc, err := tt.GetTPM()
			if err != nil {
				log.Fatal(err)
			}
			defer rwc.Close()

			akHandle, akrsp, err := attest.GetAK(rwc, tpm2.TPMAlgECC)
			if err != nil {
				log.Fatal(err)
			}
			defer keyfile.FlushHandle(rwc, akHandle)

			aconf := &attest.AttestationConfig{
				AKHandle: akHandle,
				AKRsp:    akrsp,
				KeyAlg:   tpm2.TPMAlgECC,
				Name:     []byte("app-test"),
			}

			a, err := attest.NewAttestation(rwc, aconf)
			if err != nil {
				log.Fatal(err)
			}

			db := sqlite.NewSqlite()
			if err := db.Init(nil); err != nil {
				log.Fatal(err)
			}
			if err := db.Enroll(map[string]any{
				"ekcert": a.EKPubHash(),
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
			return nil
		},
	})
}
