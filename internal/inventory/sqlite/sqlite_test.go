package sqlite_test

import (
	"path"
	"testing"

	"github.com/foxboron/attezt/internal/attest"
	"github.com/foxboron/attezt/internal/inventory/sqlite"
	"github.com/foxboron/attezt/internal/transport"
	"github.com/google/go-tpm/tpm2"
)

func TestSqlite(t *testing.T) {
	rwc, err := transport.GetTPM()
	if err != nil {
		t.Fatal(err)
	}
	defer rwc.Close()

	a, err := attest.NewAttestationWithAlg(rwc, tpm2.TPMAlgECC)
	if err != nil {
		t.Fatal(err)
	}

	db := sqlite.NewSqlite()
	if err := db.Init(map[string]any{
		"path": path.Join(t.TempDir(), "sqlite.db"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Enroll(map[string]any{
		"ekcert": a.EKPubHash(),
	}); err != nil {
		t.Fatal(err)
	}

	ok, err := db.Lookup(a)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("failed finding device")
	}
	if err := db.Remove(map[string]any{
		"ekcert": a.EKPubHash(),
	}); err != nil {
		t.Fatal(err)
	}
	ok, err = db.Lookup(a)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatalf("device should have been deleted")
	}
}
