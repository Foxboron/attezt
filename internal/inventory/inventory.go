package inventory

import (
	"fmt"

	"github.com/foxboron/attezt/internal/attest"
	"github.com/foxboron/attezt/internal/inventory/sqlite"
)

type Inventory interface {
	Lookup(*attest.Attestation) (bool, error)
	Enroll() error
	Remove() error
}

var Inventories = map[string]Inventory{
	"default": sqlite.NewSqlite(),
	"sqlite":  sqlite.NewSqlite(),
}

func GetBackend(s string) (Inventory, error) {
	i, ok := Inventories[s]
	if !ok {
		return nil, fmt.Errorf("%s is not a supported backend", s)
	}
	return i, nil
}
