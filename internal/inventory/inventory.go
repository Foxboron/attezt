package inventory

import (
	"fmt"

	"github.com/foxboron/attezt/internal/attest"
	"github.com/foxboron/attezt/internal/inventory/sqlite"
)

type Inventory interface {
	Lookup(attestation *attest.Attestation) (bool, error)
	Init(config map[string]any) error
	Enroll(data map[string]any) error
	Remove(data map[string]any) error
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
