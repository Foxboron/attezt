package inventory

import (
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
