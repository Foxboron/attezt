package inventory

import (
	"fmt"

	"github.com/foxboron/attezt/internal/attest"
	"github.com/foxboron/attezt/internal/inventory/sqlite"
)

type Inventory interface {
	// Lookup implements the function checking the inventory for a matching device that meets the attestation.
	Lookup(attestation *attest.Attestation) (bool, error)

	// GetEntry finds the database object by a given key.
	GetEntry(key string) (any, error)

	// Init initializes the inventory.
	Init(config map[string]any) error

	// Enroll adds a new device into the inventory.
	Enroll(data map[string]any) error

	// Remove removes a device from the inventory.
	Remove(data map[string]any) error

	// Remove removes a device from the inventory.
	List() (any, error)
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
