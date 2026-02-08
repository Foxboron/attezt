package varlink

import (
	"context"
	"fmt"
	"log"

	"github.com/foxboron/attezt/internal/inventory"
	"github.com/varlink/go/varlink"
)

// Create the bindings
//go:generate go tool varlink-go-interface-generator devattezt/dev.attezt.varlink

func NewVarlinkServer(address string, backend inventory.Inventory) (*varlink.Service, error) {
	service, err := varlink.NewService(
		"attezt",
		"attezt",
		"1",
		"https://github.com/foxboron/attezt",
	)
	if err != nil {
		return nil, err
	}

	host := New(backend)
	if err := service.RegisterInterface(host); err != nil {
		return nil, fmt.Errorf("failed to register varlink interface: %v", err)
	}

	addressURI := "unix:" + address

	go func() {
		if err := service.Listen(context.Background(), addressURI, 0); err != nil {
			log.Fatal(err)
		}
	}()

	return service, nil
}

func NewVarlinkClient(address string) (*varlink.Connection, error) {
	// TODO: We should allow other addresses
	addressURI := "unix:" + address
	conn, err := varlink.NewConnection(context.Background(), addressURI)
	if err != nil {
		return nil, fmt.Errorf("failed connecting to varlink: %v", err)
	}
	return conn, nil
}
