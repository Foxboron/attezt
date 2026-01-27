package atteztd

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"

	"github.com/foxboron/attezt/internal/certs"
	"github.com/foxboron/attezt/internal/inventory"
	"github.com/foxboron/attezt/internal/server"
)

const usage = `Usage:`

// Flags for rootcmd
var (
	backend = flag.String("backend", "default", "inventory backend to use (default: sqlite)")
)

func run(ctx context.Context, backend inventory.Inventory) error {
	chain, err := certs.ReadChainFromDir(".")
	if err != nil {
		return fmt.Errorf("failed reading certs: %v", err)
	}
	as := server.NewTPMAttestServer(chain, backend)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: as.Handlers(),
	}

	// TODO: This can probably be simpler?
	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("HTTP server Shutdown: %v", err)
		}
		close(idleConnsClosed)
	}()

	log.Printf("HTTP server listening on :8080")
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("HTTP server ListenAndServe: %v", err)
	}
	<-idleConnsClosed
	return nil
}

func Main() {
	flag.Usage = func() {
		fmt.Println(usage)
	}
	flag.Parse()

	backend, err := inventory.GetBackend(*backend)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}

	ctx := context.Background()
	if err := run(ctx, backend); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
