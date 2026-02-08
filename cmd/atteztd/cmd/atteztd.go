package atteztd

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/foxboron/attezt/internal/certs"
	"github.com/foxboron/attezt/internal/inventory"
	"github.com/foxboron/attezt/internal/server"
	"github.com/foxboron/attezt/internal/truststore"
	"github.com/foxboron/attezt/internal/varlink"
)

const usage = `Usage:`

// Flags for rootcmd
var (
	backend   = flag.String("backend", "default", "inventory backend to use (default: sqlite)")
	certstore = flag.String("certstore", "", "directory with pinned certificate roots (default: empty)")
	vsflag    = flag.String("varlink", "/run/attezt/dev.attezt.Server", "address for varlink (default: /run/attezt/dev.attezt.Server)")
)

func run(ctx context.Context, ts *truststore.TrustStore, backend inventory.Inventory) error {
	chain, err := certs.ReadChainFromDir(".")
	if err != nil {
		return fmt.Errorf("failed reading certs: %v", err)
	}
	as := server.NewTPMAttestServer(chain, ts, backend)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: as.Handlers(),
	}

	vs, err := varlink.NewVarlinkServer(*vsflag, backend)
	if err != nil {
		return err
	}
	defer vs.Shutdown()

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
	log.Printf("Varlink socket on %s", *vsflag)
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
		log.Fatal(err)
	}

	if err := backend.Init(nil); err != nil {
		log.Fatal(err)
	}

	// Initialize the truststore
	var ts *truststore.TrustStore
	if *certstore != "" {
		path, err := filepath.Abs(*certstore)
		if err != nil {
			log.Fatal(err)
		}
		ts, err = truststore.NewTrustStoreFromDirectory(os.DirFS(path))
		if err != nil {
			log.Fatal(err)
		}
	} else {
		// Fetch remote issuing certificates as we have no cert store
		ts = truststore.NewTrustStore(true)
	}

	ctx := context.Background()
	if err := run(ctx, ts, backend); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
