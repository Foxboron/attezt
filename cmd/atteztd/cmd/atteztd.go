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
	"github.com/foxboron/attezt/internal/server"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

const usage = `Usage:`

func run(ctx context.Context, rwc transport.TPMCloser) error {
	chain, err := certs.ReadChainFromDir(".")
	if err != nil {
		return fmt.Errorf("failed reading certs: %v", err)
	}
	as := server.NewTPMAttestServer(rwc, chain)

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

	ctx := context.Background()
	rwc, err := linuxtpm.Open("/dev/tpmrm0")
	if err != nil {
		log.Fatal(err)
	}
	defer rwc.Close()

	if err := run(ctx, rwc); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
