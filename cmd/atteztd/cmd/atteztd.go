package atteztd

import (
	"context"
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
	"github.com/urfave/cli/v3"
	"go.step.sm/crypto/kms"
	"go.step.sm/crypto/kms/apiv1"
	_ "go.step.sm/crypto/kms/tpmkms"
)

var cmd = &cli.Command{
	Name:    "atteztd",
	Version: "v0.0.0",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "root", Value: "root_ca.pem", Usage: "root CA certificate PEM file"},
		&cli.StringFlag{Name: "intermediate", Value: "intermediate_ca.pem", Usage: "intermediate CA certificate PEM file"},
		&cli.StringFlag{Name: "key", Value: "intermediate_ca.key", Usage: "intermediate private key PEM file or KMS key URI"},
		&cli.StringFlag{Name: "kms", Usage: "optional KMS URI (supports tpmkms)"},
		&cli.StringFlag{
			Name:  "varlink",
			Value: "/run/attezt/dev.attezt.Server",
			Usage: "address for varlink",
		},
		&cli.StringFlag{
			Name:  "backend",
			Value: "default",
			Usage: "inventory backend to use",
		},
		&cli.StringFlag{
			Name:  "certstore",
			Value: "",
			Usage: "directory with pinned certificate roots",
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		backend, err := inventory.GetBackend(cmd.String("backend"))
		if err != nil {
			log.Fatal(err)
		}

		if err := backend.Init(nil); err != nil {
			log.Fatal(err)
		}

		// Initialize the truststore
		var ts *truststore.TrustStore
		certstore := cmd.String("certstore")
		if certstore != "" {
			path, err := filepath.Abs(certstore)
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

		keyManager, err := kms.New(ctx, apiv1.Options{URI: cmd.String("kms")})
		if err != nil {
			return err
		}
		defer keyManager.Close()
		signer, err := keyManager.CreateSigner(&apiv1.CreateSignerRequest{SigningKey: cmd.String("key")})
		if err != nil {
			return fmt.Errorf("open intermediate signing key: %w", err)
		}
		chain, err := certs.ReadChainWithSigner(cmd.String("root"), cmd.String("intermediate"), signer)
		if err != nil {
			return err
		}
		return run(ctx, cmd.String("varlink"), chain, ts, backend)
	},
}

func run(ctx context.Context, vsaddr string, chain *certs.CertificateChain, ts *truststore.TrustStore, backend inventory.Inventory) error {
	as := server.NewTPMAttestServer(chain, ts, backend)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: as.Handlers(),
	}

	vs, err := varlink.NewVarlinkServer(vsaddr, backend)
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
	log.Printf("Varlink socket on %s", vsaddr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("HTTP server ListenAndServe: %v", err)
	}
	<-idleConnsClosed
	return nil
}

func Main() {
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
