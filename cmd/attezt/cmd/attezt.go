package attezt

import (
	"context"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/foxboron/attezt/internal/attest"
	"github.com/foxboron/attezt/internal/certs"
	tt "github.com/foxboron/attezt/internal/transport"
	"github.com/foxboron/attezt/internal/varlink"
	"github.com/foxboron/attezt/internal/varlink/devatteztserver"
	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/urfave/cli/v3"
)

var (
	// attezt ca [...]
	caCmdNew = &cli.Command{
		Name:  "ca",
		Usage: "Create, enroll and manage devices and the certificate authority",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "varlink",
				Value: "/run/attezt/dev.attezt.Server",
				Usage: "address for varlink",
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "create",
				Usage: "create keys for the certificate authority",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					log.Println("Creating certificate authority certificates...")
					chain := certs.NewCA()
					rootKey, _ := os.OpenFile("root_ca.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
					defer rootKey.Close()
					rootCrt, _ := os.OpenFile("root_ca.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
					defer rootCrt.Close()
					interKey, _ := os.OpenFile("intermediate_ca.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
					defer interKey.Close()
					interCrt, _ := os.OpenFile("intermediate_ca.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
					defer interCrt.Close()
					chain.SaveKeys(rootKey, interKey)
					chain.SaveCertificates(rootCrt, interCrt)
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "list all enrolled devices",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					conn, err := varlink.NewVarlinkClient(cmd.String("varlink"))
					if err != nil {
						log.Fatal(err)
					}
					defer conn.Close()
					devs, err := devatteztserver.ListDevices().Call(ctx, conn)
					if err != nil {
						log.Fatal(err)
					}
					for _, d := range devs {
						fmt.Println(d.Ekcert)
					}
					return nil
				},
			},
			{
				Name:  "lookup",
				Usage: "look up an enrolled device",
				Arguments: []cli.Argument{
					&cli.StringArg{
						Name: "device",
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					conn, err := varlink.NewVarlinkClient(cmd.String("varlink"))
					if err != nil {
						log.Fatal(err)
					}
					defer conn.Close()
					dev, err := devatteztserver.GetDevice().Call(ctx, conn, cmd.StringArg("device"))
					if err != nil {
						log.Fatal(err)
					}
					fmt.Println(dev.Ekcert)
					return nil
				},
			},
			{
				Name:  "enroll",
				Usage: "enroll a new device",
				Arguments: []cli.Argument{
					&cli.StringArg{
						Name: "device",
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					conn, err := varlink.NewVarlinkClient(cmd.String("varlink"))
					if err != nil {
						log.Fatal(err)
					}
					defer conn.Close()
					if err := devatteztserver.Enroll().Call(ctx, conn, cmd.StringArg("device")); err != nil {
						log.Fatal(err)
					}
					return nil
				},
			},
			{
				Name:  "remove",
				Usage: "remove a enrolled device",
				Arguments: []cli.Argument{
					&cli.StringArg{
						Name: "device",
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					conn, err := varlink.NewVarlinkClient(cmd.String("varlink"))
					if err != nil {
						log.Fatal(err)
					}
					defer conn.Close()
					if err := devatteztserver.Remove().Call(ctx, conn, cmd.StringArg("device")); err != nil {
						log.Fatal(err)
					}
					return nil
				},
			},
		},
	}

	// attezt certificate [...]
	certificateCmdNew = &cli.Command{
		Name:  "certificate",
		Usage: "Create and handle certificates signed by the attestation ca",
		Commands: []*cli.Command{
			{
				Name:  "ak",
				Usage: "create a signed applicationkey",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					log.Println("Requesting an application key...")

					rwc, err := tt.GetTPM()
					if err != nil {
						log.Fatal(err)
					}
					defer rwc.Close()

					c := attest.NewClient("http://127.0.0.1:8080")

					// Turn into signer
					akHandle, akrsp, err := attest.GetAK(rwc, TPMALG)
					if err != nil {
						return err
					}
					defer keyfile.FlushHandle(rwc, akHandle)

					aconf := &attest.AttestationConfig{
						AKHandle: akHandle,
						AKRsp:    akrsp,
						KeyAlg:   TPMALG,
						Name:     []byte("app-test"),
					}

					att, err := attest.NewAttestation(rwc, aconf)
					if err != nil {
						return err
					}

					certs, err := c.GetAttestWithAlg(rwc, att)
					if err != nil {
						log.Fatal(err)
					}

					file, err := os.Create("device_certificate.pem")
					if err != nil {
						log.Fatalf("failed writing cert chain: %v", err)
					}
					defer file.Close()

					for _, cert := range certs {
						if err := pem.Encode(file, &pem.Block{
							Type:  "CERTIFICATE",
							Bytes: cert.Raw,
						}); err != nil {
							log.Fatalf("failed writing cert")
						}
					}
					return nil
				},
			},
		},
	}

	// Main command
	cmd = &cli.Command{
		Name:    "attezt",
		Version: "v0.0.0",
		Commands: []*cli.Command{
			caCmdNew,
			certificateCmdNew,
		},
	}
)

func Main() {
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
