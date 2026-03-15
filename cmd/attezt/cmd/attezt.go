package attezt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"

	aacme "github.com/foxboron/attezt/internal/acme"
	"github.com/foxboron/attezt/internal/agent"
	"github.com/foxboron/attezt/internal/agent/devatteztagent"
	"github.com/foxboron/attezt/internal/attest"
	"github.com/smallstep/certinfo"

	"github.com/foxboron/attezt/internal/certs"
	tt "github.com/foxboron/attezt/internal/transport"
	"github.com/foxboron/attezt/internal/varlink"
	"github.com/foxboron/attezt/internal/varlink/devatteztserver"
	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
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
			{
				Name:  "cert",
				Usage: "create a device certificate",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					log.Println("Requesting an attestation key...")

					rwc, err := tt.GetTPM()
					if err != nil {
						log.Fatal(err)
					}
					defer rwc.Close()

					subject := "framework"
					atteztServer := "http://attezt.local:8080"
					acmeServer := "https://ca.home.arpa/acme/acme-da/directory"

					privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					if err != nil {
						return err
					}

					account := acme.Account{
						TermsOfServiceAgreed: true,
						PrivateKey:           privateKey,
					}

					client := acmez.Client{
						Client: &acme.Client{
							Directory: acmeServer,
						},
					}
					account, err = client.NewAccount(ctx, account)
					if err != nil {
						return err
					}

					t := time.Now()
					tafter := t.Add(24 * time.Hour)
					order := acme.Order{
						Identifiers: []acme.Identifier{{
							Type:  "permanent-identifier",
							Value: subject,
						}},
						NotBefore: &t,
						NotAfter:  &tafter,
					}

					order, err = client.NewOrder(ctx, account, order)
					if err != nil {
						return err
					}

					url := order.Authorizations[0]

					authz, err := client.GetAuthorization(ctx, account, url)
					if err != nil {
						return err
					}

					challenge := authz.Challenges[0]

					TPMALG := tpm2.TPMAlgRSA
					// TPM CHALLENGE RESLOUTION HERE
					c := attest.NewClient(atteztServer)

					// Turn into signer
					akHandle, akrsp, err := attest.GetAK(rwc, TPMALG)
					if err != nil {
						return err
					}
					defer keyfile.FlushHandle(rwc, akHandle)

					s, err := account.Thumbprint()
					if err != nil {
						return err
					}
					data := fmt.Sprintf("%s.%s", challenge.Token, s)
					hashedData := sha256.Sum256([]byte(data))

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

					fmt.Println(att.EKPubHash())
					certs, err := c.GetAttestWithAlg(rwc, att)
					if err != nil {
						log.Fatal(err)
					}

					// Create a new key and attest with AK
					key, _, err := keyfile.NewLoadableKeyWithResponse(rwc, TPMALG, 256, []byte(""))
					if err != nil {
						return err
					}

					keyhandle, parenthandle, err := keyfile.LoadKey(keyfile.NewTPMSession(rwc), key, []byte(nil))
					if err != nil {
						return err
					}

					tkey, err := key.Pubkey.Contents()
					if err != nil {
						return err
					}

					// Certify the creation of it by loading it
					dkattestparams, err := attest.CertifyKey(rwc, *aconf.AKHandle, tpm2.NamedHandle{Handle: keyhandle.Handle, Name: keyhandle.Name}, tkey, hashedData[:])
					if err != nil {
						return err
					}

					// TODO: Cerify should be part of go-tpm-keys
					// Flush before Signer
					// else we'll run out of memory
					keyfile.FlushHandle(rwc, keyhandle)
					keyfile.FlushHandle(rwc, parenthandle)

					payloadBytes, err := aacme.CreateAttestationPayload(certs, aconf.KeyAlg, dkattestparams)
					if err != nil {
						return err
					}
					challenge.Payload = payloadBytes

					csr := &x509.CertificateRequest{
						Subject: pkix.Name{
							CommonName: subject,
						},
					}

					signer, err := key.Signer(rwc, []byte(""), []byte(""))
					if err != nil {
						return err
					}
					csrbytes, err := x509.CreateCertificateRequest(rand.Reader, csr, signer)
					if err != nil {
						return fmt.Errorf("create certificate request: %v", err)
					}

					// STOP TPM

					challenge, err = client.InitiateChallenge(ctx, account, challenge)
					if err != nil {
						return fmt.Errorf("initiating challenge %q: %v", challenge.URL, err)
					}

					order, err = client.FinalizeOrder(ctx, account, order, csrbytes)
					if err != nil {
						return err
					}

					certChains, err := client.GetCertificateChain(ctx, account, order.Certificate)
					if err != nil {
						return fmt.Errorf("downloading certs: %v", err)
					}

					fmt.Println(certChains)
					return nil
				},
			},
		},
	}

	// Main command
	cmd = &cli.Command{
		Name:    "attezt",
		Version: "v0.0.0",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "varlink",
				Value: "/run/attezt/dev.attezt.Agent",
				Usage: "address for varlink agent",
			},
		},
		Commands: []*cli.Command{
			caCmdNew,
			certificateCmdNew,
			{
				Name:  "status",
				Usage: "status of the agent",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					conn, err := agent.NewClient(cmd.String("varlink"))
					if err != nil {
						return err
					}
					defer conn.Close()
					status, err := devatteztagent.GetStatus().Call(ctx, conn)
					if err != nil {
						return err
					}
					fmt.Printf("Status:\n")
					fmt.Printf("    Endorsement Key: %s\n", status.Ek)
					fmt.Printf("  Enrollment status: %t\n", status.Enrolled)

					if !status.Enrolled {
						return nil
					}

					fmt.Printf("        ACME Server: %s\n", status.AcmeServer)
					fmt.Printf(" Attestation Server: %s\n", status.AttestationServer)

					fmt.Println()
					fmt.Printf("Certificate chain:\n")

					// TODO: Format this better
					chain, err := devatteztagent.GetCertificate().Call(ctx, conn)
					if err != nil {
						return err
					}

					certb, err := base64.StdEncoding.DecodeString(chain.Device)
					if err != nil {
						return err
					}
					devcrt, err := x509.ParseCertificate(certb)
					if err != nil {
						return err
					}
					s, err := certinfo.CertificateShortText(devcrt)
					if err != nil {
						return err
					}
					fmt.Print(s)
					certb, err = base64.StdEncoding.DecodeString(chain.Intermediate)
					if err != nil {
						return err
					}
					icert, err := x509.ParseCertificate(certb)
					if err != nil {
						return err
					}
					fmt.Println()
					s, err = certinfo.CertificateShortText(icert)
					if err != nil {
						return err
					}
					fmt.Print(s)

					return nil
				},
			},
			{
				Name: "enroll",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "acme",
						Value: "",
						Usage: "URL to the acme server",
					},
					&cli.StringFlag{
						Name:  "attestation",
						Value: "",
						Usage: "URL to the attestation server",
					},
				},
				Usage: "enroll the agent towards an ACME and attestation server",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					conn, err := agent.NewClient(cmd.String("varlink"))
					if err != nil {
						return err
					}
					defer conn.Close()

					if err = devatteztagent.EnrollDevice().Call(ctx, conn, devatteztagent.Enrollment{
						AcmeServer:    cmd.String("acme"),
						AttestationCA: cmd.String("attestation"),
					}); err != nil {
						return err
					}
					return nil
				},
			},
		},
	}
)

func Main() {
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
