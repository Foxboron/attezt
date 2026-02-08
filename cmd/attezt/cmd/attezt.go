package attezt

import (
	"context"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/foxboron/attezt/internal/certs"
	tt "github.com/foxboron/attezt/internal/transport"
	"github.com/foxboron/attezt/internal/varlink"
	"github.com/foxboron/attezt/internal/varlink/devattezt"
)

// ca flags
var (
	certificateCmd = flag.NewFlagSet("certificate", flag.ExitOnError)
)

func CertificateMain(args []string) {
	certificateCmd.Usage = func() {
		fmt.Printf(`Usage:
	ak	Request an Attestation Key (AK)
`)
	}
	if len(args) == 0 {
		certificateCmd.Usage()
		os.Exit(0)
	}
	certificateCmd.Parse(args)
	switch args[0] {
	case "ak":
		log.Println("Requesting an attestation key...")

		rwc, err := tt.GetTPM()
		if err != nil {
			log.Fatal(err)
		}
		defer rwc.Close()

		c := NewClient("http://127.0.0.1:8080")
		certs, err := c.GetAttestWithAlg(rwc, TPMALG)
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
		os.Exit(0)
	}
}

// ca flags
var (
	caCmd  = flag.NewFlagSet("ca", flag.ExitOnError)
	vsflag = caCmd.String("varlink", "/run/attezt/dev.attezt.Server", "address for varlink (default: /run/attezt/dev.attezt.Server)")
)

func CAMain(args []string) {
	caCmd.Usage = func() {
		fmt.Printf(`Usage:
	create	Create an CA certificate chain
`)
	}
	if len(args) == 0 {
		caCmd.Usage()
		os.Exit(0)
	}
	caCmd.Parse(args)

	switch args[0] {
	case "list":

		ctx := context.Background()
		conn, err := varlink.NewVarlinkClient(*vsflag)
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()

		devs, err := devattezt.ListDevices().Call(ctx, conn)
		if err != nil {
			log.Fatal(err)
		}
		for _, d := range devs {
			fmt.Println(d.Ekcert)
		}
	case "lookup":
		ctx := context.Background()
		conn, err := varlink.NewVarlinkClient(*vsflag)
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()

		if len(args) != 2 {
			caCmd.Usage()
			os.Exit(0)
		}
		dev, err := devattezt.GetDevice().Call(ctx, conn, args[1])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(dev.Ekcert)
	case "enroll":
		ctx := context.Background()
		conn, err := varlink.NewVarlinkClient(*vsflag)
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()
		if len(args) != 2 {
			caCmd.Usage()
			os.Exit(0)
		}
		if err := devattezt.Enroll().Call(ctx, conn, args[1]); err != nil {
			log.Fatal(err)
		}
	case "remove":
		ctx := context.Background()
		conn, err := varlink.NewVarlinkClient(*vsflag)
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()
		if len(args) != 2 {
			caCmd.Usage()
			os.Exit(0)
		}
		if err := devattezt.Remove().Call(ctx, conn, args[1]); err != nil {
			log.Fatal(err)
		}
	case "create":
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
		os.Exit(0)
	}
}

// Main flags
var (
	rootCmd = flag.NewFlagSet("attezt", flag.ExitOnError)
)

func Main() {
	rootCmd.Usage = func() {
		fmt.Printf(`Usage:
	ca		Manage the certificate authority
	certificate	Manage device certificates
`)
	}
	rootCmd.Parse(os.Args[1:])
	if len(os.Args) < 2 {
		rootCmd.Usage()
		os.Exit(0)
	}

	switch os.Args[1] {
	case "ca":
		CAMain(os.Args[2:])
	case "certificate":
		CertificateMain(os.Args[2:])
	default:
		rootCmd.Usage()
	}
}
