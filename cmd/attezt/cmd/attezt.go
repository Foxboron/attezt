package attezt

import (
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/foxboron/attezt/internal/certs"
	"github.com/foxboron/attezt/internal/inventory"
	tt "github.com/foxboron/attezt/internal/transport"
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
	caCmd = flag.NewFlagSet("ca", flag.ExitOnError)
)

func CAMain(args []string, backend inventory.Inventory) {
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
		// TODO: Implement
	case "lookup":
		// TODO: Implement
		if len(args) != 2 {
			caCmd.Usage()
			os.Exit(0)
		}
	case "enroll":
		// TODO: Implement
		if len(args) != 2 {
			caCmd.Usage()
			os.Exit(0)
		}
		fmt.Println(args[1])
	case "remove":
		// TODO: Implement
		if len(args) != 2 {
			caCmd.Usage()
			os.Exit(0)
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
	backend = rootCmd.String("backend", "default", "inventory backend to use (default: sqlite)")
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
		backend, err := inventory.GetBackend(*backend)
		if err != nil {
			log.Fatal(err)
		}

		if err := backend.Init(nil); err != nil {
			log.Fatal(err)
		}
		CAMain(os.Args[2:], backend)
	case "certificate":
		CertificateMain(os.Args[2:])
	default:
		rootCmd.Usage()
	}
}
