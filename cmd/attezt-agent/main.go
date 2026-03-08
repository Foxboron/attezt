package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/foxboron/attezt/internal/agent"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"

	"github.com/urfave/cli/v3"
)

// Main command
var cmd = &cli.Command{
	Name:    "attezt-agent",
	Version: "v0.0.0",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "varlink",
			Value: "/run/attezt/dev.attezt.Agent",
			Usage: "address for varlink socket",
		},
		&cli.StringFlag{
			Name:  "p11kit",
			Value: "/run/attezt/p11kit.socket",
			Usage: "address for p11kit socket",
		},
		&cli.StringFlag{
			Name:  "state-dir",
			Value: "/var/lib/attezt",
			Usage: "state location for attezt",
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		rwc, err := linuxtpm.Open("/dev/tpmrm0")
		if err != nil {
			return err
		}
		defer rwc.Close()
		log.Printf("p11kit-server is running\n")
		log.Printf("export P11_KIT_SERVER_ADDRESS=unix:path=%s", cmd.String("p11kit"))
		log.Printf("varlink service is running")
		log.Printf("Running at: %s", cmd.String("varlink"))

		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		a, err := agent.NewAtteztAgent(ctx, rwc, cmd.String("varlink"), cmd.String("p11kit"), cmd.String("state-dir"))
		if err != nil {
			return err
		}

		defer func() {
			if err := a.Close(); err != nil {
				log.Fatal(err)
			}
		}()

		fsroot, err := os.OpenRoot(cmd.String("state-dir"))
		if err != nil {
			return err
		}

		// Try to load device certs if we have them
		_, err1 := fsroot.Stat("device.crt")
		_, err2 := fsroot.Stat("device.tss")
		if err := errors.Join(err1, err2); !errors.Is(err, os.ErrNotExist) {
			keyb, err := fsroot.ReadFile("device.tss")
			if err != nil {
				return err
			}
			crtb, err := fsroot.ReadFile("device.crt")
			if err != nil {
				return err
			}
			if err := a.LoadKeys(keyb, crtb); err != nil {
				return err
			}
		}

		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, syscall.SIGINT, syscall.SIGTERM)
		<-sigint
		cancel()
		return nil
	},
}

func main() {
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
