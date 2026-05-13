package main

import (
	"fmt"
	"os"

	"github.com/AngelFrieren/ccguard/internal/hashwatch"
	"github.com/AngelFrieren/ccguard/internal/storage"
	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show monitored files and their approval state",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := resolveConfig(cmd)
			if err != nil {
				return err
			}

			store, err := storage.Open(cfg.DBPath())
			if err != nil {
				return err
			}
			defer store.Close()
			if err := store.Migrate(); err != nil {
				return err
			}

			targets, err := hashwatch.ResolveTargets(cfg.WatchPaths)
			if err != nil {
				return err
			}

			fmt.Printf("data dir: %s\n", cfg.DataDir)
			fmt.Printf("watching: %v\n\n", cfg.WatchPaths)

			if len(targets) == 0 {
				fmt.Println("no monitored files currently exist on disk")
				return nil
			}

			anyDrift := false
			for _, t := range targets {
				h, err := hashwatch.HashFile(t)
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s: error reading: %v\n", t, err)
					continue
				}
				approved, err := store.IsApproved(t, h)
				if err != nil {
					return err
				}
				state := "OK     "
				if !approved {
					state = "DRIFT  "
					anyDrift = true
				}
				fmt.Printf("[%s] %s\n   sha256: %s\n", state, t, h)
			}

			if anyDrift {
				fmt.Println("\nUnapproved changes detected. Review and run `ccguard approve <path>` if intentional.")
				os.Exit(2)
			}
			return nil
		},
	}
}
