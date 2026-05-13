package main

import (
	"fmt"
	"os"

	"github.com/AngelFrieren/ccguard/internal/hashwatch"
	"github.com/AngelFrieren/ccguard/internal/storage"
	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize ccguard and approve current Claude Code config as baseline",
		Long: `init creates the ccguard data directory, initializes the SQLite database,
and records the current state of monitored files as the approved baseline.

By default, init refuses to overwrite an existing baseline. Use --force to
re-initialize (this discards previous approvals).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := resolveConfig(cmd)
			if err != nil {
				return err
			}

			if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
				return fmt.Errorf("create data dir: %w", err)
			}

			store, err := storage.Open(cfg.DBPath())
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer store.Close()

			if err := store.Migrate(); err != nil {
				return fmt.Errorf("migrate db: %w", err)
			}

			existing, err := store.CountApproved()
			if err != nil {
				return err
			}
			if existing > 0 && !force {
				return fmt.Errorf("baseline already exists (%d approved entries). Use --force to overwrite", existing)
			}
			if force {
				if err := store.ClearApproved(); err != nil {
					return err
				}
			}

			targets, err := hashwatch.ResolveTargets(cfg.WatchPaths)
			if err != nil {
				return fmt.Errorf("resolve targets: %w", err)
			}
			if len(targets) == 0 {
				fmt.Println("no monitored files found yet — they will be detected on first change")
				fmt.Printf("baseline initialized at %s\n", cfg.DataDir)
				return nil
			}

			for _, t := range targets {
				h, err := hashwatch.HashFile(t)
				if err != nil {
					fmt.Fprintf(os.Stderr, "skip %s: %v\n", t, err)
					continue
				}
				if err := store.Approve(t, h, "init"); err != nil {
					return fmt.Errorf("approve %s: %w", t, err)
				}
				fmt.Printf("approved %s\n  sha256: %s\n", t, h)
			}

			fmt.Printf("\nbaseline initialized with %d file(s)\n", len(targets))
			fmt.Printf("data dir: %s\n", cfg.DataDir)
			fmt.Println("\nNext: run `ccguard watch` to start monitoring.")
			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing baseline")
	return cmd
}
