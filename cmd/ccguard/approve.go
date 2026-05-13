package main

import (
	"fmt"
	"path/filepath"

	"github.com/AngelFrieren/ccguard/internal/hashwatch"
	"github.com/AngelFrieren/ccguard/internal/storage"
	"github.com/spf13/cobra"
)

func newApproveCmd() *cobra.Command {
	var note string

	cmd := &cobra.Command{
		Use:   "approve <path>",
		Short: "Approve the current hash of a file as legitimate",
		Long: `approve records the current SHA-256 hash of the given file as approved.

Use this after intentionally modifying a Claude Code settings file so that
subsequent watch runs don't alert on the change.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := resolveConfig(cmd)
			if err != nil {
				return err
			}

			path, err := filepath.Abs(args[0])
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

			h, err := hashwatch.HashFile(path)
			if err != nil {
				return fmt.Errorf("hash file: %w", err)
			}

			reason := note
			if reason == "" {
				reason = "manual approve"
			}
			if err := store.Approve(path, h, reason); err != nil {
				return err
			}

			fmt.Printf("approved %s\n  sha256: %s\n  reason: %s\n", path, h, reason)
			return nil
		},
	}

	cmd.Flags().StringVar(&note, "note", "", "optional reason for approval (recorded in audit log)")
	return cmd
}
