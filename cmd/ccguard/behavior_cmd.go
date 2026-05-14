package main

import (
	"fmt"
	"os"
	"time"

	"github.com/AngelFrieren/ccguard/internal/behavior"
	"github.com/AngelFrieren/ccguard/internal/storage"
	"github.com/spf13/cobra"
)

func newBehaviorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "behavior",
		Short: "Inspect behavioral monitoring status (Phase 4)",
	}
	cmd.AddCommand(newBehaviorStatusCmd())
	return cmd
}

func newBehaviorStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show behavioral monitoring backend and recent event counts",
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
				return err
			}
			defer store.Close()
			if err := store.Migrate(); err != nil {
				return err
			}

			// Show backend availability.
			tree := behavior.NewProcTree()
			b, active := behavior.SelectBackend(cfg.Behavior.Backend, tree, nil)
			status := "unavailable"
			if active {
				status = "active (watch daemon)"
			}
			fmt.Printf("Behavioral monitoring:\n")
			fmt.Printf("  configured backend : %s\n", cfg.Behavior.Backend)
			fmt.Printf("  selected backend   : %s\n", b.Name())
			fmt.Printf("  availability       : %s\n", status)
			fmt.Printf("  policy directory   : %s\n", cfg.Behavior.PolicyDir)
			fmt.Printf("  socket path        : %s\n", cfg.SocketPath())

			// Show event counts.
			since := time.Now().Add(-24 * time.Hour).Unix()
			n, err := store.CountBehaviorEventsSince(since)
			if err != nil {
				return err
			}
			fmt.Printf("\nBehavior events (past 24h): %d\n", n)
			if n > 0 {
				evs, err := store.RecentBehaviorEvents(5)
				if err != nil {
					return err
				}
				fmt.Println("\nMost recent events:")
				for _, ev := range evs {
					t := time.Unix(ev.Ts, 0).UTC().Format("2006-01-02 15:04:05Z")
					policy := ev.PolicyID
					if policy == "" {
						policy = "(no policy match)"
					}
					fmt.Printf("  %s  pid=%-6d  %-7s  %s  %s\n",
						t, ev.Pid, ev.Syscall, ev.Backend, policy)
				}
			}
			return nil
		},
	}
}
