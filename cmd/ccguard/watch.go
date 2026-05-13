package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/AngelFrieren/ccguard/internal/alert"
	"github.com/AngelFrieren/ccguard/internal/hashwatch"
	"github.com/AngelFrieren/ccguard/internal/ioc"
	"github.com/AngelFrieren/ccguard/internal/storage"
	"github.com/spf13/cobra"
)

func newWatchCmd() *cobra.Command {
	var (
		jsonLog bool
		quiet   bool
	)

	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Watch monitored files and alert on unapproved changes",
		Long: `watch starts a long-running monitor that detects modifications to
~/.claude/settings.json and project-level .claude/settings.json files.

When a change is detected, ccguard computes the SHA-256 of the new content
and compares it against the approved baseline. If the hash is unknown,
an alert is emitted and the change is recorded in the audit log.

Press Ctrl+C to stop.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := resolveConfig(cmd)
			if err != nil {
				return err
			}

			store, err := storage.Open(cfg.DBPath())
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer store.Close()
			if err := store.Migrate(); err != nil {
				return err
			}

			sink := alert.NewSink(os.Stdout, alert.Options{
				JSON:  jsonLog,
				Quiet: quiet,
			})

			iocDB, err := ioc.LoadDir(cfg.IOCDir)
			if err != nil {
				return fmt.Errorf("load IOC database: %w", err)
			}
			if iocDB.Len() > 0 {
				sink.Info("IOC database loaded", map[string]any{"count": iocDB.Len(), "dir": cfg.IOCDir})
			}

			watcher, err := hashwatch.NewWatcher(cfg.WatchPaths, store, sink, iocDB)
			if err != nil {
				return fmt.Errorf("new watcher: %w", err)
			}
			defer watcher.Close()

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			sink.Info("ccguard watch started", map[string]any{
				"paths": cfg.WatchPaths,
			})

			if err := watcher.Run(ctx); err != nil && ctx.Err() == nil {
				return err
			}

			sink.Info("ccguard watch stopped", nil)
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonLog, "json", false, "emit alerts as JSON lines")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "suppress info-level messages")
	return cmd
}
