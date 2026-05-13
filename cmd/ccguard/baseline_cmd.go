package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/AngelFrieren/ccguard/internal/baseline"
	"github.com/AngelFrieren/ccguard/internal/storage"
	"github.com/spf13/cobra"
)

func newBaselineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Manage hook execution baselines (Phase 3 anomaly detection)",
	}
	cmd.AddCommand(newBaselineShowCmd(), newBaselineResetCmd())
	return cmd
}

func newBaselineShowCmd() *cobra.Command {
	var hookName string

	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show current baseline statistics for hook execution times",
		Long: `show prints a table of mean and standard deviation for each hook that has
collected enough samples to enter the monitoring phase.

Hooks still collecting samples (< --baseline-min-samples) are shown with
status "learning". Once a hook has enough samples, anomaly detection activates
and its status changes to "monitoring".`,
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

			det := baseline.NewDetector(store, nil, baseline.Config{
				MinSamples: cfg.Baseline.MinSamples,
				Window:     cfg.Baseline.Window,
				WarnZ:      cfg.Baseline.WarnZ,
				AlertZ:     cfg.Baseline.AlertZ,
				Cooldown:   cfg.Baseline.Cooldown,
			})

			var rows []storage.BaselineStats
			if hookName != "" {
				bs, err := det.Stats(hookName)
				if err != nil {
					return err
				}
				if bs != nil {
					rows = []storage.BaselineStats{*bs}
				}
			} else {
				rows, err = det.ListStats()
				if err != nil {
					return err
				}
			}

			if len(rows) == 0 {
				if hookName != "" {
					fmt.Printf("no baseline data for hook %q\n", hookName)
				} else {
					fmt.Println("no baseline data collected yet")
					fmt.Println("Run hooks via: ccguard hook-wrap <name> -- <command>")
				}
				return nil
			}

			fmt.Printf("Hook Execution Baselines  (min-samples: %d)\n\n", cfg.Baseline.MinSamples)
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "HOOK\tSAMPLES\tMEAN\tSTDDEV\tSTATUS\tUPDATED")
			fmt.Fprintln(tw, "----\t-------\t----\t------\t------\t-------")
			for _, r := range rows {
				status := "monitoring"
				if r.SampleCount < cfg.Baseline.MinSamples {
					status = fmt.Sprintf("learning (%d/%d)", r.SampleCount, cfg.Baseline.MinSamples)
				}
				updated := time.Unix(r.UpdatedAt, 0).UTC().Format("2006-01-02 15:04:05Z")
				fmt.Fprintf(tw, "%s\t%d\t%.1fms\t%.1fms\t%s\t%s\n",
					r.HookName, r.SampleCount,
					r.MeanMs, r.StddevMs,
					status, updated,
				)
			}
			tw.Flush()
			fmt.Printf("\nAnomaly thresholds: warn z≥%.1f  alert z≥%.1f  cooldown %v\n",
				cfg.Baseline.WarnZ, cfg.Baseline.AlertZ, cfg.Baseline.Cooldown)
			return nil
		},
	}

	cmd.Flags().StringVar(&hookName, "hook", "", "show statistics for a specific hook only")
	return cmd
}

func newBaselineResetCmd() *cobra.Command {
	var (
		hookName string
		force    bool
	)

	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Reset baseline statistics and execution history for a hook",
		Long: `reset deletes both the baseline statistics and the execution history for the
specified hook (or all hooks). The hook returns to the learning phase and will
begin collecting samples anew.

Use this after intentionally changing a hook's implementation so that the old
timing data no longer represents its normal behaviour.

Without --hook, ALL hooks are reset. A confirmation prompt is shown unless
--force is specified.`,
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

			det := baseline.NewDetector(store, nil, baseline.DefaultConfig())

			if !force {
				if !confirmBaselineReset(hookName) {
					fmt.Println("reset cancelled")
					return nil
				}
			}

			if hookName != "" {
				if err := det.ResetHook(hookName); err != nil {
					return fmt.Errorf("reset hook %q: %w", hookName, err)
				}
				fmt.Printf("baseline reset for hook %q — learning phase restarted\n", hookName)
			} else {
				if err := det.ResetAll(); err != nil {
					return fmt.Errorf("reset all: %w", err)
				}
				fmt.Println("all baselines reset — learning phase restarted for all hooks")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&hookName, "hook", "", "reset only this hook (default: reset all)")
	cmd.Flags().BoolVar(&force, "force", false, "skip confirmation prompt")
	return cmd
}

func confirmBaselineReset(hookName string) bool {
	if hookName != "" {
		fmt.Printf("This will delete all baseline data for hook %q (stats + execution history).\n", hookName)
	} else {
		fmt.Println("This will delete ALL baseline data for all hooks (stats + execution history).")
	}
	fmt.Print(`Type "yes" to confirm: `)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return strings.EqualFold(strings.TrimSpace(scanner.Text()), "yes")
}
