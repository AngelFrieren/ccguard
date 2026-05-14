// Package main is the ccguard CLI entry point.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/AngelFrieren/ccguard/internal/config"
	"github.com/spf13/cobra"
)

var (
	// version is set at build time via -ldflags.
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := buildRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// buildRootCmd constructs the root cobra command and all subcommands.
// Extracted so that tests can create a fresh command tree with custom
// stdin/stdout/stderr without running main().
func buildRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "ccguard",
		Short: "ccguard — file integrity monitor for Claude Code configuration",
		Long: `ccguard is a defensive file integrity monitor for Claude Code.

It detects unauthorized modifications to ~/.claude/settings.json and
project-level .claude/settings.json by comparing SHA-256 hashes against
an approved baseline.

This is Phase 1 (hash monitoring layer only). Future phases will add
baseline anomaly detection, IOC matching, and behavioral monitoring.`,
		SilenceUsage: true,
	}

	root.PersistentFlags().String("config", "", "config file (default: $XDG_CONFIG_HOME/ccguard/config.yaml)")
	root.PersistentFlags().String("data-dir", "", "data directory (default: $XDG_DATA_HOME/ccguard)")
	root.PersistentFlags().String("ioc-dir", "", "IOC YAML directory (default: $XDG_CONFIG_HOME/ccguard/iocs)")
	root.PersistentFlags().String("policy-dir", "", "policy YAML directory (default: $XDG_CONFIG_HOME/ccguard/policies)")

	// Phase 3 baseline flags.
	root.PersistentFlags().Int("baseline-min-samples", 30, "minimum executions before anomaly detection activates per hook")
	root.PersistentFlags().Int("baseline-window", 100, "number of recent executions used to compute the baseline")
	root.PersistentFlags().Float64("baseline-warn-z", 3.0, "z-score threshold for a Warn-level anomaly")
	root.PersistentFlags().Float64("baseline-alert-z", 5.0, "z-score threshold for an Alert-level anomaly")
	root.PersistentFlags().Duration("baseline-cooldown", 5*time.Minute, "minimum interval between anomaly alerts per hook")
	root.PersistentFlags().String("log-dir", "", "Mode A: directory to tail for Claude Code hook logs (disabled by default)")

	// Phase 4 behavioral monitoring flags.
	root.PersistentFlags().String("behavior-backend", "auto", "behavioral monitoring backend: auto|procfs|auditd|ebpf|off")

	root.AddCommand(
		newInitCmd(),
		newWatchCmd(),
		newApproveCmd(),
		newStatusCmd(),
		newIOCCmd(),
		newHookWrapCmd(),
		newBaselineCmd(),
		newPolicyCmd(),
		newBehaviorCmd(),
		newVersionCmd(),
	)
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ccguard %s (commit %s, built %s)\n", version, commit, date)
		},
	}
}

func resolveConfig(cmd *cobra.Command) (*config.Config, error) {
	configPath, _ := cmd.Flags().GetString("config")
	dataDir, _ := cmd.Flags().GetString("data-dir")
	iocDir, _ := cmd.Flags().GetString("ioc-dir")
	policyDir, _ := cmd.Flags().GetString("policy-dir")
	cfg, err := config.Load(configPath, dataDir, iocDir, policyDir)
	if err != nil {
		return nil, err
	}

	// Overlay Phase 3 baseline flags.
	if v, err := cmd.Flags().GetInt("baseline-min-samples"); err == nil {
		cfg.Baseline.MinSamples = v
	}
	if v, err := cmd.Flags().GetInt("baseline-window"); err == nil {
		cfg.Baseline.Window = v
	}
	if v, err := cmd.Flags().GetFloat64("baseline-warn-z"); err == nil {
		cfg.Baseline.WarnZ = v
	}
	if v, err := cmd.Flags().GetFloat64("baseline-alert-z"); err == nil {
		cfg.Baseline.AlertZ = v
	}
	if v, err := cmd.Flags().GetDuration("baseline-cooldown"); err == nil {
		cfg.Baseline.Cooldown = v
	}
	if v, err := cmd.Flags().GetString("log-dir"); err == nil {
		cfg.Baseline.LogDir = v
	}

	// Overlay Phase 4 behavior flags.
	if v, err := cmd.Flags().GetString("behavior-backend"); err == nil && v != "" {
		cfg.Behavior.Backend = v
	}
	return cfg, nil
}
