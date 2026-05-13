// Package main is the ccguard CLI entry point.
package main

import (
	"fmt"
	"os"

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

	root.AddCommand(
		newInitCmd(),
		newWatchCmd(),
		newApproveCmd(),
		newStatusCmd(),
		newVersionCmd(),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
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
	return config.Load(configPath, dataDir, iocDir)
}
