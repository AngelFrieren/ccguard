package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/AngelFrieren/ccguard/internal/hashwatch"
	"github.com/AngelFrieren/ccguard/internal/ioc"
	"github.com/spf13/cobra"
)

func newIOCCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ioc",
		Short: "Manage and query the IOC (Indicator of Compromise) database",
	}
	cmd.AddCommand(newIOCListCmd(), newIOCCheckCmd())
	return cmd
}

func newIOCListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all loaded IOC indicators",
		Long: `list loads all IOC YAML files from the configured IOC directory and
prints a table of every indicator: its ID, severity, and description.

The IOC directory defaults to $XDG_CONFIG_HOME/ccguard/iocs and can be
overridden with the global --ioc-dir flag.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := resolveConfig(cmd)
			if err != nil {
				return err
			}

			db, err := ioc.LoadDir(cfg.IOCDir)
			if err != nil {
				return fmt.Errorf("load IOC database: %w", err)
			}

			indicators := db.All()
			if len(indicators) == 0 {
				fmt.Printf("no indicators loaded from %s\n", cfg.IOCDir)
				fmt.Println("Place *.yaml files in that directory to populate the IOC database.")
				return nil
			}

			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSEVERITY\tKIND\tDESCRIPTION")
			fmt.Fprintln(tw, "--\t--------\t----\t-----------")
			for _, ind := range indicators {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
					ind.ID,
					ind.Severity,
					ind.Match.Kind,
					ind.Description,
				)
			}
			_ = tw.Flush()

			fmt.Printf("\n%d indicator(s) loaded from %s\n", len(indicators), cfg.IOCDir)
			return nil
		},
	}
}

func newIOCCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check <path>",
		Short: "Check a file against the IOC database and print any matches",
		Long: `check hashes the given file and tests both its SHA-256 and its path
against every loaded IOC indicator. This is useful for ad-hoc investigation
without starting the watch daemon.

Exit codes:
  0  no IOC matches found
  1  one or more IOC matches found (or an error occurred)`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := resolveConfig(cmd)
			if err != nil {
				return err
			}

			path := args[0]

			db, err := ioc.LoadDir(cfg.IOCDir)
			if err != nil {
				return fmt.Errorf("load IOC database: %w", err)
			}

			// Hash the file if it exists; path-based IOCs still work without it.
			var hash string
			h, hashErr := hashwatch.HashFile(path)
			if hashErr == nil {
				hash = h
			}

			matches := db.Match(path, hash)

			fmt.Printf("file: %s\n", path)
			if hash != "" {
				fmt.Printf("sha256: %s\n", hash)
			} else {
				fmt.Printf("sha256: (file not readable: %v)\n", hashErr)
			}
			fmt.Printf("ioc dir: %s (%d indicator(s))\n\n", cfg.IOCDir, db.Len())

			if len(matches) == 0 {
				fmt.Println("result: no IOC matches")
				return nil
			}

			fmt.Printf("result: %d MATCH(ES) FOUND\n\n", len(matches))
			for _, m := range matches {
				fmt.Printf("  [%s] %s\n", m.Severity, m.ID)
				fmt.Printf("  description: %s\n", m.Description)
				if len(m.References) > 0 {
					fmt.Println("  references:")
					for _, ref := range m.References {
						fmt.Printf("    - %s\n", ref)
					}
				}
				fmt.Println()
			}

			// Exit 1 to signal matches to calling scripts.
			os.Exit(1)
			return nil
		},
	}
}
