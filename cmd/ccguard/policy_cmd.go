package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/AngelFrieren/ccguard/internal/policy"
	"github.com/spf13/cobra"
)

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage behavioral monitoring policies (Phase 4)",
	}
	cmd.AddCommand(newPolicyListCmd(), newPolicyCheckCmd(), newPolicyInitCmd())
	return cmd
}

func newPolicyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all loaded behavioral monitoring policies",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := resolveConfig(cmd)
			if err != nil {
				return err
			}
			pdb, err := policy.LoadWithFallback(cfg.Behavior.PolicyDir)
			if err != nil {
				return err
			}
			policies := pdb.All()

			// Report load source.
			switch pdb.Source {
			case policy.SourceUser:
				fmt.Printf("Source: user dir (%s)\n\n", cfg.Behavior.PolicyDir)
			case policy.SourceBuiltin:
				fmt.Printf("Source: built-in defaults (user dir empty or missing: %s)\n", cfg.Behavior.PolicyDir)
				fmt.Printf("Run 'ccguard policy init' to write the defaults to your config directory.\n\n")
			}

			if len(policies) == 0 {
				fmt.Println("no policies loaded")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSEVERITY\tSYSCALL\tACTION\tDESCRIPTION")
			fmt.Fprintln(tw, "--\t--------\t-------\t------\t-----------")
			for _, p := range policies {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					p.ID, p.Severity, p.When.Syscall, p.Action, p.Description)
			}
			tw.Flush()
			fmt.Printf("\n%d policy(ies)\n", len(policies))
			return nil
		},
	}
}

func newPolicyCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check <yaml-file>",
		Short: "Validate policy YAML syntax and report any errors",
		Long: `check parses a policy YAML file and reports any validation errors.
Exits 0 if all policies are valid, 1 if any errors are found.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pdb, errs := policy.LoadFile(args[0])
			if len(errs) > 0 {
				for _, e := range errs {
					fmt.Fprintf(os.Stderr, "error: %v\n", e)
				}
				fmt.Fprintf(os.Stderr, "%d error(s) found in %s\n", len(errs), args[0])
				os.Exit(1)
			}
			fmt.Printf("OK: %d valid policy(ies) in %s\n", pdb.Len(), args[0])
			return nil
		},
	}
}

func newPolicyInitCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write the built-in default policies to your config directory",
		Long: `init writes the built-in default policy file to
$XDG_CONFIG_HOME/ccguard/policies/default.yaml.

If the file already exists, you will be prompted to confirm before
overwriting. Use --force to skip the prompt.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := resolveConfig(cmd)
			if err != nil {
				return err
			}

			dest := filepath.Join(cfg.Behavior.PolicyDir, "default.yaml")

			if _, statErr := os.Stat(dest); statErr == nil {
				// File already exists.
				if !force {
					fmt.Fprintf(cmd.OutOrStdout(), "policy file already exists: %s\nOverwrite? [y/N] ", dest)
					scanner := bufio.NewScanner(cmd.InOrStdin())
					scanner.Scan()
					answer := strings.TrimSpace(scanner.Text())
					if !strings.EqualFold(answer, "y") {
						fmt.Fprintln(cmd.OutOrStdout(), "aborted")
						return nil
					}
				}
			}

			if err := os.MkdirAll(cfg.Behavior.PolicyDir, 0o700); err != nil {
				return fmt.Errorf("create policy dir: %w", err)
			}
			data := policy.DefaultPoliciesYAML()
			if err := os.WriteFile(dest, data, 0o644); err != nil {
				return fmt.Errorf("write %s: %w", dest, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "written: %s\n", dest)
			fmt.Fprintln(cmd.OutOrStdout(), "Edit the file to customise your policies, then restart 'ccguard watch'.")
			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing file without prompting")
	return cmd
}
