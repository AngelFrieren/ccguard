package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/AngelFrieren/ccguard/internal/alert"
	"github.com/AngelFrieren/ccguard/internal/baseline"
	"github.com/AngelFrieren/ccguard/internal/storage"
	"github.com/spf13/cobra"
)

// nowFn returns the current time. Replaced in tests for deterministic timing.
var nowFn = func() time.Time { return time.Now() }

func newHookWrapCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hook-wrap <name> -- <cmd> [args...]",
		Short: "Wrap a Claude Code hook, record its execution time, and detect anomalies",
		Long: `hook-wrap executes the given command on behalf of a Claude Code hook,
transparently passing through stdin, stdout, stderr, and the exit code.

After the command finishes, it records the execution duration in the ccguard
database and checks it against the learned baseline for that hook name. If the
duration deviates significantly (controlled by --baseline-warn-z and
--baseline-alert-z), a warning or alert is written to stderr.

To use hook-wrap, replace your hook command in Claude Code settings.json with:

  ccguard hook-wrap <HookName> -- <original-command>

Example settings.json snippet:

  "hooks": {
    "UserPromptSubmit": [{
      "command": "ccguard hook-wrap UserPromptSubmit -- /path/to/my-hook.sh"
    }]
  }

The -- separator is required to prevent flag conflicts between hook-wrap flags
and flags of the wrapped command.

hook-wrap works without a running ccguard watch daemon — it opens the SQLite
database directly. Data collected while watch is stopped is incorporated into
the baseline the next time watch starts.

Exit codes:
  Propagates the wrapped command's exit code exactly.
  Exits 1 if the command cannot be launched.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			hookName := args[0]
			command := args[1]
			cmdArgs := args[2:]

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

			// Alerts go to stderr so they appear in the Claude Code session
			// without mixing with the hook's own stdout.
			sink := alert.NewSink(os.Stderr, alert.Options{})

			det := baseline.NewDetector(store, sink, baseline.Config{
				MinSamples: cfg.Baseline.MinSamples,
				Window:     cfg.Baseline.Window,
				WarnZ:      cfg.Baseline.WarnZ,
				AlertZ:     cfg.Baseline.AlertZ,
				Cooldown:   cfg.Baseline.Cooldown,
			})

			// Notify the watch daemon of our PID so it can track the hook
			// process tree (Phase 4 behavioral monitoring). Best-effort: if the
			// daemon is not running the notification fails silently.
			notifyDaemon(cfg.SocketPath(), os.Getpid())

			exitCode := runWrap(det, hookName, command, cmdArgs)
			if exitCode != 0 {
				os.Exit(exitCode)
			}
			return nil
		},
	}
}

// notifyDaemon sends our PID to the ccguard daemon via Unix socket so the
// daemon can track this hook-wrap process and its children as the root of the
// behavior monitoring process tree. Best-effort: errors are silently ignored
// so that hook-wrap never fails due to a missing daemon.
func notifyDaemon(sockPath string, pid int) {
	conn, err := net.DialTimeout("unix", sockPath, 200*time.Millisecond)
	if err != nil {
		return // daemon not running or socket not ready — that is OK
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	fmt.Fprintf(conn, "%d\n", pid)
}

// runWrap executes command with args, records the execution via det, and
// returns the exit code. It is extracted for testability.
func runWrap(det *baseline.Detector, hookName, command string, args []string) int {
	c := exec.Command(command, args...)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	start := nowFn()
	runErr := c.Run()
	durationMs := nowFn().Sub(start).Milliseconds()

	exitCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	if err := det.RecordAndCheck(hookName, durationMs, exitCode, "wrap"); err != nil {
		fmt.Fprintf(os.Stderr, "ccguard hook-wrap: baseline record failed: %v\n", err)
	}

	return exitCode
}
