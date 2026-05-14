package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/AngelFrieren/ccguard/internal/alert"
	"github.com/AngelFrieren/ccguard/internal/behavior"
	"github.com/AngelFrieren/ccguard/internal/policy"
	"github.com/AngelFrieren/ccguard/internal/storage"
)

// listenPIDSocket accepts connections on a Unix domain socket and registers
// each notified PID as a root in tree. hook-wrap sends its PID here so the
// daemon can track the full hook process forest for behavioral monitoring.
//
// The socket file is created with 0600 permissions (same-user access only).
func listenPIDSocket(ctx context.Context, sockPath string, tree *behavior.ProcTree, sink *alert.Sink) {
	_ = os.Remove(sockPath) // remove stale socket from a previous run

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		sink.Warn("behavior: PID socket listen failed",
			map[string]any{"path": sockPath, "error": err.Error()})
		return
	}
	defer func() {
		l.Close()
		_ = os.Remove(sockPath)
	}()

	if err := os.Chmod(sockPath, 0600); err != nil {
		sink.Warn("behavior: PID socket chmod failed", map[string]any{"error": err.Error()})
	}

	// Close the listener when ctx is cancelled so Accept() unblocks.
	go func() {
		<-ctx.Done()
		l.Close()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			return // listener closed (ctx cancelled)
		}
		go handlePIDConn(conn, tree)
	}
}

func handlePIDConn(conn net.Conn, tree *behavior.ProcTree) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	var pid int
	if _, err := fmt.Fscan(conn, &pid); err == nil && pid > 0 {
		tree.AddRoot(pid)
	}
}

// processBehaviorEvents consumes events from ch, evaluates each against pdb,
// emits alerts via sink, and writes behavior_events to store in batches of up
// to 100 events or 100 ms — whichever comes first.
func processBehaviorEvents(
	ctx context.Context,
	ch <-chan behavior.Event,
	pdb *policy.DB,
	store *storage.Store,
	sink *alert.Sink,
) {
	var batch []storage.BehaviorEvent
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := store.BatchRecordBehaviorEvents(batch); err != nil {
			sink.Warn("behavior: batch write failed", map[string]any{"error": err.Error()})
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case <-tick.C:
			flush()
		case ev, ok := <-ch:
			if !ok {
				flush()
				return
			}
			pev := behaviorEventToPolicyEvent(ev)
			matches := pdb.Eval(pev)

			for _, m := range matches {
				fields := map[string]any{
					"policy_id":   m.Policy.ID,
					"severity":    string(m.Policy.Severity),
					"description": m.Policy.Description,
					"backend":     ev.Backend,
					"pid":         ev.Pid,
					"ppid":        ev.Ppid,
					"syscall":     ev.Syscall,
				}
				if len(ev.Args) > 0 {
					fields["args"] = ev.Args[0]
				}
				msg := fmt.Sprintf("behavioral policy match (T6): %s", m.Policy.ID)
				switch m.Policy.Action {
				case policy.ActionAlert:
					sink.Alert(msg, fields)
				case policy.ActionWarn:
					sink.Warn(msg, fields)
				}
				_ = store.RecordEvent(
					fmt.Sprintf("pid:%d", ev.Pid), "", "behavior-policy-match", ev.Backend,
				)
			}

			policyID, severity := "", ""
			if len(matches) > 0 {
				policyID = matches[0].Policy.ID
				severity = string(matches[0].Policy.Severity)
			}
			batch = append(batch, storage.BehaviorEvent{
				Ts:       ev.Ts,
				Backend:  ev.Backend,
				Pid:      ev.Pid,
				Ppid:     ev.Ppid,
				Syscall:  ev.Syscall,
				ArgsJSON: argsToJSON(ev.Args),
				PolicyID: policyID,
				Severity: severity,
			})
			if len(batch) >= 100 {
				flush()
			}
		}
	}
}

func behaviorEventToPolicyEvent(e behavior.Event) policy.Event {
	pe := policy.Event{Syscall: e.Syscall}
	if len(e.Args) > 0 {
		switch e.Syscall {
		case "execve":
			pe.CmdBasename = effectiveCmdBasename(e.Args)
		case "openat":
			pe.Path = e.Args[0]
		case "connect":
			pe.Destination = e.Args[0]
		}
	}
	return pe
}

// effectiveCmdBasename extracts the meaningful command name from execve args.
//
// When a shebang script is executed, the kernel replaces the process image
// with the interpreter and args[0] becomes the interpreter path (e.g.
// "/bin/bash"), while args[1] is the script being run. In that case the
// script name is the actionable identity for policy matching, not the
// interpreter. For direct binary execution, args[0] is the binary path.
//
// The policy engine also normalizes with filepath.Base, so this function
// does not need to strip directories — but it does so for clarity.
func effectiveCmdBasename(args []string) string {
	if len(args) == 0 {
		return ""
	}
	base0 := filepath.Base(args[0])
	// If args[0] is a known script interpreter and a script path follows,
	// use the script name as the effective command identity.
	if len(args) > 1 {
		switch base0 {
		case "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "fish",
			"python", "python2", "python3",
			"ruby", "perl", "lua",
			"node", "nodejs":
			return filepath.Base(args[1])
		}
	}
	return base0
}

func argsToJSON(args []string) string {
	if len(args) == 0 {
		return "[]"
	}
	b, err := json.Marshal(args)
	if err != nil {
		return "[]"
	}
	return string(b)
}
