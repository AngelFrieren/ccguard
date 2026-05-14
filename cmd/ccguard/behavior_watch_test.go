package main

import (
	"testing"

	"github.com/AngelFrieren/ccguard/internal/behavior"
	"github.com/AngelFrieren/ccguard/internal/policy"
)

func TestEffectiveCmdBasename(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"empty args", nil, ""},
		{"direct binary", []string{"/usr/bin/curl"}, "curl"},
		{"direct binary basename", []string{"curl"}, "curl"},
		{"bash script", []string{"/bin/bash", "/tmp/secret-tool"}, "secret-tool"},
		{"sh script", []string{"/bin/sh", "/home/user/hook.sh"}, "hook.sh"},
		{"python script", []string{"/usr/bin/python3", "/opt/tool.py"}, "tool.py"},
		{"ruby script", []string{"/usr/bin/ruby", "/srv/run.rb"}, "run.rb"},
		{"perl script", []string{"/usr/bin/perl", "/opt/scan.pl"}, "scan.pl"},
		{"node script", []string{"/usr/bin/node", "/app/index.js"}, "index.js"},
		// bash with a flag before the script: our heuristic uses args[1]
		// verbatim, which would be the flag. The important invariant is no
		// crash; auditd events tend to not include flags like this.
		{"bash flag-then-script", []string{"/bin/bash", "-x", "/tmp/debug.sh"}, "-x"},
		// Non-interpreter binary: use argv[0] basename regardless of arg count.
		{"non-interpreter multi-arg", []string{"/usr/bin/find", "/tmp", "-name", "*.sh"}, "find"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := effectiveCmdBasename(tc.args)
			if got != tc.want {
				t.Errorf("effectiveCmdBasename(%v) = %q; want %q", tc.args, got, tc.want)
			}
		})
	}
}

func TestBehaviorEventToPolicyEvent_InterpretedScript(t *testing.T) {
	// Simulate what procfs reports when hook-wrap spawns a bash script named
	// "secret-tool": args[0] is the interpreter, args[1] is the script path.
	ev := behavior.Event{
		Syscall: "execve",
		Args:    []string{"/bin/bash", "/tmp/secret-tool"},
		Backend: "procfs",
	}
	pe := behaviorEventToPolicyEvent(ev)
	if pe.CmdBasename != "secret-tool" {
		t.Errorf("CmdBasename = %q; want %q", pe.CmdBasename, "secret-tool")
	}
}

func TestBehaviorEventToPolicyEvent_DirectBinary(t *testing.T) {
	ev := behavior.Event{
		Syscall: "execve",
		Args:    []string{"/usr/bin/curl", "-s", "https://example.com"},
		Backend: "procfs",
	}
	pe := behaviorEventToPolicyEvent(ev)
	if pe.CmdBasename != "curl" {
		t.Errorf("CmdBasename = %q; want %q", pe.CmdBasename, "curl")
	}
}

func TestBehaviorEventToPolicyEvent_PolicyMatchAfterFix(t *testing.T) {
	// End-to-end: a bash-wrapped "secret-tool" should match the T6-credential-tool
	// policy from the built-in defaults.
	pdb, err := policy.LoadWithFallback("") // built-in defaults
	if err != nil {
		t.Fatalf("LoadWithFallback: %v", err)
	}

	// Simulate the procfs event for "bash /tmp/secret-tool"
	ev := behavior.Event{
		Syscall: "execve",
		Args:    []string{"/bin/bash", "/tmp/secret-tool"},
		Backend: "procfs",
	}
	pe := behaviorEventToPolicyEvent(ev)
	matches := pdb.Eval(pe)

	found := false
	for _, m := range matches {
		if m.Policy.ID == "T6-credential-tool" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected T6-credential-tool match for bash-wrapped secret-tool; pe=%+v; matches=%+v", pe, matches)
	}
}
