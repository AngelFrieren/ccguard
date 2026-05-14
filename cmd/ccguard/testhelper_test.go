package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// runCLI builds a fresh root command, wires the provided stdin (nil → empty),
// captures stdout and stderr, and executes with the given args.
// It returns (stdout, stderr, error) and never calls os.Exit.
func runCLI(t *testing.T, stdin io.Reader, args ...string) (string, string, error) {
	t.Helper()
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	var outBuf, errBuf bytes.Buffer
	root := buildRootCmd()
	root.SetIn(stdin)
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs(args)
	// SilenceErrors prevents cobra from writing to stderr on error.
	root.SilenceErrors = true
	err := root.Execute()
	return outBuf.String(), errBuf.String(), err
}
