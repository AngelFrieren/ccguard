package baseline

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AngelFrieren/ccguard/internal/alert"
)

// LineParser extracts hook execution data from a single log line.
// Implementations must be safe to call concurrently.
type LineParser interface {
	Parse(line string) (hookName string, durationMs int64, ok bool)
}

// NoOpParser is the default — it skips every line. Substitute a real parser
// once the Claude Code hook log format is stable and documented.
type NoOpParser struct{}

func (NoOpParser) Parse(_ string) (string, int64, bool) { return "", 0, false }

// LogTailer discovers *.log files in a directory and tails them for new hook
// execution lines parsed by a LineParser. This is Mode A data collection:
// best-effort, requires no changes to the wrapped command, but depends on a
// stable log-line format.
type LogTailer struct {
	dir    string
	det    *Detector
	sink   *alert.Sink
	parser LineParser
}

// NewLogTailer creates a LogTailer. If parser is nil, NoOpParser is used.
func NewLogTailer(dir string, det *Detector, sink *alert.Sink, parser LineParser) *LogTailer {
	if parser == nil {
		parser = NoOpParser{}
	}
	return &LogTailer{dir: dir, det: det, sink: sink, parser: parser}
}

// Run scans dir for *.log files (immediately, then every 2 s) and tails each
// new file in its own goroutine. Returns when ctx is cancelled.
//
// If dir does not exist at startup, a Warn is emitted and Run returns
// immediately (best-effort semantics).
func (lt *LogTailer) Run(ctx context.Context) {
	if _, err := os.Stat(lt.dir); err != nil {
		lt.sink.Warn("Mode A log tailer: directory not found, tailing disabled",
			map[string]any{"log_dir": lt.dir})
		return
	}
	lt.sink.Info("Mode A log tailer started", map[string]any{"log_dir": lt.dir})

	seen := make(map[string]struct{})
	lt.discover(ctx, seen) // immediate scan so existing files are picked up at once

	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			lt.discover(ctx, seen)
		}
	}
}

// discover scans dir for new *.log files and starts a tailFile goroutine for
// each one not yet seen.
func (lt *LogTailer) discover(ctx context.Context, seen map[string]struct{}) {
	entries, err := os.ReadDir(lt.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		path := filepath.Join(lt.dir, e.Name())
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		go lt.tailFile(ctx, path)
	}
}

// tailFile tails path from its current end, processing new lines every 500 ms
// until ctx is cancelled or the file becomes unreadable.
func (lt *LogTailer) tailFile(ctx context.Context, path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	// Seek to end: only process lines appended after we started watching.
	if _, err := f.Seek(0, 2); err != nil {
		return
	}

	r := bufio.NewReader(f)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			lt.drainLines(r)
		}
	}
}

// drainLines reads all complete newline-terminated lines currently in r.
func (lt *LogTailer) drainLines(r *bufio.Reader) {
	for {
		line, err := r.ReadString('\n')
		if err == nil {
			// err==nil guarantees line ends with '\n'
			hookName, durationMs, ok := lt.parser.Parse(strings.TrimRight(line, "\r\n"))
			if ok {
				if recErr := lt.det.RecordAndCheck(hookName, durationMs, 0, "log"); recErr != nil {
					lt.sink.Warn("Mode A: record failed",
						map[string]any{"hook": hookName, "error": recErr.Error()})
				}
			}
		}
		if err != nil {
			return // io.EOF (partial line) or read error — stop draining
		}
	}
}
