// Package alert provides a small structured event sink for ccguard.
//
// Phase 1 supports stdout (text or JSON lines). Later phases will add
// webhook delivery and OS-native notifications.
package alert

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// Level classifies an event's severity.
type Level string

const (
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelAlert Level = "alert"
)

// Options controls Sink formatting.
type Options struct {
	JSON  bool
	Quiet bool // suppress info-level messages
}

// Sink writes events to an io.Writer with optional JSON formatting.
type Sink struct {
	w    io.Writer
	opts Options
	mu   sync.Mutex
}

// NewSink constructs a Sink. The Writer must be safe for concurrent use or
// the caller must avoid concurrent emission (Sink itself serialises writes).
func NewSink(w io.Writer, opts Options) *Sink {
	return &Sink{w: w, opts: opts}
}

type record struct {
	Time   string         `json:"time"`
	Level  Level          `json:"level"`
	Msg    string         `json:"msg"`
	Fields map[string]any `json:"fields,omitempty"`
}

// Info emits an info-level message (suppressed when Quiet is set).
func (s *Sink) Info(msg string, fields map[string]any) {
	if s.opts.Quiet {
		return
	}
	s.emit(LevelInfo, msg, fields)
}

// Warn emits a warning.
func (s *Sink) Warn(msg string, fields map[string]any) {
	s.emit(LevelWarn, msg, fields)
}

// Alert emits a high-severity event. These are the primary user-facing
// detections — unapproved file changes, removed files, etc.
func (s *Sink) Alert(msg string, fields map[string]any) {
	s.emit(LevelAlert, msg, fields)
}

func (s *Sink) emit(level Level, msg string, fields map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r := record{
		Time:   time.Now().UTC().Format(time.RFC3339),
		Level:  level,
		Msg:    msg,
		Fields: fields,
	}

	if s.opts.JSON {
		enc := json.NewEncoder(s.w)
		_ = enc.Encode(r)
		return
	}

	prefix := levelPrefix(level)
	fmt.Fprintf(s.w, "%s [%s] %s", r.Time, prefix, msg)
	if len(fields) > 0 {
		fmt.Fprint(s.w, "  {")
		first := true
		for k, v := range fields {
			if !first {
				fmt.Fprint(s.w, ", ")
			}
			first = false
			fmt.Fprintf(s.w, "%s=%v", k, v)
		}
		fmt.Fprint(s.w, "}")
	}
	fmt.Fprintln(s.w)
}

func levelPrefix(l Level) string {
	switch l {
	case LevelAlert:
		return "ALERT"
	case LevelWarn:
		return "WARN "
	default:
		return "INFO "
	}
}
