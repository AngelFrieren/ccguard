package hashwatch

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/AngelFrieren/ccguard/internal/alert"
	"github.com/AngelFrieren/ccguard/internal/ioc"
	"github.com/AngelFrieren/ccguard/internal/storage"
	"github.com/fsnotify/fsnotify"
)

// debounceWindow coalesces rapid successive events on the same path.
// Editors often emit several events per save (write, chmod, rename) so we
// wait briefly before hashing to capture the final state.
const debounceWindow = 150 * time.Millisecond

// Watcher monitors .claude directories for changes to sensitive files.
type Watcher struct {
	watchPaths []string
	fsw        *fsnotify.Watcher
	store      *storage.Store
	sink       *alert.Sink
	iocDB      *ioc.DB // may be nil when IOC matching is not configured

	mu      sync.Mutex
	pending map[string]*time.Timer
}

// NewWatcher constructs a Watcher. iocDB may be nil to disable IOC matching.
// Caller must defer Close.
func NewWatcher(paths []string, store *storage.Store, sink *alert.Sink, iocDB *ioc.DB) (*Watcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("fsnotify: %w", err)
	}

	w := &Watcher{
		watchPaths: paths,
		fsw:        fsw,
		store:      store,
		sink:       sink,
		iocDB:      iocDB,
		pending:    make(map[string]*time.Timer),
	}

	if err := w.addWatches(); err != nil {
		_ = fsw.Close()
		return nil, err
	}
	return w, nil
}

// Close releases the underlying fsnotify watcher.
func (w *Watcher) Close() error {
	w.mu.Lock()
	for _, t := range w.pending {
		t.Stop()
	}
	w.pending = nil
	w.mu.Unlock()
	return w.fsw.Close()
}

func (w *Watcher) addWatches() error {
	for _, p := range w.watchPaths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return err
		}

		info, err := os.Stat(abs)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				// Watch the parent so we catch creation of the .claude dir later.
				parent := filepath.Dir(abs)
				if _, perr := os.Stat(parent); perr == nil {
					if werr := w.fsw.Add(parent); werr != nil {
						w.sink.Warn("cannot watch parent directory", map[string]any{
							"path":  parent,
							"error": werr.Error(),
						})
					}
				}
				continue
			}
			return err
		}

		target := abs
		if !info.IsDir() {
			target = filepath.Dir(abs)
		}
		if err := w.fsw.Add(target); err != nil {
			return fmt.Errorf("watch %s: %w", target, err)
		}
		w.sink.Info("watching", map[string]any{"path": target})
	}
	return nil
}

// Run blocks until ctx is cancelled or the underlying watcher errors.
func (w *Watcher) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil

		case event, ok := <-w.fsw.Events:
			if !ok {
				return errors.New("fsnotify events channel closed")
			}
			w.handleEvent(event)

		case err, ok := <-w.fsw.Errors:
			if !ok {
				return errors.New("fsnotify errors channel closed")
			}
			w.sink.Warn("fsnotify error", map[string]any{"error": err.Error()})
		}
	}
}

func (w *Watcher) handleEvent(ev fsnotify.Event) {
	// We only care about files that look like monitored Claude settings.
	if !IsMonitored(ev.Name) {
		return
	}
	// Ignore pure chmod-only events.
	if ev.Op == fsnotify.Chmod {
		return
	}

	w.scheduleCheck(ev.Name, ev.Op.String())
}

func (w *Watcher) scheduleCheck(path, op string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.pending == nil {
		return
	}
	if t, ok := w.pending[path]; ok {
		t.Stop()
	}
	w.pending[path] = time.AfterFunc(debounceWindow, func() {
		w.mu.Lock()
		delete(w.pending, path)
		w.mu.Unlock()
		w.check(path, op)
	})
}

func (w *Watcher) check(path, op string) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			w.sink.Alert("monitored file removed", map[string]any{
				"path": path,
				"op":   op,
			})
			_ = w.store.RecordEvent(path, "", "removed", op)
			return
		}
		w.sink.Warn("stat failed", map[string]any{"path": path, "error": err.Error()})
		return
	}
	if info.IsDir() {
		return
	}

	hash, err := HashFile(path)
	if err != nil {
		w.sink.Warn("hash failed", map[string]any{"path": path, "error": err.Error()})
		return
	}

	// IOC check runs before the approval lookup so that known-bad hashes
	// receive a higher-priority, named alert rather than a generic one.
	var iocMatches []ioc.Indicator
	if w.iocDB != nil {
		iocMatches = w.iocDB.Match(path, hash)
	}

	approved, err := w.store.IsApproved(path, hash)
	if err != nil {
		w.sink.Warn("approval lookup failed", map[string]any{"path": path, "error": err.Error()})
		return
	}

	if approved {
		_ = w.store.RecordEvent(path, hash, "approved-change", op)
		w.sink.Info("change matches approved baseline", map[string]any{
			"path":   path,
			"sha256": hash,
		})
		return
	}

	if len(iocMatches) > 0 {
		for _, m := range iocMatches {
			_ = w.store.RecordIOCEvent(path, hash, op, m.ID)
			w.sink.Alert("IOC match: known threat indicator detected", map[string]any{
				"path":        path,
				"sha256":      hash,
				"ioc_id":      m.ID,
				"severity":    string(m.Severity),
				"description": m.Description,
				"op":          op,
			})
		}
		return
	}

	_ = w.store.RecordEvent(path, hash, "unapproved-change", op)
	w.sink.Alert("unapproved change to Claude Code settings", map[string]any{
		"path":   path,
		"sha256": hash,
		"op":     op,
		"hint":   "If intentional, run: ccguard approve " + path,
	})
}
