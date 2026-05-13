// Package hashwatch implements Layer 1 of ccguard: SHA-256 based file
// integrity monitoring for Claude Code configuration files.
package hashwatch

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// MonitoredFiles is the set of filenames within a .claude directory that
// ccguard treats as sensitive. Phase 1 monitors settings.json — additional
// files will be added as the Claude Code attack surface expands.
var MonitoredFiles = map[string]struct{}{
	"settings.json":       {},
	"settings.local.json": {},
}

// IsMonitored reports whether the given filename should be hash-monitored.
func IsMonitored(filename string) bool {
	_, ok := MonitoredFiles[filepath.Base(filename)]
	return ok
}

// HashFile computes the SHA-256 of a file's contents and returns it as a
// lowercase hex string.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ResolveTargets expands the configured watch paths into a concrete list of
// monitored file paths that currently exist on disk.
//
// Each path may be either a file (returned as-is if monitored) or a
// directory (scanned non-recursively for monitored filenames).
func ResolveTargets(paths []string) ([]string, error) {
	var targets []string
	seen := make(map[string]struct{})

	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, err
		}

		info, err := os.Stat(abs)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}

		if !info.IsDir() {
			if IsMonitored(abs) {
				if _, ok := seen[abs]; !ok {
					targets = append(targets, abs)
					seen[abs] = struct{}{}
				}
			}
			continue
		}

		entries, err := os.ReadDir(abs)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if !IsMonitored(e.Name()) {
				continue
			}
			full := filepath.Join(abs, e.Name())
			if _, ok := seen[full]; !ok {
				targets = append(targets, full)
				seen[full] = struct{}{}
			}
		}
	}

	return targets, nil
}

// shouldWatchDir reports whether a directory path should receive an
// fsnotify watch. We watch the .claude directory itself rather than each
// file so that creations and atomic renames are caught.
func shouldWatchDir(path string) bool {
	return strings.HasSuffix(filepath.Clean(path), string(filepath.Separator)+".claude") ||
		filepath.Base(path) == ".claude"
}
