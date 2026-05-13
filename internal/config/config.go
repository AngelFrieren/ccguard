// Package config resolves ccguard configuration paths and settings.
//
// Phase 1 keeps config minimal — most behavior is governed by sensible
// defaults. Later phases will load YAML from $XDG_CONFIG_HOME/ccguard/config.yaml.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds resolved runtime paths and watch targets.
type Config struct {
	// DataDir is where the SQLite database and snapshots live.
	DataDir string

	// WatchPaths are absolute paths to files or directories to monitor.
	// Phase 1 default: ~/.claude/settings.json and ./.claude/settings.json.
	WatchPaths []string

	// IOCDir is the directory from which IOC YAML files are loaded (Phase 2).
	// Default: $XDG_CONFIG_HOME/ccguard/iocs or ~/.config/ccguard/iocs.
	IOCDir string
}

// DBPath returns the SQLite database file path inside DataDir.
func (c *Config) DBPath() string {
	return filepath.Join(c.DataDir, "ccguard.db")
}

// Load resolves config, applying defaults when explicit paths are empty.
//
// configPath is reserved for a future YAML config file and is accepted but not
// yet consulted.
func Load(configPath, dataDirOverride, iocDirOverride string) (*Config, error) {
	_ = configPath // reserved for future YAML config

	dataDir := dataDirOverride
	if dataDir == "" {
		d, err := defaultDataDir()
		if err != nil {
			return nil, err
		}
		dataDir = d
	}

	iocDir := iocDirOverride
	if iocDir == "" {
		d, err := defaultIOCDir()
		if err != nil {
			return nil, err
		}
		iocDir = d
	}

	watch, err := defaultWatchPaths()
	if err != nil {
		return nil, err
	}

	return &Config{
		DataDir:    dataDir,
		WatchPaths: watch,
		IOCDir:     iocDir,
	}, nil
}

func defaultIOCDir() (string, error) {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "ccguard", "iocs"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "ccguard", "iocs"), nil
}

func defaultDataDir() (string, error) {
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "ccguard"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".local", "share", "ccguard"), nil
}

func defaultWatchPaths() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home dir: %w", err)
	}

	paths := []string{
		filepath.Join(home, ".claude"),
	}

	// Project-level .claude only if it exists in the current working directory.
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	projectClaude := filepath.Join(cwd, ".claude")
	if info, err := os.Stat(projectClaude); err == nil && info.IsDir() {
		paths = append(paths, projectClaude)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	return paths, nil
}
