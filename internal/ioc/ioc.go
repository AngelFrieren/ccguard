// Package ioc implements Layer 3 of ccguard's 4-layer detection architecture:
// IOC (Indicator of Compromise) matching against known threat indicators.
//
// IOCs are loaded from YAML files and matched against file paths and SHA-256
// hashes observed during hash integrity monitoring. A match indicates that a
// detected change corresponds to a known threat campaign, warranting a
// higher-priority alert than a generic unapproved change.
package ioc

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Severity classifies an IOC's threat level.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Match describes how an Indicator is detected.
type Match struct {
	// Kind is the detection mechanism. Supported values:
	//   "file_sha256"    — exact SHA-256 hash comparison
	//   "file_path_glob" — glob pattern match against the file path
	// Unknown kinds are logged and skipped; they do not cause load errors.
	Kind   string   `yaml:"kind"`
	Values []string `yaml:"values"`
}

// Indicator is a single IOC entry describing a known threat signal.
type Indicator struct {
	ID          string   `yaml:"id"`
	Severity    Severity `yaml:"severity"`
	Description string   `yaml:"description"`
	References  []string `yaml:"references,omitempty"`
	Match       Match    `yaml:"match"`
}

// iocFile is the top-level YAML document structure.
type iocFile struct {
	Version    int         `yaml:"version"`
	Indicators []Indicator `yaml:"indicators"`
}

// DB holds a set of loaded indicators ready for matching.
type DB struct {
	indicators []Indicator
}

// Len returns the number of loaded indicators.
func (db *DB) Len() int { return len(db.indicators) }

// All returns a copy of all loaded indicators.
func (db *DB) All() []Indicator {
	out := make([]Indicator, len(db.indicators))
	copy(out, db.indicators)
	return out
}

// LoadDir loads all *.yaml files found under dir (recursively) and returns a
// DB containing their combined indicators. Files that fail to parse are logged
// as warnings and skipped so one malformed file cannot block the rest.
// If dir does not exist, an empty DB is returned without error.
func LoadDir(dir string) (*DB, error) {
	db := &DB{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		inds, err := loadFile(path)
		if err != nil {
			log.Printf("ioc: skipping %s: %v", path, err)
			return nil
		}
		db.indicators = append(db.indicators, inds...)
		return nil
	})
	if err != nil && errors.Is(err, fs.ErrNotExist) {
		return db, nil
	}
	return db, err
}

func loadFile(path string) ([]Indicator, error) {
	f, err := os.Open(path) // #nosec G304 -- path is a user-configured IOC database file
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	return parseIOCFile(f)
}

func parseIOCFile(r io.Reader) ([]Indicator, error) {
	var file iocFile
	if err := yaml.NewDecoder(r).Decode(&file); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	return file.Indicators, nil
}

// Match returns all indicators that match the given file path and sha256.
//
// For "file_sha256" indicators, sha256 is compared against each listed value.
// For "file_path_glob" indicators, path is matched against each glob pattern;
// ** matches zero or more path components.
// Indicators with unknown match kinds emit a log warning and are skipped.
func (db *DB) Match(path, sha256 string) []Indicator {
	var matches []Indicator
	for _, ind := range db.indicators {
		if matchIndicator(ind, path, sha256) {
			matches = append(matches, ind)
		}
	}
	return matches
}

func matchIndicator(ind Indicator, path, sha256 string) bool {
	switch ind.Match.Kind {
	case "file_sha256":
		for _, v := range ind.Match.Values {
			if v == sha256 {
				return true
			}
		}
	case "file_path_glob":
		norm := filepath.ToSlash(path)
		for _, pattern := range ind.Match.Values {
			if globMatch(pattern, norm) {
				return true
			}
		}
	default:
		log.Printf("ioc: indicator %s: unknown match kind %q, skipping", ind.ID, ind.Match.Kind)
	}
	return false
}

// globMatch matches path against pattern using "/" as the separator.
// "**" matches zero or more path components; other components follow
// filepath.Match semantics (* matches any non-separator sequence, ? matches
// one non-separator character, [...] matches a character class).
func globMatch(pattern, path string) bool {
	return globMatchParts(strings.Split(pattern, "/"), strings.Split(path, "/"))
}

func globMatchParts(pat, path []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			pat = pat[1:]
			// ** matches zero or more path components; try each split point.
			for i := 0; i <= len(path); i++ {
				if globMatchParts(pat, path[i:]) {
					return true
				}
			}
			return false
		}
		if len(path) == 0 {
			return false
		}
		ok, err := filepath.Match(pat[0], path[0])
		if err != nil || !ok {
			return false
		}
		pat = pat[1:]
		path = path[1:]
	}
	return len(path) == 0
}
