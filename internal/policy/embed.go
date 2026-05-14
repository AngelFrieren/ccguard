package policy

import "embed"

//go:embed defaults/default.yaml
var defaultFS embed.FS

// DefaultPoliciesYAML returns the raw bytes of the built-in default policy
// file bundled into the binary at build time.
func DefaultPoliciesYAML() []byte {
	data, _ := defaultFS.ReadFile("defaults/default.yaml")
	return data
}
