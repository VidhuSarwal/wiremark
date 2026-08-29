// Package storage is a thin, generic YAML file read/write helper. It
// doesn't know about TestCase or any other project type, so it stays
// reusable and trivially testable.
package storage

import (
	"os"

	"gopkg.in/yaml.v3"
)

// WriteYAML marshals v as YAML and writes it to path.
func WriteYAML(path string, v any) error {
	data, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// ReadYAML reads path and unmarshals it into v.
func ReadYAML(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, v)
}
