package storage

import (
	"path/filepath"
	"reflect"
	"testing"
)

type fixture struct {
	Name  string   `yaml:"name"`
	Count int      `yaml:"count"`
	Tags  []string `yaml:"tags"`
}

func TestWriteReadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.yaml")
	want := fixture{Name: "create-user", Count: 3, Tags: []string{"a", "b"}}

	if err := WriteYAML(path, want); err != nil {
		t.Fatalf("WriteYAML: %v", err)
	}

	var got fixture
	if err := ReadYAML(path, &got); err != nil {
		t.Fatalf("ReadYAML: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestReadYAMLMissingFile(t *testing.T) {
	var got fixture
	if err := ReadYAML(filepath.Join(t.TempDir(), "nope.yaml"), &got); err == nil {
		t.Fatal("ReadYAML on a missing file should error")
	}
}
