package config

import (
	"os"
	"path/filepath"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

func readYAML(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return m
}

func TestWriteEditableCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := WriteEditable(path, map[string]any{
		"server.port":  9090,
		"auth.enabled": true,
	}); err != nil {
		t.Fatalf("write: %v", err)
	}
	m := readYAML(t, path)
	server, ok := m["server"].(map[string]any)
	if !ok {
		t.Fatalf("server section missing: %#v", m)
	}
	if server["port"] != 9090 {
		t.Fatalf("server.port = %v, want 9090", server["port"])
	}
	auth, ok := m["auth"].(map[string]any)
	if !ok || auth["enabled"] != true {
		t.Fatalf("auth.enabled = %#v, want true", m["auth"])
	}
}

func TestWriteEditablePreservesUntouchedKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	seed := []byte(`# top comment
server:
  port: 8080
  address: "0.0.0.0"
crypto:
  encryption_key: "secret-should-survive"
database:
  path: "/data/skryol.db"
`)
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteEditable(path, map[string]any{"server.port": 7070}); err != nil {
		t.Fatalf("write: %v", err)
	}
	m := readYAML(t, path)
	server := m["server"].(map[string]any)
	if server["port"] != 7070 {
		t.Fatalf("server.port = %v, want 7070", server["port"])
	}
	if server["address"] != "0.0.0.0" {
		t.Fatalf("server.address lost: %v", server["address"])
	}
	crypto, ok := m["crypto"].(map[string]any)
	if !ok || crypto["encryption_key"] != "secret-should-survive" {
		t.Fatalf("crypto.encryption_key not preserved: %#v", m["crypto"])
	}
	if db := m["database"].(map[string]any); db["path"] != "/data/skryol.db" {
		t.Fatalf("database.path lost: %v", db["path"])
	}

	// The original comment should survive a node-level merge.
	raw, _ := os.ReadFile(path)
	if !contains(string(raw), "top comment") {
		t.Fatalf("comment not preserved:\n%s", raw)
	}
}

func TestWriteEditableRejectsNonEditableKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	err := WriteEditable(path, map[string]any{"crypto.encryption_key": "leak"})
	if err == nil {
		t.Fatal("expected rejection of non-editable key, got nil")
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Fatal("file should not have been written when a key is rejected")
	}
}

func TestWriteEditableScalarTypes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := WriteEditable(path, map[string]any{
		"shodan.requests_per_second": 2.5,
		"scanner.max_concurrency":    8,
		"server.enable_cors":         true,
		"auth.username":              "operator",
	}); err != nil {
		t.Fatalf("write: %v", err)
	}
	m := readYAML(t, path)
	if v := m["shodan"].(map[string]any)["requests_per_second"]; v != 2.5 {
		t.Fatalf("requests_per_second = %#v (%T), want 2.5 float", v, v)
	}
	if v := m["scanner"].(map[string]any)["max_concurrency"]; v != 8 {
		t.Fatalf("max_concurrency = %#v (%T), want 8 int", v, v)
	}
	if v := m["server"].(map[string]any)["enable_cors"]; v != true {
		t.Fatalf("enable_cors = %#v, want bool true", v)
	}
	if v := m["auth"].(map[string]any)["username"]; v != "operator" {
		t.Fatalf("username = %#v, want operator", v)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
