package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	yaml "go.yaml.in/yaml/v3"
)

// WriteEditable merges the given key/value pairs into the YAML file at path,
// preserving every other key and comment already present, and writes the result
// atomically (temp file + rename, mode 0600). Only keys in the editable registry
// are accepted; any other key is rejected so secrets/infrastructure settings can
// never be written from the settings layer.
//
// values is keyed by canonical dotted path (e.g. "server.port"). A missing file
// is created; a missing directory is an error (the caller resolves a writable
// path first).
func WriteEditable(path string, values map[string]any) error {
	if path == "" {
		return fmt.Errorf("config file path is empty; cannot persist settings")
	}
	for key := range values {
		if _, ok := editableKey(key); !ok {
			return fmt.Errorf("refusing to write non-editable config key %q", key)
		}
	}

	root, err := loadDocument(path)
	if err != nil {
		return err
	}

	// Deterministic order keeps the diff stable across saves.
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		setPath(root, splitKey(k), values[k])
	}

	out, err := yaml.Marshal(root)
	if err != nil {
		return fmt.Errorf("marshalling config: %w", err)
	}
	return atomicWrite(path, out)
}

// loadDocument reads path into a mapping node, or returns an empty mapping when
// the file does not exist yet.
func loadDocument(path string) (*yaml.Node, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}, nil
		}
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	// A document node wraps the root mapping; unwrap it. An empty file yields a
	// zero-value node with no content.
	if doc.Kind == yaml.DocumentNode {
		if len(doc.Content) == 0 {
			return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}, nil
		}
		return doc.Content[0], nil
	}
	if doc.Kind == 0 {
		return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}, nil
	}
	return &doc, nil
}

// setPath sets a scalar value at the nested path within a mapping node, creating
// intermediate mappings as needed and overwriting an existing leaf in place
// (which preserves any head/line comment attached to the key node).
func setPath(mapping *yaml.Node, path []string, value any) {
	if mapping.Kind != yaml.MappingNode {
		mapping.Kind = yaml.MappingNode
		mapping.Tag = "!!map"
		mapping.Content = nil
	}
	head := path[0]
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		keyNode := mapping.Content[i]
		if keyNode.Value == head {
			valNode := mapping.Content[i+1]
			if len(path) == 1 {
				assignScalar(valNode, value)
			} else {
				setPath(valNode, path[1:], value)
			}
			return
		}
	}
	// Key not present: append a new key node and value subtree.
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: head}
	var valNode *yaml.Node
	if len(path) == 1 {
		valNode = &yaml.Node{}
		assignScalar(valNode, value)
	} else {
		valNode = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		setPath(valNode, path[1:], value)
	}
	mapping.Content = append(mapping.Content, keyNode, valNode)
}

// assignScalar rewrites node in place to represent value with the correct YAML
// tag, so ints, bools, floats, and strings round-trip as native scalars.
func assignScalar(node *yaml.Node, value any) {
	node.Kind = yaml.ScalarNode
	node.Content = nil
	switch v := value.(type) {
	case bool:
		node.Tag = "!!bool"
		if v {
			node.Value = "true"
		} else {
			node.Value = "false"
		}
	case int:
		node.Tag = "!!int"
		node.Value = fmt.Sprintf("%d", v)
	case int64:
		node.Tag = "!!int"
		node.Value = fmt.Sprintf("%d", v)
	case float64:
		node.Tag = "!!float"
		node.Value = trimFloat(v)
	case string:
		node.Tag = "!!str"
		node.Value = v
		node.Style = 0
	default:
		node.Tag = "!!str"
		node.Value = fmt.Sprintf("%v", v)
	}
}

// trimFloat formats a float without a trailing ".0"-only noise while keeping a
// decimal point for whole numbers so the value stays a float in YAML.
func trimFloat(f float64) string {
	s := fmt.Sprintf("%g", f)
	// Ensure it reads as a float (e.g. "1" -> "1.0") so re-parsing keeps type.
	hasDot := false
	hasExp := false
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			hasDot = true
		}
		if s[i] == 'e' || s[i] == 'E' {
			hasExp = true
		}
	}
	if !hasDot && !hasExp {
		s += ".0"
	}
	return s
}

func splitKey(key string) []string {
	parts := make([]string, 0, 4)
	start := 0
	for i := 0; i < len(key); i++ {
		if key[i] == '.' {
			parts = append(parts, key[start:i])
			start = i + 1
		}
	}
	parts = append(parts, key[start:])
	return parts
}

// atomicWrite writes data to a sibling temp file and renames it over path so a
// crash mid-write can never leave a truncated config.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".skryol-config-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp config: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing temp config: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replacing config %s: %w", path, err)
	}
	return nil
}
