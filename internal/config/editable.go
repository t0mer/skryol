package config

// This file defines the single source of truth for which configuration keys are
// editable at runtime through the settings UI/API. Every consumer — the YAML
// merge writer (writer.go), the precedence-lock detector (source.go), and the
// settings service — derives its behaviour from EditableKeys so the whitelist
// can never drift between them.
//
// Secrets and infrastructure keys (crypto.encryption_key, auth.session_secret,
// auth.password, database.path, data.dir) are deliberately absent: they must
// never be written to the YAML file from the UI.

// ApplyClass describes how a saved key reaches the running process.
type ApplyClass int

const (
	// ApplyHot means the value is pushed into the live process immediately.
	ApplyHot ApplyClass = iota
	// ApplyRestart means the value is persisted to YAML but only takes effect
	// after a restart (it cannot be safely rebound in-process).
	ApplyRestart
)

// Kind is the value type of an editable key, used to coerce JSON input and to
// emit correctly-typed YAML scalars.
type Kind int

const (
	KindString Kind = iota
	KindInt
	KindFloat
	KindBool
)

// EditableKey describes one runtime-editable configuration key.
type EditableKey struct {
	// Key is the canonical dotted path (e.g. "server.port"). Its segments are
	// the nesting used both in YAML and for the env-var mapping.
	Key string
	// Flag is the pflag name that can pin this key above YAML, or "" if none.
	Flag string
	// Apply is how a change reaches the running process.
	Apply ApplyClass
	// Kind is the value type.
	Kind Kind
}

// EditableKeys is the authoritative registry of runtime-editable keys.
var EditableKeys = []EditableKey{
	{Key: "server.port", Flag: "server.port", Apply: ApplyRestart, Kind: KindInt},
	{Key: "server.address", Flag: "server.address", Apply: ApplyRestart, Kind: KindString},
	{Key: "server.base_url", Flag: "", Apply: ApplyRestart, Kind: KindString},
	{Key: "server.enable_cors", Flag: "", Apply: ApplyRestart, Kind: KindBool},

	{Key: "log.level", Flag: "log.level", Apply: ApplyHot, Kind: KindString},
	{Key: "log.format", Flag: "log.format", Apply: ApplyRestart, Kind: KindString},

	{Key: "scanner.schedule", Flag: "scanner.schedule", Apply: ApplyHot, Kind: KindString},
	{Key: "scanner.max_hosts_per_asset", Flag: "", Apply: ApplyHot, Kind: KindInt},
	{Key: "scanner.max_concurrency", Flag: "", Apply: ApplyHot, Kind: KindInt},
	{Key: "scanner.retention_days", Flag: "", Apply: ApplyHot, Kind: KindInt},
	{Key: "scanner.rescan_timeout_seconds", Flag: "", Apply: ApplyHot, Kind: KindInt},

	{Key: "shodan.base_url", Flag: "", Apply: ApplyRestart, Kind: KindString},
	{Key: "shodan.requests_per_second", Flag: "", Apply: ApplyRestart, Kind: KindFloat},
	{Key: "shodan.max_retries", Flag: "", Apply: ApplyRestart, Kind: KindInt},
	{Key: "shodan.timeout_seconds", Flag: "", Apply: ApplyRestart, Kind: KindInt},

	{Key: "auth.enabled", Flag: "auth.enabled", Apply: ApplyHot, Kind: KindBool},
	{Key: "auth.username", Flag: "", Apply: ApplyHot, Kind: KindString},
	{Key: "auth.guard_metrics", Flag: "", Apply: ApplyHot, Kind: KindBool},
}

// EditableKeyFor returns the registry entry for a dotted key.
func EditableKeyFor(key string) (EditableKey, bool) { return editableKey(key) }

// EnvName maps a canonical dotted key to its SKRYOL_ environment-variable name:
// upper-case the key and replace "." with "_". For example server.port becomes
// SKRYOL_SERVER_PORT.
func EnvName(key string) string {
	out := make([]byte, 0, len(key)+len(envPrefix)+1)
	out = append(out, envPrefix...)
	out = append(out, '_')
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c == '.':
			out = append(out, '_')
		case c >= 'a' && c <= 'z':
			out = append(out, c-32)
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

const envPrefix = "SKRYOL"

// editableKey returns the registry entry for a dotted key, if present.
func editableKey(key string) (EditableKey, bool) {
	for _, e := range EditableKeys {
		if e.Key == key {
			return e, true
		}
	}
	return EditableKey{}, false
}
