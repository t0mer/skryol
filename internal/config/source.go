package config

import (
	"os"

	"github.com/spf13/pflag"
)

// Source records where the running configuration came from, so the settings
// layer can tell which editable keys are pinned above the YAML file and must be
// shown read-only (writing them would silently no-op).
type Source struct {
	// FileUsed is the resolved YAML config path (may not yet exist on disk).
	FileUsed string
	// Locked maps an editable key to the reason it outranks YAML: "flag" or
	// "env". Keys absent from the map are freely editable through YAML.
	Locked map[string]string
}

// detectSource computes the precedence locks for every editable key. Precedence
// is flags > env > YAML, so a changed flag wins over an env var, which wins over
// the file. flags may be nil (no flag set was parsed).
func detectSource(flags *pflag.FlagSet, fileUsed string) *Source {
	locked := make(map[string]string)
	for _, e := range EditableKeys {
		if e.Flag != "" && flags != nil {
			if f := flags.Lookup(e.Flag); f != nil && f.Changed {
				locked[e.Key] = "flag"
				continue
			}
		}
		if _, ok := os.LookupEnv(EnvName(e.Key)); ok {
			locked[e.Key] = "env"
		}
	}
	return &Source{FileUsed: fileUsed, Locked: locked}
}
