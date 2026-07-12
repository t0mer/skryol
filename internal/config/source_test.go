package config

import (
	"testing"

	"github.com/spf13/pflag"
)

func TestEnvName(t *testing.T) {
	cases := map[string]string{
		"server.port":                 "SKRYOL_SERVER_PORT",
		"scanner.max_hosts_per_asset": "SKRYOL_SCANNER_MAX_HOSTS_PER_ASSET",
		"auth.guard_metrics":          "SKRYOL_AUTH_GUARD_METRICS",
	}
	for key, want := range cases {
		if got := EnvName(key); got != want {
			t.Errorf("EnvName(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestDetectSourceEnvLock(t *testing.T) {
	t.Setenv("SKRYOL_SERVER_PORT", "9090")
	src := detectSource(nil, "config.yaml")
	if src.Locked["server.port"] != "env" {
		t.Fatalf("server.port lock = %q, want env", src.Locked["server.port"])
	}
	if _, ok := src.Locked["auth.username"]; ok {
		t.Fatalf("auth.username should be unlocked, got %q", src.Locked["auth.username"])
	}
}

func TestDetectSourceFlagBeatsEnv(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	DefineFlags(fs)
	if err := fs.Parse([]string{"--server.port", "5000"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SKRYOL_SERVER_PORT", "9090") // env also set; flag must win

	src := detectSource(fs, "config.yaml")
	if src.Locked["server.port"] != "flag" {
		t.Fatalf("server.port lock = %q, want flag (flag outranks env)", src.Locked["server.port"])
	}
}

func TestDetectSourceUnchangedFlagNotLocked(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	DefineFlags(fs)
	if err := fs.Parse([]string{}); err != nil {
		t.Fatal(err)
	}
	src := detectSource(fs, "config.yaml")
	if _, ok := src.Locked["server.port"]; ok {
		t.Fatalf("unchanged flag should not lock server.port")
	}
}
