// Package config wires runtime configuration for Skryol.
//
// Precedence, highest to lowest: command-line flags > environment variables
// (prefixed SKRYOL_) > YAML config file > built-in defaults. Nested keys map to
// environment variables by upper-casing and replacing "." with "_": for example
// server.port becomes SKRYOL_SERVER_PORT.
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// Config is the fully-resolved application configuration.
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Log      LogConfig      `mapstructure:"log"`
	Database DatabaseConfig `mapstructure:"database"`
	Crypto   CryptoConfig   `mapstructure:"crypto"`
	Shodan   ShodanConfig   `mapstructure:"shodan"`
	Scanner  ScannerConfig  `mapstructure:"scanner"`
	Auth     AuthConfig     `mapstructure:"auth"`
	Data     DataConfig     `mapstructure:"data"`

	// Source records the config file path and precedence locks. It is populated
	// by Load and ignored by the YAML/env unmarshaller.
	Source *Source `mapstructure:"-"`
}

// ServerConfig controls the HTTP listener.
type ServerConfig struct {
	Port       int    `mapstructure:"port"`
	Address    string `mapstructure:"address"`
	BaseURL    string `mapstructure:"base_url"`
	EnableCORS bool   `mapstructure:"enable_cors"`
}

// LogConfig controls structured logging.
type LogConfig struct {
	Level  string `mapstructure:"level"`  // debug | info | warning | error
	Format string `mapstructure:"format"` // json | text
}

// DatabaseConfig points at the SQLite database file.
type DatabaseConfig struct {
	Path string `mapstructure:"path"`
}

// DataConfig holds the on-disk data directory (screenshots, etc.).
type DataConfig struct {
	Dir string `mapstructure:"dir"`
}

// CryptoConfig carries the at-rest encryption key. The key is operator-owned
// infrastructure and provisioned via SKRYOL_CRYPTO_ENCRYPTION_KEY.
type CryptoConfig struct {
	EncryptionKey string `mapstructure:"encryption_key"`
}

// ShodanConfig tunes the shared Shodan client.
type ShodanConfig struct {
	BaseURL           string  `mapstructure:"base_url"`
	RequestsPerSecond float64 `mapstructure:"requests_per_second"`
	MaxRetries        int     `mapstructure:"max_retries"`
	TimeoutSeconds    int     `mapstructure:"timeout_seconds"`
}

// ScannerConfig governs the scan orchestrator and its guardrails.
type ScannerConfig struct {
	Schedule         string `mapstructure:"schedule"`
	MaxHostsPerAsset int    `mapstructure:"max_hosts_per_asset"`
	MaxConcurrency   int    `mapstructure:"max_concurrency"`
	RetentionDays    int    `mapstructure:"retention_days"`
	RescanTimeoutSec int    `mapstructure:"rescan_timeout_seconds"`
}

// AuthConfig toggles and configures optional UI/API authentication.
type AuthConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	Username      string `mapstructure:"username"`
	Password      string `mapstructure:"password"` // bootstrap password, first run only
	SessionSecret string `mapstructure:"session_secret"`
	GuardMetrics  bool   `mapstructure:"guard_metrics"`
}

// Load resolves configuration from flags, environment, and an optional YAML
// file, applying defaults last. flags must already be parsed by the caller.
func Load(flags *pflag.FlagSet) (*Config, error) {
	v := viper.New()

	setDefaults(v)

	v.SetEnvPrefix("SKRYOL")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if flags != nil {
		if err := v.BindPFlags(flags); err != nil {
			return nil, fmt.Errorf("binding flags: %w", err)
		}
	}

	// Config file path: flag --config, else env, else conventional locations.
	// explicitPath is the operator-chosen path (used even if it does not exist
	// yet, so the settings layer knows where to persist edits).
	var explicitPath string
	if flags != nil {
		if cf, _ := flags.GetString("config"); cf != "" {
			explicitPath = cf
		}
	}
	if explicitPath == "" && v.GetString("config") != "" {
		explicitPath = v.GetString("config")
	}
	if explicitPath != "" {
		v.SetConfigFile(explicitPath)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("/etc/skryol")
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// A genuinely missing explicit file is also tolerated; only surface
			// parse errors.
			if !strings.Contains(err.Error(), "no such file") {
				return nil, fmt.Errorf("reading config: %w", err)
			}
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}
	cfg.normalize()

	// Resolve the file the settings layer writes back to: the one viper read,
	// else the explicit path (even if absent), else a default in the working
	// directory. Precedence locks are captured from flags and the environment.
	fileUsed := v.ConfigFileUsed()
	if fileUsed == "" {
		fileUsed = explicitPath
	}
	if fileUsed == "" {
		fileUsed = "config.yaml"
	}
	cfg.Source = detectSource(flags, fileUsed)
	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.address", "0.0.0.0")
	v.SetDefault("server.base_url", "")
	v.SetDefault("server.enable_cors", false)

	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")

	v.SetDefault("database.path", "/data/skryol.db")
	v.SetDefault("data.dir", "/data")

	v.SetDefault("crypto.encryption_key", "")

	v.SetDefault("shodan.base_url", "https://api.shodan.io")
	v.SetDefault("shodan.requests_per_second", 1.0)
	v.SetDefault("shodan.max_retries", 4)
	v.SetDefault("shodan.timeout_seconds", 30)

	v.SetDefault("scanner.schedule", "0 3 * * *")
	v.SetDefault("scanner.max_hosts_per_asset", 256)
	v.SetDefault("scanner.max_concurrency", 4)
	v.SetDefault("scanner.retention_days", 0)
	v.SetDefault("scanner.rescan_timeout_seconds", 300)

	v.SetDefault("auth.enabled", false)
	v.SetDefault("auth.username", "admin")
	v.SetDefault("auth.password", "")
	v.SetDefault("auth.session_secret", "")
	// Secure by default: when auth is enabled, /metrics (which carries asset
	// identifiers and scores in its labels) is guarded too. Operators scraping
	// over a trusted network can opt out with auth.guard_metrics=false.
	v.SetDefault("auth.guard_metrics", true)
}

func (c *Config) normalize() {
	c.Log.Level = strings.ToLower(strings.TrimSpace(c.Log.Level))
	c.Log.Format = strings.ToLower(strings.TrimSpace(c.Log.Format))
	if c.Server.Port == 0 {
		c.Server.Port = 8080
	}
}

// DefineFlags registers the standard command-line flags onto fs and returns it.
// Env-var overrides use the SKRYOL_ prefix (see package doc).
func DefineFlags(fs *pflag.FlagSet) {
	fs.String("config", "", "Path to YAML config file")
	fs.Int("server.port", 8080, "HTTP listen port")
	fs.String("server.address", "0.0.0.0", "HTTP listen address")
	fs.String("log.level", "info", "Log level: debug|info|warning|error")
	fs.String("log.format", "json", "Log format: json|text")
	fs.String("database.path", "/data/skryol.db", "SQLite database path")
	fs.String("data.dir", "/data", "Data directory for screenshots and runtime files")
	fs.String("scanner.schedule", "0 3 * * *", "Cron schedule for the daily scan batch")
	fs.Bool("auth.enabled", false, "Require authentication for the UI/API")
}

// Validate checks invariants that must hold before the app can start.
func (c *Config) Validate() error {
	switch c.Log.Level {
	case "debug", "info", "warning", "warn", "error":
	default:
		return fmt.Errorf("invalid log.level %q", c.Log.Level)
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		return fmt.Errorf("invalid log.format %q", c.Log.Format)
	}
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server.port %d", c.Server.Port)
	}
	if c.Database.Path == "" {
		return fmt.Errorf("database.path must not be empty")
	}
	return nil
}
