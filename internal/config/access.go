package config

import (
	"fmt"
	"strings"
)

// Coerce converts a raw value (typically decoded from JSON, where numbers arrive
// as float64) into the Go type expected for the given editable key. It returns
// an error for unknown keys or values that cannot represent the key's kind.
func Coerce(key string, raw any) (any, error) {
	ek, ok := editableKey(key)
	if !ok {
		return nil, fmt.Errorf("unknown editable key %q", key)
	}
	switch ek.Kind {
	case KindString:
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("%s must be a string", key)
		}
		return strings.TrimSpace(s), nil
	case KindBool:
		b, ok := raw.(bool)
		if !ok {
			return nil, fmt.Errorf("%s must be a boolean", key)
		}
		return b, nil
	case KindInt:
		switch v := raw.(type) {
		case float64:
			if v != float64(int(v)) {
				return nil, fmt.Errorf("%s must be a whole number", key)
			}
			return int(v), nil
		case int:
			return v, nil
		default:
			return nil, fmt.Errorf("%s must be a number", key)
		}
	case KindFloat:
		switch v := raw.(type) {
		case float64:
			return v, nil
		case int:
			return float64(v), nil
		default:
			return nil, fmt.Errorf("%s must be a number", key)
		}
	default:
		return nil, fmt.Errorf("unsupported kind for %q", key)
	}
}

// GetEditable returns the current value of an editable key from the config.
func (c *Config) GetEditable(key string) (any, bool) {
	switch key {
	case "server.port":
		return c.Server.Port, true
	case "server.address":
		return c.Server.Address, true
	case "server.base_url":
		return c.Server.BaseURL, true
	case "server.enable_cors":
		return c.Server.EnableCORS, true
	case "log.level":
		return c.Log.Level, true
	case "log.format":
		return c.Log.Format, true
	case "scanner.schedule":
		return c.Scanner.Schedule, true
	case "scanner.max_hosts_per_asset":
		return c.Scanner.MaxHostsPerAsset, true
	case "scanner.max_concurrency":
		return c.Scanner.MaxConcurrency, true
	case "scanner.retention_days":
		return c.Scanner.RetentionDays, true
	case "scanner.rescan_timeout_seconds":
		return c.Scanner.RescanTimeoutSec, true
	case "shodan.base_url":
		return c.Shodan.BaseURL, true
	case "shodan.requests_per_second":
		return c.Shodan.RequestsPerSecond, true
	case "shodan.max_retries":
		return c.Shodan.MaxRetries, true
	case "shodan.timeout_seconds":
		return c.Shodan.TimeoutSeconds, true
	case "auth.enabled":
		return c.Auth.Enabled, true
	case "auth.username":
		return c.Auth.Username, true
	case "auth.guard_metrics":
		return c.Auth.GuardMetrics, true
	default:
		return nil, false
	}
}

// SetEditable writes a coerced value into the config field for an editable key.
// val must already be of the key's Go type (see Coerce).
func (c *Config) SetEditable(key string, val any) error {
	switch key {
	case "server.port":
		c.Server.Port = val.(int)
	case "server.address":
		c.Server.Address = val.(string)
	case "server.base_url":
		c.Server.BaseURL = val.(string)
	case "server.enable_cors":
		c.Server.EnableCORS = val.(bool)
	case "log.level":
		c.Log.Level = val.(string)
	case "log.format":
		c.Log.Format = val.(string)
	case "scanner.schedule":
		c.Scanner.Schedule = val.(string)
	case "scanner.max_hosts_per_asset":
		c.Scanner.MaxHostsPerAsset = val.(int)
	case "scanner.max_concurrency":
		c.Scanner.MaxConcurrency = val.(int)
	case "scanner.retention_days":
		c.Scanner.RetentionDays = val.(int)
	case "scanner.rescan_timeout_seconds":
		c.Scanner.RescanTimeoutSec = val.(int)
	case "shodan.base_url":
		c.Shodan.BaseURL = val.(string)
	case "shodan.requests_per_second":
		c.Shodan.RequestsPerSecond = val.(float64)
	case "shodan.max_retries":
		c.Shodan.MaxRetries = val.(int)
	case "shodan.timeout_seconds":
		c.Shodan.TimeoutSeconds = val.(int)
	case "auth.enabled":
		c.Auth.Enabled = val.(bool)
	case "auth.username":
		c.Auth.Username = val.(string)
	case "auth.guard_metrics":
		c.Auth.GuardMetrics = val.(bool)
	default:
		return fmt.Errorf("unknown editable key %q", key)
	}
	return nil
}
