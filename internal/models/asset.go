// Package models holds Skryol's core domain types and their validation.
package models

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// AssetType enumerates the kinds of monitored asset.
type AssetType string

const (
	AssetIP     AssetType = "ip"
	AssetFQDN   AssetType = "fqdn"
	AssetDomain AssetType = "domain"
	AssetCIDR   AssetType = "cidr"
)

// Asset is a monitored external asset.
type Asset struct {
	ID        string    `json:"id"`
	Type      AssetType `json:"type"`
	Value     string    `json:"value"`
	Label     string    `json:"label"`
	Notes     string    `json:"notes"`
	Enabled   bool      `json:"enabled"`
	Rescan    bool      `json:"rescan"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// hostnameRE matches a DNS hostname/domain label sequence. It intentionally
// rejects leading/trailing dots and empty labels.
var hostnameRE = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$`)

// ValidateType checks the asset type is one of the known kinds.
func ValidateType(t AssetType) error {
	switch t {
	case AssetIP, AssetFQDN, AssetDomain, AssetCIDR:
		return nil
	default:
		return fmt.Errorf("invalid asset type %q", t)
	}
}

// NormalizeAssetValue validates and canonicalizes an asset value for its type.
// It returns the normalized value or an error describing the rejection.
func NormalizeAssetValue(t AssetType, value string) (string, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return "", fmt.Errorf("asset value must not be empty")
	}
	switch t {
	case AssetIP:
		addr, err := netip.ParseAddr(v)
		if err != nil {
			return "", fmt.Errorf("invalid IP address %q: %w", value, err)
		}
		if addr.Zone() != "" {
			return "", fmt.Errorf("IP address must not carry a zone: %q", value)
		}
		return addr.String(), nil

	case AssetCIDR:
		prefix, err := netip.ParsePrefix(v)
		if err != nil {
			return "", fmt.Errorf("invalid CIDR %q: %w", value, err)
		}
		// Canonicalize to the masked network address.
		return prefix.Masked().String(), nil

	case AssetFQDN, AssetDomain:
		host := strings.ToLower(strings.TrimSuffix(v, "."))
		if strings.Contains(host, "/") || strings.Contains(host, " ") {
			return "", fmt.Errorf("invalid hostname %q", value)
		}
		if len(host) > 253 {
			return "", fmt.Errorf("hostname too long: %q", value)
		}
		if !hostnameRE.MatchString(host) {
			return "", fmt.Errorf("invalid %s %q", t, value)
		}
		return host, nil

	default:
		return "", fmt.Errorf("invalid asset type %q", t)
	}
}

// Validate checks the asset is internally consistent, normalizing Value.
func (a *Asset) Validate() error {
	if err := ValidateType(a.Type); err != nil {
		return err
	}
	normalized, err := NormalizeAssetValue(a.Type, a.Value)
	if err != nil {
		return err
	}
	a.Value = normalized
	if len(a.Label) > 200 {
		return fmt.Errorf("label too long")
	}
	return nil
}
