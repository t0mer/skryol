// Package backup implements portable export/import of Skryol configuration
// (assets, Shodan keys, notification channels, and alert rules) with a
// three-mode secret strategy:
//
//   - none:         secrets omitted; keys/channels import disabled + need creds.
//   - instance_key: existing ciphertexts carried verbatim with a non-reversible
//     key fingerprint; usable only where the same
//     SKRYOL_CRYPTO_ENCRYPTION_KEY is provisioned.
//   - passphrase:   secrets re-encrypted under an argon2id-derived key so the
//     bundle is portable across instances with different keys.
package backup

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/t0mer/skryol/internal/crypto"
	"github.com/t0mer/skryol/internal/db"
	"github.com/t0mer/skryol/internal/keys"
	"github.com/t0mer/skryol/internal/models"
)

// SecretMode enumerates the export secret strategies.
type SecretMode string

const (
	ModeNone        SecretMode = "none"
	ModeInstanceKey SecretMode = "instance_key"
	ModePassphrase  SecretMode = "passphrase"
)

const bundleVersion = "1"

// Argon2id parameters for passphrase-derived keys.
const (
	kdfTime    = 2
	kdfMemory  = 64 * 1024
	kdfThreads = 4
	kdfKeyLen  = 32
	kdfSaltLen = 16
)

// Bundle is the exported configuration document.
type Bundle struct {
	Version        string        `json:"version"`
	ExportedAt     string        `json:"exported_at"`
	SecretMode     SecretMode    `json:"secret_mode"`
	KeyFingerprint string        `json:"key_fingerprint,omitempty"`
	Salt           string        `json:"salt,omitempty"`
	Assets         []AssetItem   `json:"assets"`
	ShodanKeys     []KeyItem     `json:"shodan_keys"`
	Channels       []ChannelItem `json:"channels"`
	Rules          []RuleItem    `json:"rules"`
}

type AssetItem struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Label   string `json:"label"`
	Notes   string `json:"notes"`
	Enabled bool   `json:"enabled"`
	Rescan  bool   `json:"rescan"`
}

type KeyItem struct {
	Label         string  `json:"label"`
	Enabled       bool    `json:"enabled"`
	RatePerSecond float64 `json:"rate_per_second"`
	Ciphertext    string  `json:"ciphertext,omitempty"`
}

type ChannelItem struct {
	Type       string `json:"type"`
	Label      string `json:"label"`
	Enabled    bool   `json:"enabled"`
	Ciphertext string `json:"ciphertext,omitempty"`
}

type RuleItem struct {
	Scope           string          `json:"scope"`
	AssetType       string          `json:"asset_type,omitempty"`
	AssetValue      string          `json:"asset_value,omitempty"`
	Condition       string          `json:"condition"`
	Params          json.RawMessage `json:"params,omitempty"`
	Enabled         bool            `json:"enabled"`
	CooldownSeconds int             `json:"cooldown_seconds"`
	Severity        string          `json:"severity"`
	Label           string          `json:"label"`
	ChannelLabels   []string        `json:"channel_labels"`
}

// Result summarizes an import.
type Result struct {
	Created map[string]int `json:"created"`
	Updated map[string]int `json:"updated"`
	Skipped map[string]int `json:"skipped"`
	Notes   []string       `json:"notes"`
}

// Service performs export/import.
type Service struct {
	db     *db.DB
	cipher *crypto.Cipher
	keys   *keys.Service
}

// NewService builds the backup service.
func NewService(database *db.DB, cipher *crypto.Cipher, keySvc *keys.Service) *Service {
	return &Service{db: database, cipher: cipher, keys: keySvc}
}

// ExportOptions controls an export.
type ExportOptions struct {
	Mode       SecretMode
	Passphrase string
}

// Export builds a configuration bundle.
func (s *Service) Export(ctx context.Context, opts ExportOptions) (*Bundle, error) {
	if opts.Mode == "" {
		opts.Mode = ModeNone
	}
	b := &Bundle{
		Version:    bundleVersion,
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
		SecretMode: opts.Mode,
		Assets:     []AssetItem{},
		ShodanKeys: []KeyItem{},
		Channels:   []ChannelItem{},
		Rules:      []RuleItem{},
	}

	var reseal func(existingCiphertext string) (string, error)
	switch opts.Mode {
	case ModeNone:
		reseal = func(string) (string, error) { return "", nil }
	case ModeInstanceKey:
		if !s.cipher.Enabled() {
			return nil, fmt.Errorf("instance_key export requires an encryption key")
		}
		b.KeyFingerprint = s.cipher.Fingerprint()
		reseal = func(ct string) (string, error) { return ct, nil } // carry as-is
	case ModePassphrase:
		if strings.TrimSpace(opts.Passphrase) == "" {
			return nil, fmt.Errorf("passphrase export requires a passphrase")
		}
		salt := make([]byte, kdfSaltLen)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		b.Salt = base64.StdEncoding.EncodeToString(salt)
		pcipher, err := crypto.NewFromRawKey(deriveKey(opts.Passphrase, salt))
		if err != nil {
			return nil, err
		}
		reseal = func(ct string) (string, error) {
			if ct == "" {
				return "", nil
			}
			plain, err := s.cipher.Decrypt(ct)
			if err != nil {
				return "", fmt.Errorf("decrypting for re-encryption: %w", err)
			}
			return pcipher.Encrypt(plain)
		}
	default:
		return nil, fmt.Errorf("unknown secret mode %q", opts.Mode)
	}

	// Assets.
	assets, err := s.db.ListAssets(ctx)
	if err != nil {
		return nil, err
	}
	for _, a := range assets {
		b.Assets = append(b.Assets, AssetItem{Type: string(a.Type), Value: a.Value, Label: a.Label, Notes: a.Notes, Enabled: a.Enabled, Rescan: a.Rescan})
	}

	// Shodan keys.
	dbKeys, err := s.db.ListShodanKeys(ctx)
	if err != nil {
		return nil, err
	}
	for _, k := range dbKeys {
		ct, err := reseal(k.Ciphertext)
		if err != nil {
			return nil, err
		}
		b.ShodanKeys = append(b.ShodanKeys, KeyItem{Label: k.Label, Enabled: k.Enabled, RatePerSecond: k.RatePerSecond, Ciphertext: ct})
	}

	// Channels.
	chans, err := s.db.ListChannels(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range chans {
		ct, err := reseal(c.Ciphertext)
		if err != nil {
			return nil, err
		}
		b.Channels = append(b.Channels, ChannelItem{Type: string(c.Type), Label: c.Label, Enabled: c.Enabled, Ciphertext: ct})
	}

	// Rules (reference assets by type/value and channels by label).
	assetByID := map[string]models.Asset{}
	for _, a := range assets {
		assetByID[a.ID] = a
	}
	chanByID := map[string]models.Channel{}
	for _, c := range chans {
		chanByID[c.ID] = c
	}
	rules, err := s.db.ListRules(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		item := RuleItem{
			Scope: string(r.Scope), Condition: r.Condition, Params: r.Params, Enabled: r.Enabled,
			CooldownSeconds: r.CooldownSeconds, Severity: r.Severity, Label: r.Label, ChannelLabels: []string{},
		}
		if a, ok := assetByID[r.AssetID]; ok {
			item.AssetType = string(a.Type)
			item.AssetValue = a.Value
		}
		for _, cid := range r.ChannelIDs {
			if c, ok := chanByID[cid]; ok {
				item.ChannelLabels = append(item.ChannelLabels, c.Label)
			}
		}
		b.Rules = append(b.Rules, item)
	}

	return b, nil
}

// ImportOptions controls an import.
type ImportOptions struct {
	Passphrase string
}

// Import applies a bundle idempotently, reporting what changed.
func (s *Service) Import(ctx context.Context, b *Bundle, opts ImportOptions) (*Result, error) {
	res := &Result{
		Created: map[string]int{}, Updated: map[string]int{}, Skipped: map[string]int{}, Notes: []string{},
	}

	// Resolve how to turn bundle ciphertexts into local ciphertexts.
	var localize func(bundleCiphertext string) (string, bool, error) // -> (ct, hasSecret, err)
	switch b.SecretMode {
	case ModeNone, "":
		localize = func(string) (string, bool, error) { return "", false, nil }
		res.Notes = append(res.Notes, "No secrets in bundle: keys and channels imported disabled, pending credentials.")
	case ModeInstanceKey:
		if !s.cipher.Enabled() {
			return nil, fmt.Errorf("bundle carries instance_key secrets but no encryption key is configured")
		}
		if b.KeyFingerprint != "" && b.KeyFingerprint != s.cipher.Fingerprint() {
			return nil, fmt.Errorf("bundle key fingerprint does not match this instance's key; use a passphrase export instead")
		}
		localize = func(ct string) (string, bool, error) {
			if ct == "" {
				return "", false, nil
			}
			return ct, true, nil
		}
	case ModePassphrase:
		if strings.TrimSpace(opts.Passphrase) == "" {
			return nil, fmt.Errorf("this bundle is passphrase-protected; a passphrase is required")
		}
		salt, err := base64.StdEncoding.DecodeString(b.Salt)
		if err != nil {
			return nil, fmt.Errorf("invalid salt in bundle: %w", err)
		}
		pcipher, err := crypto.NewFromRawKey(deriveKey(opts.Passphrase, salt))
		if err != nil {
			return nil, err
		}
		if !s.cipher.Enabled() {
			return nil, fmt.Errorf("importing secrets requires an encryption key on this instance")
		}
		// Pre-flight: verify the passphrase can decrypt before writing anything,
		// so a wrong passphrase is non-destructive.
		if ct := firstCiphertext(b); ct != "" {
			if _, err := pcipher.Decrypt(ct); err != nil {
				return nil, fmt.Errorf("wrong passphrase or corrupt bundle")
			}
		}
		localize = func(ct string) (string, bool, error) {
			if ct == "" {
				return "", false, nil
			}
			plain, err := pcipher.Decrypt(ct)
			if err != nil {
				return "", false, fmt.Errorf("wrong passphrase or corrupt bundle: %w", err)
			}
			local, err := s.cipher.Encrypt(plain)
			return local, true, err
		}
	default:
		return nil, fmt.Errorf("unknown secret mode %q", b.SecretMode)
	}

	// Existing state for idempotency.
	existingAssets, _ := s.db.ListAssets(ctx)
	assetKey := func(t, v string) string { return t + "|" + v }
	assetIDByKey := map[string]string{}
	for _, a := range existingAssets {
		assetIDByKey[assetKey(string(a.Type), a.Value)] = a.ID
	}

	// Assets (upsert by type+value).
	for _, item := range b.Assets {
		a := &models.Asset{Type: models.AssetType(item.Type), Value: item.Value, Label: item.Label, Notes: item.Notes, Enabled: item.Enabled, Rescan: item.Rescan}
		if err := a.Validate(); err != nil {
			res.Skipped["assets"]++
			res.Notes = append(res.Notes, fmt.Sprintf("skipped invalid asset %s: %v", item.Value, err))
			continue
		}
		if id, ok := assetIDByKey[assetKey(item.Type, item.Value)]; ok {
			a.ID = id
			if err := s.db.UpdateAsset(ctx, a); err != nil {
				res.Skipped["assets"]++
				continue
			}
			res.Updated["assets"]++
		} else {
			if err := s.db.CreateAsset(ctx, a); err != nil {
				res.Skipped["assets"]++
				continue
			}
			assetIDByKey[assetKey(item.Type, item.Value)] = a.ID
			res.Created["assets"]++
		}
	}

	// Shodan keys (create if no same-label key exists).
	existingKeys, _ := s.db.ListShodanKeys(ctx)
	keyLabels := map[string]bool{}
	for _, k := range existingKeys {
		keyLabels[k.Label] = true
	}
	for _, item := range b.ShodanKeys {
		if item.Label != "" && keyLabels[item.Label] {
			res.Skipped["shodan_keys"]++
			continue
		}
		ct, hasSecret, err := localize(item.Ciphertext)
		if err != nil {
			return nil, err
		}
		k := &models.ShodanKey{Label: item.Label, Ciphertext: ct, Enabled: item.Enabled && hasSecret, RatePerSecond: item.RatePerSecond, Health: "unknown"}
		if !hasSecret {
			k.Enabled = false
		}
		if err := s.db.CreateShodanKey(ctx, k); err != nil {
			res.Skipped["shodan_keys"]++
			continue
		}
		keyLabels[item.Label] = true
		res.Created["shodan_keys"]++
	}

	// Channels (create if no same-label channel exists), track label->id.
	existingChans, _ := s.db.ListChannels(ctx)
	chanIDByLabel := map[string]string{}
	for _, c := range existingChans {
		chanIDByLabel[c.Label] = c.ID
	}
	for _, item := range b.Channels {
		if item.Label != "" {
			if _, ok := chanIDByLabel[item.Label]; ok {
				res.Skipped["channels"]++
				continue
			}
		}
		ct, hasSecret, err := localize(item.Ciphertext)
		if err != nil {
			return nil, err
		}
		c := &models.Channel{Type: models.ChannelType(item.Type), Label: item.Label, Ciphertext: ct, Enabled: item.Enabled && hasSecret, NeedsCredentials: !hasSecret}
		if err := s.db.CreateChannel(ctx, c); err != nil {
			res.Skipped["channels"]++
			continue
		}
		chanIDByLabel[item.Label] = c.ID
		res.Created["channels"]++
	}

	// Rules (create; remap asset + channels).
	for _, item := range b.Rules {
		rule := &models.AlertRule{
			Scope: models.AlertScope(item.Scope), Condition: item.Condition, Params: item.Params,
			Enabled: item.Enabled, CooldownSeconds: item.CooldownSeconds, Severity: item.Severity, Label: item.Label,
		}
		if rule.Scope == models.ScopeAsset {
			id, ok := assetIDByKey[assetKey(item.AssetType, item.AssetValue)]
			if !ok {
				res.Skipped["rules"]++
				res.Notes = append(res.Notes, fmt.Sprintf("skipped rule %q: asset %s not found", item.Condition, item.AssetValue))
				continue
			}
			rule.AssetID = id
		}
		for _, label := range item.ChannelLabels {
			if id, ok := chanIDByLabel[label]; ok {
				rule.ChannelIDs = append(rule.ChannelIDs, id)
			}
		}
		if err := s.db.CreateRule(ctx, rule); err != nil {
			res.Skipped["rules"]++
			continue
		}
		res.Created["rules"]++
	}

	// Refresh the Shodan key pool with any newly imported keys.
	if err := s.keys.Reload(ctx); err != nil {
		res.Notes = append(res.Notes, "warning: key pool reload failed: "+err.Error())
	}
	return res, nil
}

// firstCiphertext returns the first non-empty secret ciphertext in the bundle.
func firstCiphertext(b *Bundle) string {
	for _, k := range b.ShodanKeys {
		if k.Ciphertext != "" {
			return k.Ciphertext
		}
	}
	for _, c := range b.Channels {
		if c.Ciphertext != "" {
			return c.Ciphertext
		}
	}
	return ""
}

func deriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, kdfTime, kdfMemory, kdfThreads, kdfKeyLen)
}
