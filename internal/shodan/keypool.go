package shodan

import (
	"context"
	"errors"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Health enumerates a key's operational state.
type Health string

const (
	HealthUnknown   Health = "unknown"
	HealthHealthy   Health = "healthy"
	HealthCooling   Health = "cooling"   // transient 429 backoff
	HealthExhausted Health = "exhausted" // out of credits (402)
	HealthInvalid   Health = "invalid"   // bad/unauthorized key (401)
)

// ErrNoHealthyKeys is returned when the pool has no usable key.
var ErrNoHealthyKeys = errors.New("shodan: no healthy keys with credits available")

// Key is a single Shodan API key with its live health/credit state. The secret
// is held in memory only; encryption at rest is handled by the persistence
// layer, not the pool.
type Key struct {
	ID            string
	Label         string
	secret        string
	Enabled       bool
	QueryCredits  int
	ScanCredits   int
	Plan          string
	Health        Health
	LastError     string
	LastUsedAt    time.Time
	LastCheckedAt time.Time

	limiter   *rate.Limiter
	coolUntil time.Time
}

// KeyState is an exported, secret-free snapshot of a key's state for the UI.
type KeyState struct {
	ID            string    `json:"id"`
	Label         string    `json:"label"`
	Enabled       bool      `json:"enabled"`
	QueryCredits  int       `json:"query_credits"`
	ScanCredits   int       `json:"scan_credits"`
	Plan          string    `json:"plan"`
	Health        Health    `json:"health"`
	LastError     string    `json:"last_error,omitempty"`
	LastUsedAt    time.Time `json:"last_used_at,omitempty"`
	LastCheckedAt time.Time `json:"last_checked_at,omitempty"`
}

// KeyConfig seeds a key into the pool.
type KeyConfig struct {
	ID            string
	Label         string
	Secret        string
	Enabled       bool
	RatePerSecond float64
	QueryCredits  int
	ScanCredits   int
	Plan          string
	Health        Health
}

// KeyPool owns the set of keys and hands them out with per-key rate limiting.
// Selection is least-recently-used among healthy keys that still have credits.
type KeyPool struct {
	mu          sync.Mutex
	keys        []*Key
	defaultRate float64
	cooldown    time.Duration
}

// NewKeyPool builds a pool. defaultRate is the per-key token-bucket rate
// (requests/sec) used when a key does not specify its own.
func NewKeyPool(defaultRate float64) *KeyPool {
	if defaultRate <= 0 {
		defaultRate = 1.0
	}
	return &KeyPool{defaultRate: defaultRate, cooldown: 60 * time.Second}
}

// SetKeys replaces the pool contents from the given configs, preserving live
// limiter state for keys whose ID is unchanged.
func (p *KeyPool) SetKeys(configs []KeyConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()

	existing := make(map[string]*Key, len(p.keys))
	for _, k := range p.keys {
		existing[k.ID] = k
	}

	newKeys := make([]*Key, 0, len(configs))
	for _, c := range configs {
		r := c.RatePerSecond
		if r <= 0 {
			r = p.defaultRate
		}
		health := c.Health
		if health == "" {
			health = HealthUnknown
		}
		k := &Key{
			ID:           c.ID,
			Label:        c.Label,
			secret:       c.Secret,
			Enabled:      c.Enabled,
			QueryCredits: c.QueryCredits,
			ScanCredits:  c.ScanCredits,
			Plan:         c.Plan,
			Health:       health,
			limiter:      rate.NewLimiter(rate.Limit(r), 1),
		}
		if prev, ok := existing[c.ID]; ok {
			// Preserve runtime state across reloads.
			k.limiter = prev.limiter
			k.limiter.SetLimit(rate.Limit(r))
			k.LastUsedAt = prev.LastUsedAt
			k.LastCheckedAt = prev.LastCheckedAt
			k.coolUntil = prev.coolUntil
			if prev.Health != HealthUnknown {
				k.Health = prev.Health
			}
		}
		newKeys = append(newKeys, k)
	}
	p.keys = newKeys
}

// selectable reports whether a key can currently be used.
func (k *Key) selectable(now time.Time) bool {
	if !k.Enabled {
		return false
	}
	switch k.Health {
	case HealthInvalid, HealthExhausted:
		return false
	case HealthCooling:
		return now.After(k.coolUntil)
	}
	return true
}

// acquire selects the least-recently-used usable key and blocks on its rate
// limiter until a token is available. It returns the key or ErrNoHealthyKeys.
func (p *KeyPool) acquire(ctx context.Context) (*Key, error) {
	p.mu.Lock()
	now := time.Now()
	var chosen *Key
	for _, k := range p.keys {
		if !k.selectable(now) {
			continue
		}
		if k.Health == HealthCooling && now.After(k.coolUntil) {
			k.Health = HealthHealthy
		}
		if chosen == nil || k.LastUsedAt.Before(chosen.LastUsedAt) {
			chosen = k
		}
	}
	if chosen == nil {
		p.mu.Unlock()
		return nil, ErrNoHealthyKeys
	}
	chosen.LastUsedAt = now
	limiter := chosen.limiter
	p.mu.Unlock()

	if err := limiter.Wait(ctx); err != nil {
		return nil, err
	}
	return chosen, nil
}

// markCooling puts a key into transient backoff for the pool's cooldown window.
func (p *KeyPool) markCooling(k *Key, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	k.Health = HealthCooling
	k.coolUntil = time.Now().Add(p.cooldown)
	k.LastError = reason
}

// markExhausted flags a key as out of credits.
func (p *KeyPool) markExhausted(k *Key, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	k.Health = HealthExhausted
	k.LastError = reason
}

// markInvalid flags a key as unauthorized/bad.
func (p *KeyPool) markInvalid(k *Key, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	k.Health = HealthInvalid
	k.LastError = reason
}

// markHealthy clears error state after a successful request.
func (p *KeyPool) markHealthy(k *Key) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if k.Health == HealthCooling || k.Health == HealthUnknown {
		k.Health = HealthHealthy
	}
	k.LastError = ""
}

// updateCredits records refreshed credit counts for a key by ID.
func (p *KeyPool) updateCredits(id string, info APIInfoResponse) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, k := range p.keys {
		if k.ID != id {
			continue
		}
		k.QueryCredits = info.QueryCredits
		k.ScanCredits = info.ScanCredits
		k.Plan = info.Plan
		k.LastCheckedAt = time.Now()
		if k.Health == HealthUnknown {
			k.Health = HealthHealthy
		}
		return
	}
}

// States returns secret-free snapshots of all keys.
func (p *KeyPool) States() []KeyState {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]KeyState, 0, len(p.keys))
	for _, k := range p.keys {
		out = append(out, KeyState{
			ID:            k.ID,
			Label:         k.Label,
			Enabled:       k.Enabled,
			QueryCredits:  k.QueryCredits,
			ScanCredits:   k.ScanCredits,
			Plan:          k.Plan,
			Health:        k.Health,
			LastError:     k.LastError,
			LastUsedAt:    k.LastUsedAt,
			LastCheckedAt: k.LastCheckedAt,
		})
	}
	return out
}

// snapshot returns the current keys (pointers) for iteration by the client.
func (p *KeyPool) snapshot() []*Key {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*Key, len(p.keys))
	copy(out, p.keys)
	return out
}

// HasUsable reports whether any key is currently selectable.
func (p *KeyPool) HasUsable() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for _, k := range p.keys {
		if k.selectable(now) {
			return true
		}
	}
	return false
}
