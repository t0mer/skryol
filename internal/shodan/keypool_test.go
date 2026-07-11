package shodan

import (
	"context"
	"testing"
	"time"
)

func TestKeyPool_LRUSelection(t *testing.T) {
	p := NewKeyPool(1000)
	p.SetKeys([]KeyConfig{
		{ID: "a", Secret: "a", Enabled: true, Health: HealthHealthy},
		{ID: "b", Secret: "b", Enabled: true, Health: HealthHealthy},
	})
	ctx := context.Background()

	k1, err := p.acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := p.acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if k1.ID == k2.ID {
		t.Fatalf("expected different keys via LRU, both %s", k1.ID)
	}
}

func TestKeyPool_SkipsUnhealthy(t *testing.T) {
	p := NewKeyPool(1000)
	p.SetKeys([]KeyConfig{
		{ID: "a", Secret: "a", Enabled: true, Health: HealthInvalid},
		{ID: "b", Secret: "b", Enabled: true, Health: HealthHealthy},
		{ID: "c", Secret: "c", Enabled: false, Health: HealthHealthy},
	})
	for i := 0; i < 3; i++ {
		k, err := p.acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if k.ID != "b" {
			t.Fatalf("expected only healthy enabled key b, got %s", k.ID)
		}
	}
}

func TestKeyPool_NoHealthyKeys(t *testing.T) {
	p := NewKeyPool(1000)
	p.SetKeys([]KeyConfig{
		{ID: "a", Secret: "a", Enabled: true, Health: HealthExhausted},
	})
	if _, err := p.acquire(context.Background()); err != ErrNoHealthyKeys {
		t.Fatalf("expected ErrNoHealthyKeys, got %v", err)
	}
}

func TestKeyPool_CoolingRecovers(t *testing.T) {
	p := NewKeyPool(1000)
	p.cooldown = 10 * time.Millisecond
	p.SetKeys([]KeyConfig{
		{ID: "a", Secret: "a", Enabled: true, Health: HealthHealthy},
	})
	k := p.snapshot()[0]
	p.markCooling(k, "429")
	if p.HasUsable() {
		t.Fatal("expected no usable key while cooling")
	}
	time.Sleep(20 * time.Millisecond)
	if !p.HasUsable() {
		t.Fatal("expected key usable after cooldown elapsed")
	}
}

func TestKeyPool_SetKeysPreservesState(t *testing.T) {
	p := NewKeyPool(1000)
	p.SetKeys([]KeyConfig{{ID: "a", Secret: "a", Enabled: true, Health: HealthHealthy}})
	k, _ := p.acquire(context.Background())
	used := k.LastUsedAt
	if used.IsZero() {
		t.Fatal("expected LastUsedAt set")
	}
	// Reload with the same ID: runtime state should survive.
	p.SetKeys([]KeyConfig{{ID: "a", Secret: "a2", Enabled: true}})
	if got := p.snapshot()[0].LastUsedAt; !got.Equal(used) {
		t.Fatalf("expected preserved LastUsedAt, got %v want %v", got, used)
	}
}
