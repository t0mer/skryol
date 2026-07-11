package shodan

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(t *testing.T, handler http.HandlerFunc, keys ...KeyConfig) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	pool := NewKeyPool(1000) // effectively no rate limiting in tests
	if len(keys) == 0 {
		keys = []KeyConfig{{ID: "k1", Secret: "s1", Enabled: true, Health: HealthHealthy}}
	}
	pool.SetKeys(keys)
	c := New(pool, Options{BaseURL: srv.URL, MaxRetries: 3, Timeout: 5 * time.Second})
	return c, srv
}

func TestHost_Success(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "s1" {
			t.Errorf("missing key param, got %q", r.URL.RawQuery)
		}
		w.Write([]byte(`{"ip_str":"1.2.3.4","ports":[80,443],"org":"Acme"}`))
	})
	hr, raw, err := c.Host(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	if hr.Org != "Acme" || len(hr.Ports) != 2 {
		t.Fatalf("unexpected host: %+v", hr)
	}
	if len(raw) == 0 {
		t.Fatal("expected raw body preserved")
	}
}

func TestHost_NotFound(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"No information available for that IP."}`))
	})
	_, _, err := c.Host(context.Background(), "1.2.3.4")
	if !errors.Is(err, ErrHostNotFound) {
		t.Fatalf("expected ErrHostNotFound, got %v", err)
	}
}

func TestHost_RateLimitThenSuccess(t *testing.T) {
	var calls int32
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`{"ip_str":"1.2.3.4","ports":[22]}`))
	},
		KeyConfig{ID: "k1", Secret: "s1", Enabled: true, Health: HealthHealthy},
		KeyConfig{ID: "k2", Secret: "s2", Enabled: true, Health: HealthHealthy},
	)
	hr, _, err := c.Host(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("expected success after retry, got %v", err)
	}
	if len(hr.Ports) != 1 {
		t.Fatalf("unexpected host: %+v", hr)
	}
	if atomic.LoadInt32(&calls) < 2 {
		t.Fatalf("expected a retry, calls=%d", calls)
	}
}

func TestRotation_DistributesAcrossKeys(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Query().Get("key")]++
		mu.Unlock()
		w.Write([]byte(`{"ip_str":"1.2.3.4"}`))
	},
		KeyConfig{ID: "k1", Secret: "s1", Enabled: true, Health: HealthHealthy},
		KeyConfig{ID: "k2", Secret: "s2", Enabled: true, Health: HealthHealthy},
	)
	for i := 0; i < 6; i++ {
		if _, _, err := c.Host(context.Background(), "1.2.3.4"); err != nil {
			t.Fatalf("host %d: %v", i, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if seen["s1"] == 0 || seen["s2"] == 0 {
		t.Fatalf("expected both keys used, got %v", seen)
	}
	// LRU should balance evenly.
	if seen["s1"] != 3 || seen["s2"] != 3 {
		t.Fatalf("expected even LRU distribution, got %v", seen)
	}
}

func TestAllKeysExhausted(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
	},
		KeyConfig{ID: "k1", Secret: "s1", Enabled: true, Health: HealthHealthy},
	)
	_, _, err := c.Host(context.Background(), "1.2.3.4")
	if err == nil {
		t.Fatal("expected error when key exhausted")
	}
	if c.pool.HasUsable() {
		t.Fatal("expected pool to have no usable keys after 402")
	}
}

func TestAPIInfo_UpdatesCredits(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"query_credits":42,"scan_credits":7,"plan":"dev"}`))
	})
	key := c.pool.snapshot()[0]
	info, err := c.APIInfo(context.Background(), key)
	if err != nil {
		t.Fatalf("api-info: %v", err)
	}
	if info.QueryCredits != 42 {
		t.Fatalf("unexpected credits: %+v", info)
	}
	st := c.pool.States()[0]
	if st.QueryCredits != 42 || st.ScanCredits != 7 || st.Plan != "dev" {
		t.Fatalf("pool credits not updated: %+v", st)
	}
}

func TestResolveDNS(t *testing.T) {
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("hostnames"); got != "a.com,b.com" {
			t.Errorf("hostnames param = %q", got)
		}
		w.Write([]byte(`{"a.com":"1.1.1.1","b.com":"2.2.2.2"}`))
	})
	res, err := c.ResolveDNS(context.Background(), []string{"a.com", "b.com"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res["a.com"] != "1.1.1.1" || res["b.com"] != "2.2.2.2" {
		t.Fatalf("unexpected resolve: %v", res)
	}
}
