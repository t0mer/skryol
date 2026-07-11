// Package shodan implements a rate-limited, key-rotating client for the Shodan
// REST API. A single Client owns a pool of API keys and distributes requests
// across them (least-recently-used among healthy keys), applying a per-key
// token-bucket rate limit and retry/backoff on transient failures.
package shodan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrHostNotFound indicates Shodan has no information for the requested host
// (HTTP 404). Callers treat this as "no data", not a failure.
var ErrHostNotFound = errors.New("shodan: no information available for host")

// Options configures a Client.
type Options struct {
	BaseURL    string
	MaxRetries int
	Timeout    time.Duration
	Logger     *slog.Logger
	// OnRequest, if set, is called after each API request with the endpoint
	// label and an outcome ("ok", "not_found", "rate_limited", "error").
	OnRequest func(endpoint, outcome string)
}

// Client is the shared Shodan API client.
type Client struct {
	pool       *KeyPool
	http       *http.Client
	baseURL    string
	maxRetries int
	log        *slog.Logger
	onRequest  func(endpoint, outcome string)
	rng        *rand.Rand
}

// New builds a Client backed by the given key pool.
func New(pool *KeyPool, opts Options) *Client {
	base := strings.TrimRight(opts.BaseURL, "/")
	if base == "" {
		base = "https://api.shodan.io"
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	retries := opts.MaxRetries
	if retries <= 0 {
		retries = 4
	}
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Client{
		pool:       pool,
		http:       &http.Client{Timeout: timeout},
		baseURL:    base,
		maxRetries: retries,
		log:        log,
		onRequest:  opts.OnRequest,
		rng:        rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Pool exposes the underlying key pool.
func (c *Client) Pool() *KeyPool { return c.pool }

// Host fetches GET /shodan/host/{ip}. It returns the decoded response and the
// raw JSON body (persisted verbatim). ErrHostNotFound is returned for 404.
func (c *Client) Host(ctx context.Context, ip string) (*HostResponse, json.RawMessage, error) {
	raw, err := c.do(ctx, http.MethodGet, "/shodan/host/"+url.PathEscape(ip), url.Values{"minify": {"false"}}, "host")
	if err != nil {
		return nil, raw, err
	}
	var hr HostResponse
	if err := json.Unmarshal(raw, &hr); err != nil {
		return nil, raw, fmt.Errorf("decoding host response: %w", err)
	}
	if hr.IP == "" {
		hr.IP = ip
	}
	return &hr, raw, nil
}

// ResolveDNS resolves hostnames to IPs via GET /dns/resolve.
func (c *Client) ResolveDNS(ctx context.Context, hostnames []string) (DNSResolveResponse, error) {
	if len(hostnames) == 0 {
		return DNSResolveResponse{}, nil
	}
	q := url.Values{"hostnames": {strings.Join(hostnames, ",")}}
	raw, err := c.do(ctx, http.MethodGet, "/dns/resolve", q, "dns_resolve")
	if err != nil {
		return nil, err
	}
	var out DNSResolveResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decoding dns resolve: %w", err)
	}
	return out, nil
}

// ReverseDNS resolves IPs to hostnames via GET /dns/reverse.
func (c *Client) ReverseDNS(ctx context.Context, ips []string) (DNSReverseResponse, error) {
	if len(ips) == 0 {
		return DNSReverseResponse{}, nil
	}
	q := url.Values{"ips": {strings.Join(ips, ",")}}
	raw, err := c.do(ctx, http.MethodGet, "/dns/reverse", q, "dns_reverse")
	if err != nil {
		return nil, err
	}
	var out DNSReverseResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decoding dns reverse: %w", err)
	}
	return out, nil
}

// DomainInfo enumerates subdomains and DNS records via GET /dns/domain/{domain}.
func (c *Client) DomainInfo(ctx context.Context, domain string) (*DomainResponse, error) {
	raw, err := c.do(ctx, http.MethodGet, "/dns/domain/"+url.PathEscape(domain), nil, "dns_domain")
	if err != nil {
		return nil, err
	}
	var dr DomainResponse
	if err := json.Unmarshal(raw, &dr); err != nil {
		return nil, fmt.Errorf("decoding domain response: %w", err)
	}
	if dr.Domain == "" {
		dr.Domain = domain
	}
	return &dr, nil
}

// APIInfo fetches GET /api-info for a specific key (no rotation) and updates the
// pool's credit/health state for that key.
func (c *Client) APIInfo(ctx context.Context, key *Key) (*APIInfoResponse, error) {
	raw, status, err := c.rawRequestWithKey(ctx, http.MethodGet, "/api-info", nil, key)
	if err != nil {
		return nil, err
	}
	if err := c.classifyStatus(status, key, "api_info"); err != nil {
		return nil, err
	}
	var info APIInfoResponse
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, fmt.Errorf("decoding api-info: %w", err)
	}
	c.pool.updateCredits(key.ID, info)
	return &info, nil
}

// RefreshCredits refreshes /api-info for every enabled key. Errors per key are
// logged, not fatal.
func (c *Client) RefreshCredits(ctx context.Context) {
	for _, k := range c.pool.snapshot() {
		if !k.Enabled {
			continue
		}
		if _, err := c.APIInfo(ctx, k); err != nil {
			c.log.Warn("refresh credits failed", "key", k.ID, "label", k.Label, "err", err)
		}
	}
}

// SubmitScan requests an on-demand rescan of the given IPs via POST /shodan/scan.
func (c *Client) SubmitScan(ctx context.Context, ips []string) (*ScanSubmitResponse, error) {
	form := url.Values{"ips": {strings.Join(ips, ",")}}
	raw, err := c.doForm(ctx, "/shodan/scan", form, "scan_submit")
	if err != nil {
		return nil, err
	}
	var resp ScanSubmitResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("decoding scan submit: %w", err)
	}
	return &resp, nil
}

// ScanStatus polls GET /shodan/scan/{id}.
func (c *Client) ScanStatus(ctx context.Context, id string) (*ScanStatusResponse, error) {
	raw, err := c.do(ctx, http.MethodGet, "/shodan/scan/"+url.PathEscape(id), nil, "scan_status")
	if err != nil {
		return nil, err
	}
	var resp ScanStatusResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("decoding scan status: %w", err)
	}
	return &resp, nil
}

// do performs a rotating, retrying GET request and returns the response body.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, endpoint string) (json.RawMessage, error) {
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		key, err := c.pool.acquire(ctx)
		if err != nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, err
		}

		raw, status, reqErr := c.rawRequestWithKey(ctx, method, path, query, key)
		if reqErr != nil {
			lastErr = reqErr
			c.report(endpoint, "error")
			if err := c.backoff(ctx, attempt); err != nil {
				return nil, err
			}
			continue
		}

		switch {
		case status == http.StatusOK:
			c.pool.markHealthy(key)
			c.report(endpoint, "ok")
			return raw, nil
		case status == http.StatusNotFound:
			c.pool.markHealthy(key)
			c.report(endpoint, "not_found")
			return raw, ErrHostNotFound
		case status == http.StatusTooManyRequests:
			c.pool.markCooling(key, "rate limited (429)")
			c.report(endpoint, "rate_limited")
			lastErr = fmt.Errorf("shodan %s: rate limited", endpoint)
			if err := c.backoff(ctx, attempt); err != nil {
				return nil, err
			}
			continue
		case status == http.StatusUnauthorized:
			c.pool.markInvalid(key, "unauthorized (401)")
			c.report(endpoint, "error")
			lastErr = fmt.Errorf("shodan %s: key unauthorized", endpoint)
			continue
		case status == http.StatusPaymentRequired || status == http.StatusForbidden:
			c.pool.markExhausted(key, fmt.Sprintf("out of credits (%d)", status))
			c.report(endpoint, "error")
			lastErr = fmt.Errorf("shodan %s: key out of credits (%d)", endpoint, status)
			continue
		case status >= 500:
			c.report(endpoint, "error")
			lastErr = fmt.Errorf("shodan %s: server error %d", endpoint, status)
			if err := c.backoff(ctx, attempt); err != nil {
				return nil, err
			}
			continue
		default:
			c.report(endpoint, "error")
			return raw, fmt.Errorf("shodan %s: unexpected status %d: %s", endpoint, status, snippet(raw))
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("shodan %s: exhausted retries", endpoint)
	}
	return nil, lastErr
}

// doForm performs a rotating POST with a form body (used for scan submission).
func (c *Client) doForm(ctx context.Context, path string, form url.Values, endpoint string) (json.RawMessage, error) {
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		key, err := c.pool.acquire(ctx)
		if err != nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, err
		}
		u := c.buildURL(path, url.Values{}, key)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		raw, status, reqErr := c.roundtrip(req)
		if reqErr != nil {
			lastErr = reqErr
			if err := c.backoff(ctx, attempt); err != nil {
				return nil, err
			}
			continue
		}
		if err := c.classifyStatus(status, key, endpoint); err != nil {
			lastErr = err
			if status == http.StatusTooManyRequests || status >= 500 {
				if berr := c.backoff(ctx, attempt); berr != nil {
					return nil, berr
				}
				continue
			}
			continue
		}
		c.pool.markHealthy(key)
		c.report(endpoint, "ok")
		return raw, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("shodan %s: exhausted retries", endpoint)
	}
	return nil, lastErr
}

// classifyStatus maps a status code to a key-health update and error.
func (c *Client) classifyStatus(status int, key *Key, endpoint string) error {
	switch {
	case status == http.StatusOK:
		return nil
	case status == http.StatusTooManyRequests:
		c.pool.markCooling(key, "rate limited (429)")
		return fmt.Errorf("shodan %s: rate limited", endpoint)
	case status == http.StatusUnauthorized:
		c.pool.markInvalid(key, "unauthorized (401)")
		return fmt.Errorf("shodan %s: key unauthorized", endpoint)
	case status == http.StatusPaymentRequired || status == http.StatusForbidden:
		c.pool.markExhausted(key, fmt.Sprintf("out of credits (%d)", status))
		return fmt.Errorf("shodan %s: key out of credits (%d)", endpoint, status)
	default:
		return fmt.Errorf("shodan %s: status %d", endpoint, status)
	}
}

// rawRequestWithKey issues a single request with a specific key, returning the
// body and status without any health bookkeeping.
func (c *Client) rawRequestWithKey(ctx context.Context, method, path string, query url.Values, key *Key) (json.RawMessage, int, error) {
	u := c.buildURL(path, query, key)
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, 0, err
	}
	return c.roundtrip(req)
}

func (c *Client) roundtrip(req *http.Request) (json.RawMessage, int, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return json.RawMessage(body), resp.StatusCode, nil
}

func (c *Client) buildURL(path string, query url.Values, key *Key) string {
	if query == nil {
		query = url.Values{}
	}
	query.Set("key", key.secret)
	return c.baseURL + path + "?" + query.Encode()
}

// backoff sleeps with exponential backoff + jitter, respecting ctx cancellation.
func (c *Client) backoff(ctx context.Context, attempt int) error {
	base := time.Duration(math.Pow(2, float64(attempt))) * 250 * time.Millisecond
	if base > 15*time.Second {
		base = 15 * time.Second
	}
	jitter := time.Duration(c.rng.Int63n(int64(250 * time.Millisecond)))
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(base + jitter):
		return nil
	}
}

func (c *Client) report(endpoint, outcome string) {
	if c.onRequest != nil {
		c.onRequest(endpoint, outcome)
	}
}

func snippet(b []byte) string {
	const max = 200
	s := strings.TrimSpace(string(b))
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
