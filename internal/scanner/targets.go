package scanner

import (
	"context"
	"fmt"
	"math/big"
	"net/netip"
	"sort"

	"github.com/t0mer/skryol/internal/models"
	"github.com/t0mer/skryol/internal/shodan"
)

// resolveTargets expands an asset into the concrete IP addresses to look up,
// enforcing the per-asset host cap. It returns the target IPs (deduplicated and
// sorted) or an error if a guardrail is violated.
func (s *Scanner) resolveTargets(ctx context.Context, a models.Asset) ([]string, error) {
	switch a.Type {
	case models.AssetIP:
		return []string{a.Value}, nil

	case models.AssetCIDR:
		return expandCIDR(a.Value, s.config().MaxHostsPerAsset)

	case models.AssetFQDN:
		res, err := s.client.ResolveDNS(ctx, []string{a.Value})
		if err != nil {
			return nil, fmt.Errorf("resolving %s: %w", a.Value, err)
		}
		ips := dedupeSortedIPs(collectResolved(res))
		if len(ips) == 0 {
			return nil, fmt.Errorf("hostname %s did not resolve to any IP", a.Value)
		}
		return capHosts(ips, s.config().MaxHostsPerAsset)

	case models.AssetDomain:
		return s.resolveDomain(ctx, a.Value)

	default:
		return nil, fmt.Errorf("unsupported asset type %q", a.Type)
	}
}

// resolveDomain enumerates a domain's subdomains via Shodan and resolves them
// to IPs (apex + each subdomain), capped.
func (s *Scanner) resolveDomain(ctx context.Context, domain string) ([]string, error) {
	info, err := s.client.DomainInfo(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("enumerating domain %s: %w", domain, err)
	}

	// Prefer A/AAAA records already present in the enumeration to save credits.
	ipSet := map[string]bool{}
	var hostnames []string
	hostnames = append(hostnames, domain)
	for _, rec := range info.Data {
		fqdn := domain
		if rec.Subdomain != "" {
			fqdn = rec.Subdomain + "." + domain
		}
		switch rec.Type {
		case "A", "AAAA":
			if _, err := netip.ParseAddr(rec.Value); err == nil {
				ipSet[rec.Value] = true
			}
		}
		hostnames = append(hostnames, fqdn)
	}
	for _, sub := range info.Subdomains {
		hostnames = append(hostnames, sub+"."+domain)
	}

	// Resolve any hostnames we don't yet have an IP for (bounded batch).
	hostnames = dedupeStrings(hostnames)
	if len(hostnames) > s.config().MaxHostsPerAsset {
		hostnames = hostnames[:s.config().MaxHostsPerAsset]
	}
	if len(hostnames) > 0 {
		res, err := s.client.ResolveDNS(ctx, hostnames)
		if err != nil {
			s.log.Warn("domain hostname resolution failed", "domain", domain, "err", err)
		} else {
			for _, ip := range collectResolved(res) {
				ipSet[ip] = true
			}
		}
	}

	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	ips = dedupeSortedIPs(ips)
	if len(ips) == 0 {
		return nil, fmt.Errorf("domain %s yielded no resolvable IPs", domain)
	}
	return capHosts(ips, s.config().MaxHostsPerAsset)
}

// expandCIDR lists the member addresses of a prefix, rejecting ranges larger
// than maxHosts.
func expandCIDR(cidr string, maxHosts int) ([]string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	prefix = prefix.Masked()

	bits := prefix.Addr().BitLen()
	hostBits := bits - prefix.Bits()
	// Count = 2^hostBits, guarded against overflow via big.Int.
	count := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	if count.Cmp(big.NewInt(int64(maxHosts))) > 0 {
		return nil, fmt.Errorf("CIDR %s expands to %s hosts, exceeding the cap of %d (raise scanner.max_hosts_per_asset or use a smaller range)", cidr, count.String(), maxHosts)
	}

	var out []string
	addr := prefix.Addr()
	for prefix.Contains(addr) {
		out = append(out, addr.String())
		addr = addr.Next()
		if !addr.IsValid() {
			break
		}
		if len(out) >= maxHosts {
			break
		}
	}
	return out, nil
}

func capHosts(ips []string, maxHosts int) ([]string, error) {
	if len(ips) > maxHosts {
		return nil, fmt.Errorf("asset resolved to %d hosts, exceeding the cap of %d", len(ips), maxHosts)
	}
	return ips, nil
}

func collectResolved(res shodan.DNSResolveResponse) []string {
	out := make([]string, 0, len(res))
	for _, ip := range res {
		if ip != "" {
			out = append(out, ip)
		}
	}
	return out
}

func dedupeSortedIPs(ips []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		out = append(out, ip)
	}
	sort.Slice(out, func(i, j int) bool {
		ai, erri := netip.ParseAddr(out[i])
		aj, errj := netip.ParseAddr(out[j])
		if erri != nil || errj != nil {
			return out[i] < out[j]
		}
		return ai.Less(aj)
	})
	return out
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
