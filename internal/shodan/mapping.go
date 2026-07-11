package shodan

import (
	"fmt"
	"sort"
	"strings"
)

// databaseModules are Shodan module names that indicate an exposed database.
var databaseModules = map[string]bool{
	"mongodb":       true,
	"elastic":       true,
	"elasticsearch": true,
	"redis":         true,
	"mysql":         true,
	"postgresql":    true,
	"postgres":      true,
	"cassandra":     true,
	"memcached":     true,
	"memcache":      true,
	"couchdb":       true,
	"influxdb":      true,
	"kibana":        true,
	"riak":          true,
	"etcd":          true,
	"clickhouse":    true,
}

// remoteDesktopModules are modules/services associated with remote-desktop or
// screen-sharing exposure.
var remoteDesktopModules = map[string]bool{
	"vnc":         true,
	"rdp":         true,
	"rfb":         true,
	"rtsp":        true,
	"x11":         true,
	"team-viewer": true,
}

// MapHost converts a decoded host report into normalized findings plus host
// metadata. It is deterministic: findings are sorted by (kind, key).
func MapHost(hr *HostResponse) ([]Finding, HostMeta) {
	meta := HostMeta{
		IP:        hr.IP,
		Hostnames: uniqueStrings(hr.Hostnames),
		Org:       hr.Org,
		ISP:       hr.ISP,
		OS:        hr.OS,
		Tags:      uniqueStrings(hr.Tags),
		Country:   hr.CountryCode,
		City:      hr.City,
		Online:    len(hr.Ports) > 0 || len(hr.Data) > 0,
	}

	var findings []Finding
	cveMax := map[string]*Finding{}
	tagSet := lowerSet(hr.Tags)

	// Open ports (host-level list is authoritative for presence).
	seenPort := map[int]bool{}
	for _, p := range hr.Ports {
		if seenPort[p] {
			continue
		}
		seenPort[p] = true
		findings = append(findings, Finding{
			Kind:     KindPort,
			TargetIP: hr.IP,
			Key:      fmt.Sprintf("%d", p),
			Severity: SeverityInfo,
			Detail:   map[string]any{"port": p},
		})
	}

	// Host-level CVEs (no CVSS available at this level).
	for _, cve := range hr.Vulns {
		addCVE(cveMax, hr.IP, cve, 0, false, "")
	}

	for _, svc := range hr.Data {
		module := strings.ToLower(svc.Shodan.Module)

		// Service fingerprint finding.
		if svc.Product != "" || module != "" {
			findings = append(findings, Finding{
				Kind:     KindService,
				TargetIP: hr.IP,
				Key:      fmt.Sprintf("%d/%s", svc.Port, moduleOr(module, svc.Transport)),
				Severity: SeverityInfo,
				Detail: map[string]any{
					"port":    svc.Port,
					"module":  module,
					"product": svc.Product,
					"version": svc.Version,
				},
			})
		}

		// Per-service CVEs (carry CVSS + verified).
		for cve, v := range svc.Vulns {
			addCVE(cveMax, hr.IP, cve, v.CVSS.Float(), v.Verified, v.Summary)
		}

		// Exposed database.
		if databaseModules[module] {
			findings = append(findings, Finding{
				Kind:     KindWeakness,
				TargetIP: hr.IP,
				Key:      fmt.Sprintf("exposed_database:%d", svc.Port),
				Severity: SeverityHigh,
				Detail: map[string]any{
					"weakness": "exposed_database",
					"port":     svc.Port,
					"module":   module,
				},
			})
		}

		// Screenshots + remote-desktop exposure.
		if svc.Opts.Screenshot != nil {
			labels := lowerSet(svc.Opts.Screenshot.Labels)
			remote := remoteDesktopModules[module] || labels["remote desktop"] || labels["rdp"] || labels["vnc"]
			sev := SeverityMedium
			if remote {
				sev = SeverityHigh
			}
			findings = append(findings, Finding{
				Kind:     KindScreenshot,
				TargetIP: hr.IP,
				Key:      fmt.Sprintf("screenshot:%d", svc.Port),
				Severity: sev,
				Detail: map[string]any{
					"port":           svc.Port,
					"module":         module,
					"labels":         svc.Opts.Screenshot.Labels,
					"remote_desktop": remote,
				},
			})
			if remote {
				findings = append(findings, Finding{
					Kind:     KindWeakness,
					TargetIP: hr.IP,
					Key:      fmt.Sprintf("remote_desktop:%d", svc.Port),
					Severity: SeverityHigh,
					Detail: map[string]any{
						"weakness": "remote_desktop",
						"port":     svc.Port,
						"module":   module,
					},
				})
			}
		}

		// SMB shares.
		if svc.SMB != nil {
			for _, sh := range svc.SMB.Shares {
				sev := SeverityMedium
				if svc.SMB.Anonymous {
					sev = SeverityHigh
				}
				findings = append(findings, Finding{
					Kind:     KindSMBShare,
					TargetIP: hr.IP,
					Key:      fmt.Sprintf("smb:%d:%s", svc.Port, sh.Name),
					Severity: sev,
					Detail: map[string]any{
						"port":      svc.Port,
						"share":     sh.Name,
						"type":      sh.Type,
						"anonymous": svc.SMB.Anonymous,
					},
				})
			}
		}

		// MQTT topics.
		if module == "mqtt" && len(svc.MQTT) > 0 {
			findings = append(findings, Finding{
				Kind:     KindMQTTTopic,
				TargetIP: hr.IP,
				Key:      fmt.Sprintf("mqtt:%d", svc.Port),
				Severity: SeverityMedium,
				Detail: map[string]any{
					"port": svc.Port,
					"raw":  string(svc.MQTT),
				},
			})
		}

		// TLS / certificate issues.
		if svc.SSL != nil {
			mapCert(&findings, hr.IP, svc)
		}
	}

	// Default-password detection via tags.
	if tagSet["default-password"] || tagSet["default password"] {
		findings = append(findings, Finding{
			Kind:     KindWeakness,
			TargetIP: hr.IP,
			Key:      "default_password",
			Severity: SeverityCritical,
			Detail:   map[string]any{"weakness": "default_password", "source": "tag"},
		})
	}

	// Flush merged CVE findings.
	for _, f := range cveMax {
		findings = append(findings, *f)
	}

	sortFindings(findings)
	return findings, meta
}

func mapCert(findings *[]Finding, ip string, svc Service) {
	cert := svc.SSL.Cert
	if cert.Expired {
		*findings = append(*findings, Finding{
			Kind:     KindCert,
			TargetIP: ip,
			Key:      fmt.Sprintf("cert_expired:%d", svc.Port),
			Severity: SeverityMedium,
			Detail:   map[string]any{"issue": "expired", "port": svc.Port, "expires": cert.Expires},
		})
	}
	if isSelfSigned(cert) {
		*findings = append(*findings, Finding{
			Kind:     KindCert,
			TargetIP: ip,
			Key:      fmt.Sprintf("cert_selfsigned:%d", svc.Port),
			Severity: SeverityMedium,
			Detail:   map[string]any{"issue": "self_signed", "port": svc.Port},
		})
	}
	for _, ver := range svc.SSL.Versions {
		v := strings.ToUpper(strings.ReplaceAll(ver, "v", ""))
		if strings.Contains(v, "SSL") || v == "TLS1.0" || v == "TLS10" || v == "TLS1.1" || v == "TLS11" {
			*findings = append(*findings, Finding{
				Kind:     KindCert,
				TargetIP: ip,
				Key:      fmt.Sprintf("weak_tls:%d:%s", svc.Port, ver),
				Severity: SeverityMedium,
				Detail:   map[string]any{"issue": "weak_tls", "port": svc.Port, "version": ver},
			})
		}
	}
}

// isSelfSigned reports whether the cert subject equals its issuer.
func isSelfSigned(cert SSLCert) bool {
	if len(cert.Subject) == 0 || len(cert.Issuer) == 0 {
		return false
	}
	sc, ok1 := cert.Subject["CN"]
	ic, ok2 := cert.Issuer["CN"]
	if !ok1 || !ok2 {
		return false
	}
	return fmt.Sprint(sc) == fmt.Sprint(ic)
}

func addCVE(m map[string]*Finding, ip, cve string, cvss float64, verified bool, summary string) {
	cve = strings.TrimSpace(cve)
	if cve == "" {
		return
	}
	if existing, ok := m[cve]; ok {
		if cvss > existing.CVSS {
			existing.CVSS = cvss
			existing.Severity = severityFromCVSS(cvss)
			existing.Detail["cvss"] = cvss
		}
		if verified {
			existing.Detail["verified"] = true
		}
		return
	}
	m[cve] = &Finding{
		Kind:     KindCVE,
		TargetIP: ip,
		Key:      cve,
		Severity: severityFromCVSS(cvss),
		CVSS:     cvss,
		Detail: map[string]any{
			"cve":      cve,
			"cvss":     cvss,
			"verified": verified,
			"summary":  summary,
		},
	}
}

func sortFindings(f []Finding) {
	sort.Slice(f, func(i, j int) bool {
		if f[i].Kind != f[j].Kind {
			return f[i].Kind < f[j].Kind
		}
		return f[i].Key < f[j].Key
	})
}

func moduleOr(module, fallback string) string {
	if module != "" {
		return module
	}
	if fallback != "" {
		return fallback
	}
	return "unknown"
}

func uniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func lowerSet(in []string) map[string]bool {
	m := make(map[string]bool, len(in))
	for _, s := range in {
		m[strings.ToLower(strings.TrimSpace(s))] = true
	}
	return m
}
