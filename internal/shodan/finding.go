package shodan

// FindingKind enumerates the normalized finding categories persisted per scan.
type FindingKind string

const (
	KindPort       FindingKind = "port"
	KindCVE        FindingKind = "cve"
	KindWeakness   FindingKind = "weakness"
	KindScreenshot FindingKind = "screenshot"
	KindSMBShare   FindingKind = "smb_share"
	KindMQTTTopic  FindingKind = "mqtt_topic"
	KindService    FindingKind = "service"
	KindCert       FindingKind = "cert"
)

// Severity buckets a finding by impact.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Finding is a normalized, comparable observation derived from a host report.
// Key is a stable identity within a (Kind, TargetIP) so diffs can match across
// scans (e.g. "443/tcp" for a port, "CVE-2021-1234" for a CVE).
type Finding struct {
	Kind     FindingKind    `json:"kind"`
	TargetIP string         `json:"target_ip"`
	Key      string         `json:"key"`
	Severity Severity       `json:"severity"`
	CVSS     float64        `json:"cvss"`
	Detail   map[string]any `json:"detail"`
}

// HostMeta captures non-finding host metadata surfaced in the UI.
type HostMeta struct {
	IP        string   `json:"ip"`
	Hostnames []string `json:"hostnames"`
	Org       string   `json:"org"`
	ISP       string   `json:"isp"`
	OS        string   `json:"os"`
	Tags      []string `json:"tags"`
	Country   string   `json:"country"`
	City      string   `json:"city"`
	Online    bool     `json:"online"`
}

// severityFromCVSS buckets a CVSS score into a severity band.
//
//	>=9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, <4.0 low (0 -> info).
func severityFromCVSS(cvss float64) Severity {
	switch {
	case cvss >= 9.0:
		return SeverityCritical
	case cvss >= 7.0:
		return SeverityHigh
	case cvss >= 4.0:
		return SeverityMedium
	case cvss > 0:
		return SeverityLow
	default:
		return SeverityInfo
	}
}
