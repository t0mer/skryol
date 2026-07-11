// Package scoring computes a deterministic, reproducible security score and
// letter grade for an asset from its normalized findings. All penalties are
// named, documented weights (no inline magic numbers) so the model is
// transparent and tunable.
package scoring

import (
	"encoding/json"
	"math"

	"github.com/t0mer/skryol/internal/models"
	"github.com/t0mer/skryol/internal/shodan"
)

// Weights are the per-issue penalties subtracted from a perfect score of 100.
// They are exported and JSON-serializable so an operator can tune them via
// settings; DefaultWeights documents the baseline.
type Weights struct {
	CVECritical        float64 `json:"cve_critical"`        // per critical CVE (CVSS >= 9.0)
	CVEHigh            float64 `json:"cve_high"`            // per high CVE (7.0-8.9)
	CVEMedium          float64 `json:"cve_medium"`          // per medium CVE (4.0-6.9)
	CVELow             float64 `json:"cve_low"`             // per low CVE (< 4.0)
	VerifiedMultiplier float64 `json:"verified_multiplier"` // multiplier for verified CVEs
	DefaultPassword    float64 `json:"default_password"`    // default credentials detected
	RemoteDesktop      float64 `json:"remote_desktop"`      // exposed VNC/RDP screenshot service
	ExposedDatabase    float64 `json:"exposed_database"`    // exposed database service
	AnonymousSMB       float64 `json:"anonymous_smb"`       // anonymous SMB share
	SMBShare           float64 `json:"smb_share"`           // authenticated SMB share exposure
	CertIssue          float64 `json:"cert_issue"`          // expired / self-signed certificate
	WeakTLS            float64 `json:"weak_tls"`            // weak/deprecated TLS version
	MQTTExposed        float64 `json:"mqtt_exposed"`        // exposed MQTT broker
	SensitivePort      float64 `json:"sensitive_port"`      // each additional sensitive open port
}

// DefaultWeights returns the documented baseline penalty table.
func DefaultWeights() Weights {
	return Weights{
		CVECritical:        15,
		CVEHigh:            8,
		CVEMedium:          3,
		CVELow:             1,
		VerifiedMultiplier: 1.5,
		DefaultPassword:    40,
		RemoteDesktop:      25,
		ExposedDatabase:    25,
		AnonymousSMB:       20,
		SMBShare:           5,
		CertIssue:          5,
		WeakTLS:            5,
		MQTTExposed:        15,
		SensitivePort:      2,
	}
}

// sensitivePorts are ports whose exposure carries a small penalty each.
var sensitivePorts = map[int]bool{
	21:    true, // ftp
	23:    true, // telnet
	135:   true, // msrpc
	139:   true, // netbios
	445:   true, // smb
	1433:  true, // mssql
	3306:  true, // mysql
	3389:  true, // rdp
	5432:  true, // postgres
	5900:  true, // vnc
	6379:  true, // redis
	9200:  true, // elasticsearch
	11211: true, // memcached
	27017: true, // mongodb
}

// Result is the computed score outcome.
type Result struct {
	Score          int     `json:"score"`
	Grade          string  `json:"grade"`
	HighestCVSS    float64 `json:"highest_cvss"`
	CVECount       int     `json:"cve_count"`
	CriticalCount  int     `json:"critical_count"`
	OpenPortsCount int     `json:"open_ports_count"`
	Penalty        float64 `json:"penalty"`
}

// Score computes the score/grade for a set of findings using the given weights.
func Score(findings []models.Finding, w Weights) Result {
	var penalty, highest float64
	cveCount, critical, ports := 0, 0, 0

	for _, f := range findings {
		switch f.Kind {
		case string(shodan.KindCVE):
			cveCount++
			if f.CVSS > highest {
				highest = f.CVSS
			}
			base := cvePenalty(f.Severity, w)
			if isVerified(f.Detail) {
				base *= w.VerifiedMultiplier
			}
			penalty += base

		case string(shodan.KindPort):
			ports++
			if p := detailInt(f.Detail, "port"); sensitivePorts[p] {
				penalty += w.SensitivePort
			}

		case string(shodan.KindWeakness):
			penalty += weaknessPenalty(f.Detail, w)

		case string(shodan.KindSMBShare):
			if detailBool(f.Detail, "anonymous") {
				penalty += w.AnonymousSMB
			} else {
				penalty += w.SMBShare
			}

		case string(shodan.KindCert):
			if detailString(f.Detail, "issue") == "weak_tls" {
				penalty += w.WeakTLS
			} else {
				penalty += w.CertIssue
			}

		case string(shodan.KindScreenshot):
			// Remote-desktop screenshots also emit a weakness finding that
			// carries the penalty; the screenshot itself is not double-counted.

		case string(shodan.KindMQTTTopic):
			penalty += w.MQTTExposed
		}

		if f.Severity == string(shodan.SeverityCritical) {
			critical++
		}
	}

	score := int(math.Round(100 - penalty))
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return Result{
		Score:          score,
		Grade:          Grade(score),
		HighestCVSS:    highest,
		CVECount:       cveCount,
		CriticalCount:  critical,
		OpenPortsCount: ports,
		Penalty:        penalty,
	}
}

// Grade maps a score to a letter grade using documented bands.
//
//	A: 90-100, B: 80-89, C: 70-79, D: 60-69, F: below 60.
func Grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func cvePenalty(severity string, w Weights) float64 {
	switch severity {
	case string(shodan.SeverityCritical):
		return w.CVECritical
	case string(shodan.SeverityHigh):
		return w.CVEHigh
	case string(shodan.SeverityMedium):
		return w.CVEMedium
	default:
		return w.CVELow
	}
}

func weaknessPenalty(detail json.RawMessage, w Weights) float64 {
	switch detailString(detail, "weakness") {
	case "default_password":
		return w.DefaultPassword
	case "remote_desktop":
		return w.RemoteDesktop
	case "exposed_database":
		return w.ExposedDatabase
	default:
		return 0
	}
}

func isVerified(detail json.RawMessage) bool { return detailBool(detail, "verified") }

func decodeDetail(detail json.RawMessage) map[string]any {
	if len(detail) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(detail, &m); err != nil {
		return nil
	}
	return m
}

func detailString(detail json.RawMessage, key string) string {
	m := decodeDetail(detail)
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func detailBool(detail json.RawMessage, key string) bool {
	m := decodeDetail(detail)
	if m == nil {
		return false
	}
	v, _ := m[key].(bool)
	return v
}

func detailInt(detail json.RawMessage, key string) int {
	m := decodeDetail(detail)
	if m == nil {
		return 0
	}
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	return 0
}
