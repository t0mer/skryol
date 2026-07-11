// Package alerts evaluates alert rules against a completed scan and its diff,
// applies per-rule dedup/cooldown, routes firings to notification channels, and
// records every firing to an audit log.
package alerts

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/t0mer/skryol/internal/db"
	"github.com/t0mer/skryol/internal/metrics"
	"github.com/t0mer/skryol/internal/models"
	"github.com/t0mer/skryol/internal/notify"
)

// Condition identifiers (see the build contract §9).
const (
	CondNewOpenPort        = "new_open_port"
	CondNewCVE             = "new_cve"
	CondCVSSAtLeast        = "cve_cvss_at_least"
	CondScoreDrop          = "score_drop_at_least"
	CondGradeBelow         = "grade_drops_below"
	CondDefaultPassword    = "default_password_detected"
	CondNewScreenshot      = "new_screenshot_service"
	CondNewSMBShare        = "new_smb_share"
	CondNewExposedDatabase = "new_exposed_database"
	CondCertIssue          = "cert_expired_or_selfsigned"
	CondAssetOffline       = "asset_offline"
	CondAssetOnline        = "asset_online"
	CondScanFailed         = "scan_failed"
)

// Notifier delivers a message to a channel by ID.
type Notifier interface {
	SendTo(ctx context.Context, channelID string, msg notify.Message) error
}

// Engine evaluates rules and dispatches notifications.
type Engine struct {
	db       *db.DB
	notifier Notifier
	metrics  *metrics.Metrics
	log      *slog.Logger
	baseURL  string
}

// New builds the alert engine.
func New(database *db.DB, notifier Notifier, m *metrics.Metrics, log *slog.Logger, baseURL string) *Engine {
	return &Engine{db: database, notifier: notifier, metrics: m, log: log, baseURL: strings.TrimRight(baseURL, "/")}
}

// Evaluate runs all applicable rules for the asset against the scan/diff.
func (e *Engine) Evaluate(ctx context.Context, asset models.Asset, scan *models.Scan, summary models.DiffSummary) error {
	rules, err := e.db.RulesForAsset(ctx, asset.ID)
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}
	for _, rule := range rules {
		m := e.match(rule, scan, summary)
		if !m.fired {
			continue
		}
		e.fire(ctx, asset, rule, m)
	}
	return nil
}

// matchResult is the outcome of evaluating one rule.
type matchResult struct {
	fired    bool
	instance string // signature for dedup within a rule/asset/condition
	facts    string // human-readable summary for the message body
}

func (e *Engine) match(rule models.AlertRule, scan *models.Scan, s models.DiffSummary) matchResult {
	params := parseParams(rule.Params)
	switch rule.Condition {
	case CondScanFailed:
		if scan.Status == models.ScanFailed {
			return matchResult{true, scan.ID, "Scan failed: " + scan.Error}
		}
	case CondAssetOffline:
		if s.WentOffline {
			return matchResult{true, scan.ID, "Asset went offline in Shodan."}
		}
	case CondAssetOnline:
		if s.CameOnline {
			return matchResult{true, scan.ID, "Asset came online in Shodan."}
		}
	case CondScoreDrop:
		points := params.float("points", params.float("value", 10))
		if s.ScoreDelta <= -int(points) && s.ScoreDelta < 0 {
			return matchResult{true, scan.ID, fmt.Sprintf("Security score dropped by %d points (now %s).", -s.ScoreDelta, scoreStr(s.ScoreTo))}
		}
	case CondGradeBelow:
		threshold := strings.ToUpper(params.str("grade", "B"))
		if s.GradeFrom != "" && gradeRank(s.GradeTo) > gradeRank(threshold) && gradeRank(s.GradeFrom) <= gradeRank(threshold) {
			return matchResult{true, scan.ID, fmt.Sprintf("Grade dropped from %s to %s (below %s).", s.GradeFrom, s.GradeTo, threshold)}
		}
	case CondNewOpenPort:
		return matchAdded(s.Added, func(c models.FindingChange) bool { return c.Kind == "port" }, "New open port(s)")
	case CondNewCVE:
		minCVSS := params.float("min_cvss", 0)
		return matchAdded(s.Added, func(c models.FindingChange) bool { return c.Kind == "cve" && c.CVSS >= minCVSS }, "New CVE(s)")
	case CondCVSSAtLeast:
		threshold := params.float("cvss", params.float("min_cvss", 7.0))
		return matchAdded(s.Added, func(c models.FindingChange) bool { return c.Kind == "cve" && c.CVSS >= threshold }, fmt.Sprintf("New CVE(s) with CVSS >= %.1f", threshold))
	case CondDefaultPassword:
		return matchAdded(s.Added, func(c models.FindingChange) bool { return c.Kind == "weakness" && c.Key == "default_password" }, "Default password detected")
	case CondNewScreenshot:
		remoteOnly := params.boolean("remote_only", false)
		return matchAdded(s.Added, func(c models.FindingChange) bool {
			return c.Kind == "screenshot" && (!remoteOnly || detailBool(c.Detail, "remote_desktop"))
		}, "New screenshot service")
	case CondNewSMBShare:
		return matchAdded(s.Added, func(c models.FindingChange) bool { return c.Kind == "smb_share" }, "New SMB share")
	case CondNewExposedDatabase:
		return matchAdded(s.Added, func(c models.FindingChange) bool {
			return c.Kind == "weakness" && strings.HasPrefix(c.Key, "exposed_database")
		}, "New exposed database")
	case CondCertIssue:
		return matchAdded(s.Added, func(c models.FindingChange) bool {
			return c.Kind == "cert" && (strings.HasPrefix(c.Key, "cert_expired") || strings.HasPrefix(c.Key, "cert_selfsigned"))
		}, "Certificate expired or self-signed")
	}
	return matchResult{}
}

// matchAdded filters added findings by predicate; instance is the sorted key set.
func matchAdded(added []models.FindingChange, pred func(models.FindingChange) bool, label string) matchResult {
	var keys []string
	for _, c := range added {
		if pred(c) {
			keys = append(keys, c.TargetIP+"/"+c.Key)
		}
	}
	if len(keys) == 0 {
		return matchResult{}
	}
	sort.Strings(keys)
	return matchResult{fired: true, instance: strings.Join(keys, ","), facts: label + ": " + strings.Join(keys, ", ")}
}

func (e *Engine) fire(ctx context.Context, asset models.Asset, rule models.AlertRule, m matchResult) {
	dedupKey := strings.Join([]string{rule.ID, asset.ID, rule.Condition, m.instance}, "|")

	if rule.CooldownSeconds > 0 {
		last, err := e.db.LastAlertEvent(ctx, dedupKey)
		if err != nil {
			e.log.Warn("cooldown lookup failed", "rule", rule.ID, "err", err)
		} else if !last.IsZero() && time.Since(last) < time.Duration(rule.CooldownSeconds)*time.Second {
			e.log.Debug("alert suppressed by cooldown", "rule", rule.ID, "asset", asset.Value)
			return
		}
	}

	msg := e.buildMessage(asset, rule, m)
	delivered := map[string]string{}
	for _, cid := range rule.ChannelIDs {
		if err := e.notifier.SendTo(ctx, cid, msg); err != nil {
			e.log.Warn("notification send failed", "channel", cid, "rule", rule.ID, "err", err)
			delivered[cid] = "error: " + err.Error()
		} else {
			delivered[cid] = "ok"
		}
	}

	payload, _ := json.Marshal(map[string]any{"facts": m.facts, "instance": m.instance})
	deliveredJSON, _ := json.Marshal(delivered)
	event := &models.AlertEvent{
		RuleID:    rule.ID,
		AssetID:   asset.ID,
		Condition: rule.Condition,
		Severity:  rule.Severity,
		FiredAt:   time.Now().UTC(),
		DedupKey:  dedupKey,
		Payload:   payload,
		Delivered: deliveredJSON,
	}
	if err := e.db.RecordAlertEvent(ctx, event); err != nil {
		e.log.Warn("recording alert event failed", "rule", rule.ID, "err", err)
	}
	e.metrics.AlertsFired.WithLabelValues(rule.Condition).Inc()
	e.log.Info("alert fired", "rule", rule.ID, "condition", rule.Condition, "asset", asset.Value, "channels", len(rule.ChannelIDs))
}

func (e *Engine) buildMessage(asset models.Asset, rule models.AlertRule, m matchResult) notify.Message {
	name := asset.Label
	if name == "" {
		name = asset.Value
	}
	severity := strings.ToUpper(rule.Severity)
	if severity == "" {
		severity = "INFO"
	}
	title := fmt.Sprintf("[Skryol %s] %s", severity, name)
	body := m.facts
	body += fmt.Sprintf("\n\nAsset: %s (%s)", asset.Value, asset.Type)
	if e.baseURL != "" {
		body += fmt.Sprintf("\nDetails: %s/assets/%s", e.baseURL, asset.ID)
	}
	return notify.Message{Title: title, Body: body}
}

// --- helpers ---

type params map[string]any

func parseParams(raw json.RawMessage) params {
	if len(raw) == 0 {
		return params{}
	}
	var p params
	if err := json.Unmarshal(raw, &p); err != nil {
		return params{}
	}
	return p
}

func (p params) float(key string, def float64) float64 {
	if v, ok := p[key].(float64); ok {
		return v
	}
	return def
}

func (p params) str(key, def string) string {
	if v, ok := p[key].(string); ok && v != "" {
		return v
	}
	return def
}

func (p params) boolean(key string, def bool) bool {
	if v, ok := p[key].(bool); ok {
		return v
	}
	return def
}

func gradeRank(g string) int {
	switch strings.ToUpper(g) {
	case "A":
		return 0
	case "B":
		return 1
	case "C":
		return 2
	case "D":
		return 3
	default:
		return 4 // F or unknown
	}
}

func scoreStr(s *int) string {
	if s == nil {
		return "n/a"
	}
	return fmt.Sprintf("%d", *s)
}

func detailBool(detail json.RawMessage, key string) bool {
	if len(detail) == 0 {
		return false
	}
	var m map[string]any
	if err := json.Unmarshal(detail, &m); err != nil {
		return false
	}
	v, _ := m[key].(bool)
	return v
}
