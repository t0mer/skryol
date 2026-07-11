package alerts

import (
	"encoding/json"
	"testing"

	"github.com/t0mer/skryol/internal/models"
)

func rule(cond string, params map[string]any) models.AlertRule {
	p, _ := json.Marshal(params)
	return models.AlertRule{ID: "r1", Condition: cond, Params: p, CooldownSeconds: 0}
}

func change(kind, key string, cvss float64) models.FindingChange {
	return models.FindingChange{Kind: kind, Key: key, TargetIP: "1.1.1.1", CVSS: cvss}
}

func TestMatch_Conditions(t *testing.T) {
	e := &Engine{}
	scan := &models.Scan{ID: "s2", Status: models.ScanOK}

	cases := []struct {
		name  string
		rule  models.AlertRule
		diff  models.DiffSummary
		scan  *models.Scan
		fired bool
	}{
		{
			name:  "new open port fires",
			rule:  rule(CondNewOpenPort, nil),
			diff:  models.DiffSummary{Added: []models.FindingChange{change("port", "22", 0)}},
			fired: true,
		},
		{
			name:  "new open port no adds",
			rule:  rule(CondNewOpenPort, nil),
			diff:  models.DiffSummary{Added: []models.FindingChange{change("cve", "CVE-1", 5)}},
			fired: false,
		},
		{
			name:  "cvss at least 7 fires on 9",
			rule:  rule(CondCVSSAtLeast, map[string]any{"cvss": 7.0}),
			diff:  models.DiffSummary{Added: []models.FindingChange{change("cve", "CVE-1", 9.0)}},
			fired: true,
		},
		{
			name:  "cvss at least 7 skips 5",
			rule:  rule(CondCVSSAtLeast, map[string]any{"cvss": 7.0}),
			diff:  models.DiffSummary{Added: []models.FindingChange{change("cve", "CVE-1", 5.0)}},
			fired: false,
		},
		{
			name:  "score drop fires",
			rule:  rule(CondScoreDrop, map[string]any{"points": 10.0}),
			diff:  models.DiffSummary{ScoreDelta: -15},
			fired: true,
		},
		{
			name:  "score drop below threshold no fire",
			rule:  rule(CondScoreDrop, map[string]any{"points": 20.0}),
			diff:  models.DiffSummary{ScoreDelta: -15},
			fired: false,
		},
		{
			name:  "grade drops below B",
			rule:  rule(CondGradeBelow, map[string]any{"grade": "B"}),
			diff:  models.DiffSummary{GradeFrom: "A", GradeTo: "C"},
			fired: true,
		},
		{
			name:  "grade already below no re-fire",
			rule:  rule(CondGradeBelow, map[string]any{"grade": "B"}),
			diff:  models.DiffSummary{GradeFrom: "C", GradeTo: "D"},
			fired: false,
		},
		{
			name:  "default password",
			rule:  rule(CondDefaultPassword, nil),
			diff:  models.DiffSummary{Added: []models.FindingChange{change("weakness", "default_password", 0)}},
			fired: true,
		},
		{
			name:  "asset offline",
			rule:  rule(CondAssetOffline, nil),
			diff:  models.DiffSummary{WentOffline: true},
			fired: true,
		},
		{
			name:  "scan failed",
			rule:  rule(CondScanFailed, nil),
			scan:  &models.Scan{ID: "s2", Status: models.ScanFailed},
			diff:  models.DiffSummary{},
			fired: true,
		},
		{
			name:  "exposed database",
			rule:  rule(CondNewExposedDatabase, nil),
			diff:  models.DiffSummary{Added: []models.FindingChange{change("weakness", "exposed_database:27017", 0)}},
			fired: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sc := scan
			if c.scan != nil {
				sc = c.scan
			}
			got := e.match(c.rule, sc, c.diff)
			if got.fired != c.fired {
				t.Fatalf("fired=%v want %v (facts=%q)", got.fired, c.fired, got.facts)
			}
		})
	}
}

func TestMatch_DedupInstanceStable(t *testing.T) {
	e := &Engine{}
	scan := &models.Scan{ID: "s2"}
	d := models.DiffSummary{Added: []models.FindingChange{change("port", "443", 0), change("port", "22", 0)}}
	a := e.match(rule(CondNewOpenPort, nil), scan, d)
	b := e.match(rule(CondNewOpenPort, nil), scan, d)
	if a.instance != b.instance || a.instance == "" {
		t.Fatalf("instance signature should be stable and non-empty: %q vs %q", a.instance, b.instance)
	}
}
