package scoring

import (
	"encoding/json"
	"testing"

	"github.com/t0mer/skryol/internal/models"
)

func f(kind, severity string, cvss float64, detail map[string]any) models.Finding {
	d, _ := json.Marshal(detail)
	return models.Finding{Kind: kind, Severity: severity, CVSS: cvss, Detail: d}
}

func TestScore_PerfectWhenClean(t *testing.T) {
	res := Score(nil, DefaultWeights())
	if res.Score != 100 || res.Grade != "A" {
		t.Fatalf("expected 100/A for no findings, got %d/%s", res.Score, res.Grade)
	}
}

func TestScore_Deterministic(t *testing.T) {
	findings := []models.Finding{
		f("cve", "critical", 9.8, map[string]any{"verified": true}),
		f("port", "info", 0, map[string]any{"port": 5900}),
		f("weakness", "critical", 0, map[string]any{"weakness": "default_password"}),
	}
	w := DefaultWeights()
	a := Score(findings, w)
	b := Score(findings, w)
	if a != b {
		t.Fatalf("scoring not deterministic: %+v != %+v", a, b)
	}
	// 100 - (15*1.5 verified crit CVE) - (2 sensitive port) - (40 default pw) = 100 - 64.5 = 35.5 -> 36
	if a.Score != 36 {
		t.Fatalf("expected score 36, got %d (penalty %.1f)", a.Score, a.Penalty)
	}
	if a.Grade != "F" {
		t.Fatalf("expected grade F, got %s", a.Grade)
	}
	if a.HighestCVSS != 9.8 || a.CVECount != 1 || a.CriticalCount != 2 {
		t.Fatalf("unexpected counts: %+v", a)
	}
}

func TestScore_ClampsAtZero(t *testing.T) {
	var findings []models.Finding
	for i := 0; i < 10; i++ {
		findings = append(findings, f("weakness", "critical", 0, map[string]any{"weakness": "default_password"}))
	}
	res := Score(findings, DefaultWeights())
	if res.Score != 0 {
		t.Fatalf("expected clamp to 0, got %d", res.Score)
	}
}

func TestGradeBands(t *testing.T) {
	cases := map[int]string{100: "A", 90: "A", 89: "B", 80: "B", 79: "C", 70: "C", 69: "D", 60: "D", 59: "F", 0: "F"}
	for score, want := range cases {
		if got := Grade(score); got != want {
			t.Errorf("Grade(%d) = %s want %s", score, got, want)
		}
	}
}

func TestVerifiedWeighsMore(t *testing.T) {
	w := DefaultWeights()
	unverified := Score([]models.Finding{f("cve", "high", 8.0, map[string]any{"verified": false})}, w)
	verified := Score([]models.Finding{f("cve", "high", 8.0, map[string]any{"verified": true})}, w)
	if verified.Score >= unverified.Score {
		t.Fatalf("verified CVE should reduce score more: verified=%d unverified=%d", verified.Score, unverified.Score)
	}
}
