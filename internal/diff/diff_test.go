package diff

import (
	"testing"

	"github.com/t0mer/skryol/internal/models"
)

func mkFinding(kind, key, ip string, cvss float64) models.Finding {
	return models.Finding{Kind: kind, Key: key, TargetIP: ip, CVSS: cvss}
}

func intp(i int) *int { return &i }

func TestCompute_AddedRemoved(t *testing.T) {
	from := &models.Scan{ID: "s1", Score: intp(80), Grade: "B"}
	to := &models.Scan{ID: "s2", Score: intp(50), Grade: "F"}

	fromF := []models.Finding{
		mkFinding("port", "22", "1.1.1.1", 0),
		mkFinding("port", "80", "1.1.1.1", 0),
		mkFinding("cve", "CVE-1", "1.1.1.1", 5.0),
	}
	toF := []models.Finding{
		mkFinding("port", "22", "1.1.1.1", 0),                   // unchanged
		mkFinding("port", "443", "1.1.1.1", 0),                  // added
		mkFinding("cve", "CVE-1", "1.1.1.1", 9.0),               // cvss changed
		mkFinding("weakness", "default_password", "1.1.1.1", 0), // added
	}

	d := Compute(from, to, fromF, toF)

	if len(d.Added) != 2 {
		t.Fatalf("expected 2 added, got %d: %+v", len(d.Added), d.Added)
	}
	// port 80 and cve? no — cve still present. Removed should be port 80 only.
	if len(d.Removed) != 1 || d.Removed[0].Key != "80" {
		t.Fatalf("expected port 80 removed, got %+v", d.Removed)
	}
	if len(d.CVSSChanged) != 1 || d.CVSSChanged[0].FromCVSS != 5.0 || d.CVSSChanged[0].ToCVSS != 9.0 {
		t.Fatalf("expected CVE-1 cvss change 5->9, got %+v", d.CVSSChanged)
	}
	if d.ScoreDelta != -30 {
		t.Fatalf("expected score delta -30, got %d", d.ScoreDelta)
	}
	if d.GradeFrom != "B" || d.GradeTo != "F" {
		t.Fatalf("unexpected grades: %s -> %s", d.GradeFrom, d.GradeTo)
	}
}

func TestCompute_FirstScanAllAdded(t *testing.T) {
	to := &models.Scan{ID: "s1", Score: intp(90), Grade: "A"}
	toF := []models.Finding{
		mkFinding("port", "22", "1.1.1.1", 0),
		mkFinding("cve", "CVE-9", "1.1.1.1", 7.5),
	}
	d := Compute(nil, to, nil, toF)
	if len(d.Added) != 2 || len(d.Removed) != 0 {
		t.Fatalf("expected all added on first scan, got added=%d removed=%d", len(d.Added), len(d.Removed))
	}
	if d.FromScanID != "" {
		t.Fatalf("expected empty from scan id, got %q", d.FromScanID)
	}
}

func TestCompute_Reachability(t *testing.T) {
	from := &models.Scan{ID: "s1"}
	to := &models.Scan{ID: "s2"}
	// Was online (had ports), now offline (no ports/services).
	fromF := []models.Finding{mkFinding("port", "22", "1.1.1.1", 0)}
	var toF []models.Finding
	d := Compute(from, to, fromF, toF)
	if !d.WentOffline || d.CameOnline {
		t.Fatalf("expected went offline, got %+v", d)
	}

	d2 := Compute(from, to, nil, []models.Finding{mkFinding("service", "22/ssh", "1.1.1.1", 0)})
	if !d2.CameOnline {
		t.Fatalf("expected came online, got %+v", d2)
	}
}
