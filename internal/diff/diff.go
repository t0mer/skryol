// Package diff compares two scans of an asset and produces a structured,
// persisted summary of what changed. The summary drives both the "what changed"
// UI and the alert rule engine.
package diff

import (
	"github.com/t0mer/skryol/internal/models"
)

// identity uniquely keys a finding within an asset across scans.
type identity struct {
	kind     string
	key      string
	targetIP string
}

func idOf(f models.Finding) identity {
	return identity{kind: f.Kind, key: f.Key, targetIP: f.TargetIP}
}

// Compute builds the structured diff of a "to" scan against a "from" scan.
// from may be nil (first scan), in which case every current finding is "added".
func Compute(from, to *models.Scan, fromFindings, toFindings []models.Finding) models.DiffSummary {
	prev := map[identity]models.Finding{}
	for _, f := range fromFindings {
		prev[idOf(f)] = f
	}
	curr := map[identity]models.Finding{}
	for _, f := range toFindings {
		curr[idOf(f)] = f
	}

	summary := models.DiffSummary{
		ToScanID:    to.ID,
		Added:       []models.FindingChange{},
		Removed:     []models.FindingChange{},
		CVSSChanged: []models.CVSSChange{},
	}
	if from != nil {
		summary.FromScanID = from.ID
	}

	// Added + CVSS changes.
	for id, f := range curr {
		p, existed := prev[id]
		if !existed {
			summary.Added = append(summary.Added, toChange(f))
			continue
		}
		if f.CVSS != p.CVSS {
			summary.CVSSChanged = append(summary.CVSSChanged, models.CVSSChange{
				Kind:     f.Kind,
				Key:      f.Key,
				TargetIP: f.TargetIP,
				FromCVSS: p.CVSS,
				ToCVSS:   f.CVSS,
			})
		}
	}
	// Removed.
	for id, f := range prev {
		if _, still := curr[id]; !still {
			summary.Removed = append(summary.Removed, toChange(f))
		}
	}

	sortChanges(summary.Added)
	sortChanges(summary.Removed)
	sortCVSS(summary.CVSSChanged)

	// Score / grade deltas.
	summary.ScoreTo = to.Score
	summary.GradeTo = to.Grade
	if from != nil {
		summary.ScoreFrom = from.Score
		summary.GradeFrom = from.Grade
	}
	if summary.ScoreFrom != nil && summary.ScoreTo != nil {
		summary.ScoreDelta = *summary.ScoreTo - *summary.ScoreFrom
	}

	// Reachability. A scan is "online" if it observed any ports/services.
	summary.Online = isOnline(toFindings)
	if from != nil {
		summary.WasOnline = isOnline(fromFindings)
		summary.WentOffline = summary.WasOnline && !summary.Online
		summary.CameOnline = !summary.WasOnline && summary.Online
	} else {
		summary.WasOnline = summary.Online
	}

	return summary
}

func isOnline(findings []models.Finding) bool {
	for _, f := range findings {
		if f.Kind == "port" || f.Kind == "service" {
			return true
		}
	}
	return false
}

func toChange(f models.Finding) models.FindingChange {
	return models.FindingChange{
		Kind:     f.Kind,
		Key:      f.Key,
		TargetIP: f.TargetIP,
		Severity: f.Severity,
		CVSS:     f.CVSS,
		Detail:   f.Detail,
	}
}

func sortChanges(cs []models.FindingChange) {
	// Insertion order is non-deterministic (map iteration); sort for stability.
	for i := 1; i < len(cs); i++ {
		for j := i; j > 0 && less(cs[j], cs[j-1]); j-- {
			cs[j], cs[j-1] = cs[j-1], cs[j]
		}
	}
}

func less(a, b models.FindingChange) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.TargetIP != b.TargetIP {
		return a.TargetIP < b.TargetIP
	}
	return a.Key < b.Key
}

func sortCVSS(cs []models.CVSSChange) {
	for i := 1; i < len(cs); i++ {
		for j := i; j > 0 && cvssLess(cs[j], cs[j-1]); j-- {
			cs[j], cs[j-1] = cs[j-1], cs[j]
		}
	}
}

func cvssLess(a, b models.CVSSChange) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	return a.Key < b.Key
}
