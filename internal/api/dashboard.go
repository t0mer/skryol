package api

import (
	"net/http"

	"github.com/t0mer/skryol/internal/models"
)

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	summaries, err := s.DB.AssetSummaries(r.Context())
	if err != nil {
		s.Log.Error("dashboard summaries", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to build dashboard")
		return
	}
	trend, err := s.DB.FleetScoreTrend(r.Context(), 30)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to build trend")
		return
	}

	dash := models.Dashboard{
		Assets:            summaries,
		Trend:             trend,
		GradeDistribution: map[string]int{},
	}
	if dash.Assets == nil {
		dash.Assets = []models.AssetSummary{}
	}
	if dash.Trend == nil {
		dash.Trend = []models.TrendPoint{}
	}

	var scoreSum, scored int
	for _, a := range summaries {
		dash.TotalAssets++
		if a.Enabled {
			dash.EnabledAssets++
		}
		if a.LastScanID != "" {
			dash.ScannedAssets++
		}
		if a.Score != nil {
			scoreSum += *a.Score
			scored++
		}
		if a.Grade != "" {
			dash.GradeDistribution[a.Grade]++
		}
		dash.CriticalIssues += a.CriticalCount
		dash.TotalCVEs += a.CVECount
	}
	if scored > 0 {
		dash.AverageScore = float64(scoreSum) / float64(scored)
	}

	writeJSON(w, http.StatusOK, dash)
}
