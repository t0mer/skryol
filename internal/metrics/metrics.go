// Package metrics defines Skryol's Prometheus collectors (namespace skryol_).
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const namespace = "skryol"

// Metrics bundles the application collectors.
type Metrics struct {
	Registry *prometheus.Registry

	ScansTotal       *prometheus.CounterVec
	ScanDuration     *prometheus.HistogramVec
	ShodanRequests   *prometheus.CounterVec
	ShodanKeyCredits *prometheus.GaugeVec
	AlertsFired      *prometheus.CounterVec
	AssetScore       *prometheus.GaugeVec
	HTTPRequests     *prometheus.CounterVec
}

// New builds the collectors registered on a private registry.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGoCollector())
	reg.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	factory := promauto.With(reg)

	return &Metrics{
		Registry: reg,
		ScansTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "scans_total",
			Help: "Total asset scans by status.",
		}, []string{"status"}),
		ScanDuration: factory.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Name: "scan_duration_seconds",
			Help:    "Per-asset scan duration in seconds.",
			Buckets: prometheus.ExponentialBuckets(1, 2, 10),
		}, []string{"asset_type"}),
		ShodanRequests: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "shodan_requests_total",
			Help: "Total Shodan API requests by endpoint and outcome.",
		}, []string{"endpoint", "outcome"}),
		ShodanKeyCredits: factory.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Name: "shodan_key_credits",
			Help: "Remaining credits per Shodan key and credit type.",
		}, []string{"key", "type"}),
		AlertsFired: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "alerts_fired_total",
			Help: "Total alert firings by condition.",
		}, []string{"condition"}),
		AssetScore: factory.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Name: "asset_score",
			Help: "Latest security score per asset.",
		}, []string{"asset"}),
		HTTPRequests: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "http_requests_total",
			Help: "Total HTTP requests by method and status.",
		}, []string{"method", "status"}),
	}
}
