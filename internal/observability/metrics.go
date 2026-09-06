package observability

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

var (
	activeAgents         atomic.Int64
	fimAlerts            atomic.Int64
	metricsIngested      atomic.Int64
	authFailures         atomic.Int64
	ingestionNanoseconds atomic.Int64
)

func AgentConnected()    { activeAgents.Add(1) }
func AgentDisconnected() { activeAgents.Add(-1) }
func FIMAlert()          { fimAlerts.Add(1) }
func MetricIngested(duration time.Duration) {
	metricsIngested.Add(1)
	ingestionNanoseconds.Add(duration.Nanoseconds())
}
func AuthFailure() { authFailures.Add(1) }

func Handler(w http.ResponseWriter, _ *http.Request) {
	count := metricsIngested.Load()
	average := float64(0)
	if count > 0 {
		average = float64(ingestionNanoseconds.Load()) / float64(count) / float64(time.Millisecond)
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP sentinel_active_agents Active authenticated agents.\n# TYPE sentinel_active_agents gauge\nsentinel_active_agents %d\n", activeAgents.Load())
	fmt.Fprintf(w, "# HELP sentinel_fim_alerts_total FIM alerts processed.\n# TYPE sentinel_fim_alerts_total counter\nsentinel_fim_alerts_total %d\n", fimAlerts.Load())
	fmt.Fprintf(w, "# HELP sentinel_metrics_ingested_total Metrics ingested.\n# TYPE sentinel_metrics_ingested_total counter\nsentinel_metrics_ingested_total %d\n", count)
	fmt.Fprintf(w, "# HELP sentinel_auth_failures_total Authentication failures.\n# TYPE sentinel_auth_failures_total counter\nsentinel_auth_failures_total %d\n", authFailures.Load())
	fmt.Fprintf(w, "# HELP sentinel_ingestion_latency_ms_avg Average ingestion latency in milliseconds.\n# TYPE sentinel_ingestion_latency_ms_avg gauge\nsentinel_ingestion_latency_ms_avg %.3f\n", average)
}
