package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sentinel-core/internal/collector"
	"sentinel-core/internal/executor"
	"sentinel-core/internal/network"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

type MetricsPayload struct {
	NodeID    string  `json:"node_id"`
	CPUUsage  float64 `json:"cpu_usage_pct"`
	RAMUsage  float64 `json:"ram_usage_pct"`
	Timestamp string  `json:"timestamp"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	mux := http.NewServeMux()

	mux.Handle("POST /trigger-ansible", enforceVPN(http.HandlerFunc(executor.RunAnsiblePlaybook)))
	mux.Handle("GET /backup-status", enforceVPN(http.HandlerFunc(collector.CheckResticStatus)))

	server := &http.Server{
		Addr:         "10.0.0.15:9443",
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	// Start des Hintergrund-Workers für Telemetrie (Metriken an Hub senden)
	go startMetricsReporter("node-1234-prod", "https://10.0.0.1:8443/api/v1/metrics")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("Sentinel Agent gestartet auf WireGuard Interface", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Agent Server abgestürzt", "error", err)
			os.Exit(1)
		}
	}()

	<-stop
	slog.Info("Fahre Agent sicher herunter...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)
}

func startMetricsReporter(nodeID string, hubMetricsURL string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		cpuPercentages, err := cpu.Percent(0, false)
		var cpuUsage float64 = 0.0
		if err == nil && len(cpuPercentages) > 0 {
			cpuUsage = cpuPercentages[0]
		}

		vmStat, err := mem.VirtualMemory()
		var ramUsage float64 = 0.0
		if err == nil {
			ramUsage = vmStat.UsedPercent
		}

		payload := MetricsPayload{
			NodeID:    nodeID,
			CPUUsage:  cpuUsage,
			RAMUsage:  ramUsage,
			Timestamp: time.Now().Format(time.RFC3339),
		}

		data, err := json.Marshal(payload)
		if err != nil {
			continue
		}

		resp, err := http.Post(hubMetricsURL, "application/json", bytes.NewBuffer(data))
		if err != nil {
			slog.Warn("Konnte Metriken nicht an Hub senden", "error", err)
			continue
		}
		resp.Body.Close()
	}
}

func enforceVPN(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := network.ValidateVPNConnection(r.RemoteAddr); err != nil {
			slog.Warn("Unautorisierter Zugriffserfassungsversuch blockiert", "remote", r.RemoteAddr)
			http.Error(w, "Forbidden: Invalid network path", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
