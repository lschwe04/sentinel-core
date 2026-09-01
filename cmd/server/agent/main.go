package main

import (
	"log/slog"
	"net/http"
	"os"

	"sentinel-agent/internal/collector"
	"sentinel-agent/internal/executor"
)

func main() {
	slog.Info("Starte Sentinel Agent...")

	mux := http.NewServeMux()

	// Agent Endpunkte
	mux.HandleFunc("POST /trigger-ansible", executor.RunAnsiblePlaybook)
	mux.HandleFunc("GET /backup-status", collector.CheckResticStatus)

	// Nur an WireGuard Interface (z.B. wg0) binden
	server := &http.Server{
		Addr:    "10.0.0.15:9443", // Lokale WG-IP des Nodes
		Handler: mux,
	}

	// In Produktion zwingend ListenAndServeTLS mit mTLS
	if err := server.ListenAndServe(); err != nil {
		slog.Error("Agent Fehler", "error", err)
		os.Exit(1)
	}
}
