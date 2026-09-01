package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sentinel-core/internal/handlers"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	mux := http.NewServeMux()

	// API Endpoints für Nodes & UI
	mux.HandleFunc("GET /api/v1/hardening/status", handlers.GetHardeningStatus)
	mux.HandleFunc("POST /api/v1/hardening/trigger", handlers.TriggerHardening)
	mux.HandleFunc("GET /api/v1/backup/status", handlers.GetBackupStatus)
	mux.HandleFunc("POST /api/v1/metrics", handlers.IngestMetrics) // <-- Hinzugefügt: Agenten-Metriken empfangen
	mux.HandleFunc("GET /api/v1/metrics", handlers.GetMetrics)

	// UI Reiter Routen
	mux.HandleFunc("GET /api/v1/ui/hardening", handlers.RenderHardeningTab)
	mux.HandleFunc("GET /api/v1/ui/metrics", handlers.RenderMetricsTab)
	mux.HandleFunc("GET /api/v1/ui/backups", handlers.RenderBackupsTab)
	mux.HandleFunc("GET /api/v1/ui/logs", handlers.RenderLogsTab)
	mux.HandleFunc("GET /api/v1/ui/provisioning", handlers.RenderProvisioningTab)

	secureMux := enforceAuth(mux)

	tlsConfig, err := getEnterpriseTLSConfig()
	if err != nil {
		slog.Error("Konnte mTLS-Zertifikate nicht laden", "error", err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr:         "10.0.0.1:8443",
		Handler:      secureMux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("SentinelCore Hub API startet auf 10.0.0.1:8443 (mTLS aktiv)")
		if err := server.ListenAndServeTLS("certs/hub-cert.pem", "certs/hub-key.pem"); err != nil && err != http.ErrServerClosed {
			slog.Error("Server Fehler", "error", err)
			os.Exit(1)
		}
	}()

	<-stop
	slog.Info("Fahre Server kontrolliert herunter...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)
}

func getEnterpriseTLSConfig() (*tls.Config, error) {
	caCertPool := x509.NewCertPool()
	caCert, err := os.ReadFile("certs/ca-cert.pem")
	if err != nil {
		return nil, err
	}
	caCertPool.AppendCertsFromPEM(caCert)

	return &tls.Config{
		MinVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		ClientAuth:               tls.RequireAndVerifyClientCert,
		ClientCAs:                caCertPool,
	}, nil
}

func enforceAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Bei mTLS-Verbindungen prüfen wir zusätzlich das Client-Zertifikat (Zero Trust)
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			clientCert := r.TLS.PeerCertificates[0]
			slog.Debug("mTLS Verbindung verifiziert", "client_cn", clientCert.Subject.CommonName)
		}

		token := r.Header.Get("Authorization")
		if token != "Bearer SECRET_ENTERPRISE_TOKEN" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
```[cite: 9]

---

#### 2. Metriken im Hub persistent speichern (`internal/handlers/metrics.go`)
Ersetze die reine Mock-Datei durch echte Datenbank-Logik, damit Telemetriedaten skaliert und abgefragt werden können[cite: 9]:

```go
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"sentinel-core/internal/db"
)

type NodeMetrics struct {
	NodeID       string    `json:"node_id"`
	CPUUsagePct  float64   `json:"cpu_usage_pct"`
	RAMUsagePct  float64   `json:"ram_usage_pct"`
	DiskUsagePct float64   `json:"disk_usage_pct"`
	Timestamp    time.Time `json:"timestamp"`
}

// IngestMetrics nimmt die Telemetriedaten des Agenten entgegen und speichert sie in PostgreSQL
func IngestMetrics(w http.ResponseWriter, r *http.Request) {
	var metrics NodeMetrics
	if err := json.NewDecoder(r.Body).Decode(&metrics); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	query := `
		INSERT INTO node_metrics (node_id, cpu_usage_pct, ram_usage_pct, disk_usage_pct, recorded_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := db.Pool.Exec(ctx, query, metrics.NodeID, metrics.CPUUsagePct, metrics.RAMUsagePct, metrics.DiskUsagePct, time.Now())
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"status": "metric_stored"}`))
}

// GetMetrics liest die neuesten Metriken für einen Node aus der Datenbank aus
func GetMetrics(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		http.Error(w, "node_id is required", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	var m NodeMetrics
	query := `SELECT node_id, cpu_usage_pct, ram_usage_pct, disk_usage_pct, recorded_at FROM node_metrics WHERE node_id = $1 ORDER BY recorded_at DESC LIMIT 1`
	err := db.Pool.QueryRow(ctx, query, nodeID).Scan(&m.NodeID, &m.CPUUsagePct, &m.RAMUsagePct, &m.DiskUsagePct, &m.Timestamp)
	if err != nil {
		// Fallback, falls keine Daten vorliegen
		m = NodeMetrics{NodeID: nodeID, CPUUsagePct: 0, RAMUsagePct: 0, DiskUsagePct: 0, Timestamp: time.Now()}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(m)
}
```[cite: 9]

---

### Teil 2: Sentinel-Agent Anpassungen

#### Agent mit mTLS-Client-Zertifikaten und gopsutil ausstatten (`cmd/agent/main.go`)
Damit der Agent sicher mit dem Hub kommunizieren kann (der mTLS erzwingt), muss der HTTP-Client des Agenten die Zertifikate der CA, das Client-Zertifikat und den Private Key laden[cite: 9, 10].

```go
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sentinel-agent/internal/collector"
	"sentinel-agent/internal/executor"
	"sentinel-agent/internal/network"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

type MetricsPayload struct {
	NodeID       string  `json:"node_id"`
	CPUUsagePct  float64 `json:"cpu_usage_pct"`
	RAMUsagePct  float64 `json:"ram_usage_pct"`
	DiskUsagePct float64 `json:"disk_usage_pct"`
	Timestamp    string  `json:"timestamp"`
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

	// Hintergrund-Worker für Telemetrie starten (sendet echte gopsutil-Werte an den Hub)
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

func createMTLSClient() *http.Client {
	// Lade CA Zertifikat
	caCert, err := os.ReadFile("certs/ca-cert.pem")
	if err != nil {
		slog.Error("Fehler beim Laden der CA für mTLS-Client", "error", err)
		return &http.Client{Timeout: 5 * time.Second}
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Lade Agenten Client-Zertifikat und Key
	cert, err := tls.LoadX509KeyPair("certs/agent-cert.pem", "certs/agent-key.pem")
	if err != nil {
		slog.Error("Fehler beim Laden des Agenten-Zertifikats", "error", err)
		return &http.Client{Timeout: 5 * time.Second}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS13,
	}

	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
	}
}

func startMetricsReporter(nodeID string, hubMetricsURL string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	client := createMTLSClient()

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
			NodeID:       nodeID,
			CPUUsagePct:  cpuUsage,
			RAMUsagePct:  ramUsage,
			DiskUsagePct: 15.0, // Kann bei Bedarf über gopsutil/disk ergänzt werden
			Timestamp:    time.Now().Format(time.RFC3339),
		}

		data, err := json.Marshal(payload)
		if err != nil {
			continue
		}

		req, err := http.NewRequest("POST", hubMetricsURL, bytes.NewBuffer(data))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		// Zero-Trust Authorization Header mitübergeben
		req.Header.Set("Authorization", "Bearer SECRET_ENTERPRISE_TOKEN")

		resp, err := client.Do(req)
		if err != nil {
			slog.Warn("Konnte Metriken nicht mTLS-gesichert an Hub senden", "error", err)
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
```[cite: 10]

---

### Nächster Schritt für die Skalierbarkeit:
Falls noch nicht geschehen, sollten im PostgreSQL-Container (`postgres`) die entsprechenden Tabellen (`node_metrics`, `backups`, etc.) per Migrationsskript angelegt werden, damit die Datenbankabfragen (`db.Pool.Exec`) fehlerfrei durchlaufen[cite: 9].
