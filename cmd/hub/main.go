package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sentinel-core/internal/auth"
	"sentinel-core/internal/db"
	"sentinel-core/internal/handlers"
	"sentinel-core/internal/middleware"
	"sentinel-core/internal/services"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	slog.Info("Starte SentinelCore Management Hub...")

	// 1. Datenbank-Pool verbinden & Indizierte Migrationen ausführen
	if err := db.InitDB(); err != nil {
		slog.Error("Datenbank-Initialisierung fehlgeschlagen", "error", err)
		os.Exit(1)
	}
	defer db.CloseDB()

	if err := db.RunMigrations(); err != nil {
		slog.Error("Datenbank-Migrationen fehlgeschlagen", "error", err)
		os.Exit(1)
	}

	// 2. Alert Engine im Hintergrund starten
	services.StartAlertEngine()

	// 3. Router einrichten
	mux := http.NewServeMux()

	// Öffentliche Endpunkte
	mux.HandleFunc("/health", handlers.HandleHealthCheck)
	mux.HandleFunc("/enroll", handlers.HandleAgentEnrollment)
	mux.HandleFunc("/security", handlers.RenderSecurityTrustPage)
	mux.HandleFunc("/webhook/stripe", handlers.HandleStripeWebhook)

	// Geschützte API-Endpunkte mit Authentifizierung & Tenant-Isolation
	protectedMetrics := auth.TenantAuthMiddleware(http.HandlerFunc(handlers.IngestMetrics))
	mux.Handle("/api/v1/metrics", protectedMetrics)

	mux.HandleFunc("/api/v1/metrics/query", handlers.GetMetrics)
	mux.HandleFunc("/api/v1/hardening/report", handlers.HandleHardeningReport)
	mux.HandleFunc("/api/v1/provisioning/trigger", handlers.TriggerProvisioning)

	// UI & HTMX Endpunkte
	mux.HandleFunc("/api/v1/ui/hardening/widget", handlers.RenderHardeningWidget)
	mux.HandleFunc("/api/v1/ui/tenant/overview", handlers.RenderTenantOverview)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8443"
	}

	server := &http.Server{
		Addr: ":" + port,
		// Globale Sicherheits-Middleware aktivieren
		Handler:           middleware.SecurityHeadersMiddleware(mux),
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}

	// Graceful Shutdown vorbereiten
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("Hub Server lauscht", "port", port)
		// Falls Zertifikate vorhanden sind, mTLS nutzen, sonst HTTP/TLS Fallback
		if _, err := os.Stat("certs/server.crt"); err == nil {
			if err := server.ListenAndServeTLS("certs/server.crt", "certs/server.key"); err != nil && err != http.ErrServerClosed {
				slog.Error("HTTPS Server abgestürzt", "error", err)
			}
		} else {
			slog.Warn("Keine Zertifikate in ./certs/ gefunden, starte im HTTP Modus für Entwicklung")
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("HTTP Server abgestürzt", "error", err)
			}
		}
	}()

	<-stop
	slog.Info("Herunterfahren des Hub Servers eingeleitet...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("Fehler beim geordneten Server-Shutdown", "error", err)
	} else {
		slog.Info("Hub Server erfolgreich beendet.")
	}
}
