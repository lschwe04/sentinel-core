package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
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

	slog.Info("Starte SentinelCore Management Hub (Enterprise Edition)...")

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

	// On-the-Fly Zertifikats-Check für den 1-Click Demo-Modus / Out-of-the-Box Start
	if _, err := os.Stat("certs/server.crt"); os.IsNotExist(err) {
		slog.Info("Keine Zertifikate gefunden. Generiere Self-Signed Zertifikate on-the-fly...")
		if genErr := generateSelfSignedCert(); genErr != nil {
			slog.Error("Konnte keine Self-Signed Zertifikate generieren", "error", genErr)
		} else {
			slog.Info("Self-Signed Zertifikate erfolgreich unter ./certs/ erstellt.")
		}
	}

	// mTLS Client CA Pool für Enterprise-Sicherheit konfigurieren
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if caCertPEM := os.Getenv("CA_CERT_PEM"); caCertPEM != "" {
		caCertPool := x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM([]byte(caCertPEM)); ok {
			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			slog.Info("mTLS Client-Zertifikatsverifizierung erfolgreich aktiviert.")
		} else {
			slog.Warn("Konnte CA-Zertifikat für mTLS nicht parsen, falle auf Standard-TLS zurück.")
		}
	}

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           middleware.SecurityHeadersMiddleware(mux),
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig:         tlsConfig,
	}

	// Graceful Shutdown vorbereiten
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("Hub Server lauscht", "port", port)
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

// Hilfsfunktion zur automatischen Generierung von Entwicklung-/Demo-Zertifikaten
func generateSelfSignedCert() error {
	if err := os.MkdirAll("certs", 0755); err != nil {
		return err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"SentinelCore Demo Inc."},
			CommonName:   "SentinelCore Hub",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost", "hub"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create("certs/server.crt")
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	keyOut, err := os.Create("certs/server.key")
	if err != nil {
		return err
	}
	defer keyOut.Close()
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		return err
	}

	return nil
}
