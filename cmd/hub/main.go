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

	"sentinel-core/internal/api"
	"sentinel-core/internal/auth"
	"sentinel-core/internal/config"
	"sentinel-core/internal/db"
	"sentinel-core/internal/handlers"
	"sentinel-core/internal/middleware"
	"sentinel-core/internal/observability"
	"sentinel-core/internal/services"

	"github.com/redis/go-redis/v9"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	slog.Info("Starte SentinelCore Management Hub (Enterprise Edition)...")
	secretProvider := config.NewProvider()
	startupCtx, startupCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer startupCancel()

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
	handlers.InitSSEBroker()

	// 3. Router einrichten
	privateMux := http.NewServeMux()

	// Öffentliche Endpunkte
	privateMux.HandleFunc("/health", handlers.HandleHealthCheck)
	privateMux.HandleFunc("/healthz", handlers.HandleLiveness)
	privateMux.HandleFunc("/security", handlers.RenderSecurityTrustPage)
	privateMux.HandleFunc("/webhook/stripe", handlers.HandleStripeWebhook)
	jwtSecret, secretErr := secretProvider.Get(startupCtx, "JWT_SECRET")
	if secretErr != nil && os.Getenv("JWT_PRIVATE_KEY_PEM") == "" {
		slog.Error("JWT_SECRET konnte nicht geladen werden", "error", secretErr)
		os.Exit(1)
	}
	if os.Getenv("JWT_PRIVATE_KEY_PEM") == "" || os.Getenv("JWT_PUBLIC_KEY_PEM") == "" {
		if os.Getenv("ALLOW_EPHEMERAL_JWT_KEYS") != "true" {
			slog.Error("JWT_PRIVATE_KEY_PEM und JWT_PUBLIC_KEY_PEM müssen für Enterprise-Betrieb konfiguriert sein")
			os.Exit(1)
		}
	}
	if len(jwtSecret) < 32 {
		slog.Error("JWT_SECRET muss mindestens 32 Zeichen lang sein")
		os.Exit(1)
	}

	// Geschützte API-Endpunkte mit Authentifizierung & Tenant-Isolation
	var agentLimiter *auth.RedisRateLimiter
	tenantRateLimited := func(handler http.Handler) http.Handler {
		return auth.RedisRateLimitMiddleware(agentLimiter, true, handler)
	}
	protectedMetrics := auth.TenantAuthMiddleware(tenantRateLimited(http.HandlerFunc(handlers.IngestMetrics)))
	privateMux.Handle("/api/v1/metrics", protectedMetrics)
	privateMux.HandleFunc("/metrics", observability.Handler)

	privateMux.Handle("/api/v1/metrics/query", middleware.EnforceTenantAndRBAC("customer_view", jwtSecret)(tenantRateLimited(http.HandlerFunc(handlers.GetMetrics))))
	privateMux.Handle("/api/v1/hardening/report", auth.TenantAuthMiddleware(tenantRateLimited(http.HandlerFunc(handlers.HandleHardeningReport))))
	privateMux.Handle("/api/v1/provisioning/trigger", middleware.EnforceTenantAndRBAC("syshaus_tech", jwtSecret)(tenantRateLimited(http.HandlerFunc(handlers.TriggerProvisioning))))

	// UI & HTMX Endpunkte
	privateMux.Handle("/api/v1/ui/hardening/widget", middleware.EnforceTenantAndRBAC("customer_view", jwtSecret)(tenantRateLimited(http.HandlerFunc(handlers.RenderHardeningWidget))))
	privateMux.Handle("/api/v1/ui/tenant/overview", middleware.EnforceTenantAndRBAC("customer_view", jwtSecret)(tenantRateLimited(http.HandlerFunc(handlers.RenderTenantOverview))))
	privateMux.Handle("/api/v1/events", middleware.EnforceTenantAndRBAC("customer_view", jwtSecret)(tenantRateLimited(http.HandlerFunc(handlers.HandleSSEStream))))
	privateMux.Handle("/api/v1/onboarding", middleware.EnforceTenantAndRBAC("syshaus_admin", jwtSecret)(tenantRateLimited(http.HandlerFunc(handlers.GenerateOnboardingPayload))))

	// Versionierte Agenten-Schnittstelle: Bootstrap erfolgt über Enrollment, danach über Secret und optional gebundenes mTLS-Zertifikat.
	var redisClient *redis.Client
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		options, redisErr := redis.ParseURL(redisURL)
		if redisErr != nil {
			slog.Error("REDIS_URL ist ungültig", "error", redisErr)
			os.Exit(1)
		}
		redisClient = redis.NewClient(options)
		agentLimiter = auth.NewRedisRateLimiter(redisClient, 300, time.Minute)
	} else {
		slog.Error("REDIS_URL fehlt; verteilter Agent-Rate-Limiter ist nicht konfiguriert")
		os.Exit(1)
	}
	privateMux.HandleFunc("/readyz", handlers.HandleReadiness(redisClient))
	agentAPI := func(handler http.Handler) http.Handler {
		secured := handlers.RequireAgent(handler)
		return auth.RedisRateLimitMiddleware(agentLimiter, true, secured)
	}
	privateMux.Handle("/agent/v1/heartbeat", agentAPI(http.HandlerFunc(handlers.HandleAgentHeartbeat)))
	privateMux.Handle("/agent/v1/telemetry", agentAPI(http.HandlerFunc(handlers.HandleAgentTelemetry)))
	privateMux.Handle("/agent/v1/hardening/report", agentAPI(http.HandlerFunc(handlers.HandleAgentHardeningReport)))
	privateMux.Handle("/agent/v1/commands", agentAPI(http.HandlerFunc(handlers.HandleAgentCommands)))
	privateMux.Handle("/agent/v1/commands/", agentAPI(http.HandlerFunc(handlers.HandleAgentCommandAck)))
	privateMux.HandleFunc("/downloads/linux/sentinel-agent", handlers.ServeAgentArtifact("linux"))
	privateMux.HandleFunc("/downloads/windows/sentinel-agent.exe", handlers.ServeAgentArtifact("windows"))
	privateMux.HandleFunc("/downloads/linux/install.sh", handlers.ServeInstaller("linux"))
	privateMux.HandleFunc("/downloads/windows/install.ps1", handlers.ServeInstaller("windows"))
	api.SetupRoutes(privateMux, jwtSecret)

	publicPort := os.Getenv("PUBLIC_PORT")
	if publicPort == "" {
		publicPort = "8443"
	}
	privatePort := os.Getenv("PRIVATE_PORT")
	if privatePort == "" {
		privatePort = "9443"
	}

	// On-the-Fly Zertifikats-Check für den 1-Click Demo-Modus / Out-of-the-Box Start
	if _, err := os.Stat("certs/server.crt"); os.IsNotExist(err) && os.Getenv("ALLOW_EPHEMERAL_CERTS") == "true" {
		slog.Info("Keine Zertifikate gefunden. Generiere Self-Signed Zertifikate on-the-fly...")
		if genErr := generateSelfSignedCert(); genErr != nil {
			slog.Error("Konnte keine Self-Signed Zertifikate generieren", "error", genErr)
			os.Exit(1)
		} else {
			slog.Info("Self-Signed Zertifikate erfolgreich unter ./certs/ erstellt.")
		}
	}

	// Public TLS never requests client certificates; enrollment is the only public route.
	publicTLS := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	privateTLS := publicTLS.Clone()
	privateTLS.ClientAuth = tls.RequireAndVerifyClientCert
	var securityManager *auth.SecurityManager

	caCertPEM, caSecretErr := secretProvider.Get(startupCtx, "CA_CERT_PEM")
	if caSecretErr == nil && caCertPEM != "" {
		caCertPool := x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM([]byte(caCertPEM)); ok {
			privateTLS.ClientCAs = caCertPool
			if caKeyPEM, keyErr := secretProvider.Get(startupCtx, "CA_KEY_PEM"); keyErr == nil && caKeyPEM != "" {
				var managerErr error
				securityManager, managerErr = auth.NewSecurityManager([]byte(caCertPEM), []byte(caKeyPEM), jwtSecret)
				if managerErr != nil {
					slog.Error("Konnte Agent-Zertifikatsausstellung nicht initialisieren", "error", managerErr)
					os.Exit(1)
				}
				handlers.ConfigureAgentSecurityManager(securityManager)
			} else {
				slog.Error("CA_KEY_PEM fehlt trotz CA_CERT_PEM; mTLS-Enrollment ist nicht sicher konfiguriert")
				os.Exit(1)
			}
		} else {
			slog.Error("Konnte CA-Zertifikat für mTLS nicht parsen")
			os.Exit(1)
		}
	} else {
		slog.Error("CA_CERT_PEM fehlt; privater mTLS-Listener wird nicht gestartet")
		os.Exit(1)
	}
	privateMux.Handle("/.well-known/jwks.json", auth.JWKSHandler(securityManager))
	publicMux := http.NewServeMux()
	publicMux.Handle("/enroll", auth.RedisRateLimitByIPMiddleware(agentLimiter, true, http.HandlerFunc(handlers.HandleAgentEnrollment)))

	publicServer := &http.Server{
		Addr:              ":" + publicPort,
		Handler:           middleware.SecurityHeadersMiddleware(publicMux),
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig:         publicTLS,
	}
	privateServer := &http.Server{
		Addr:              ":" + privatePort,
		Handler:           middleware.SecurityHeadersMiddleware(privateMux),
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig:         privateTLS,
	}

	// Graceful Shutdown vorbereiten
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("Public Enrollment-Listener lauscht", "port", publicPort)
		if _, err := os.Stat("certs/server.crt"); err == nil {
			if err := publicServer.ListenAndServeTLS("certs/server.crt", "certs/server.key"); err != nil && err != http.ErrServerClosed {
				slog.Error("HTTPS Server abgestürzt", "error", err)
			}
		} else {
			slog.Error("TLS-Zertifikate fehlen; HTTP-Fallback ist für den Beta-Betrieb deaktiviert")
		}
	}()
	go func() {
		slog.Info("Privater mTLS-Listener lauscht", "port", privatePort)
		if err := privateServer.ListenAndServeTLS("certs/server.crt", "certs/server.key"); err != nil && err != http.ErrServerClosed {
			slog.Error("Privater mTLS-Server abgestürzt", "error", err)
		}
	}()

	<-stop
	slog.Info("Herunterfahren des Hub Servers eingeleitet...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := publicServer.Shutdown(ctx); err != nil {
		slog.Error("Fehler beim geordneten Server-Shutdown", "error", err)
	}
	if err := privateServer.Shutdown(ctx); err != nil {
		slog.Error("Fehler beim mTLS-Shutdown", "error", err)
	}
	slog.Info("Hub Server erfolgreich beendet.")
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
