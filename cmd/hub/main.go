package main

import (
	"log/slog"
	"net/http"
	"os"
	"sentinel-core/internal/db"
	"sentinel-core/internal/handlers"
	"sentinel-core/internal/services"
)

func main() {
	// 1. Logger einrichten
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	slog.Info("Starte SentinelCore Hub...")

	// 2. Datenbank verbinden & Migrationen ausführen
	db.InitDB() // Falls du eine InitDB-Funktion hast, ansonsten direkt Pool starten
	if err := db.RunMigrations(); err != nil {
		slog.Error("Migrationen fehlgeschlagen", "error", err)
		os.Exit(1)
	}

	// 3. 🚀 Hintergrund-Dienste starten (Die Alert-Engine)
	services.StartAlertEngine()

	// 4. HTTP-Routen registrieren
	http.HandleFunc("/enroll", handlers.HandleAgentEnrollment)
	http.HandleFunc("/security", handlers.RenderSecurityTrustPage)
	http.HandleFunc("/webhook/stripe", handlers.HandleStripeWebhook)

	// 5. Server lauschen lassen
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	slog.Info("Hub erfolgreich gestartet", "port", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		slog.Error("HTTP Server abgestürzt", "error", err)
	}
}
