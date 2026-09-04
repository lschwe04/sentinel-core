// internal/handlers/stripe_webhook.go
package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sentinel-core/internal/db"
	"time"

	"github.com/stripe/stripe-go/v74/webhook"
)

// HandleStripeWebhook verarbeitet Stripe-Events mit scharfer Webhook-Signaturprüfung für den Live-Betrieb
func HandleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	const MaxBodyBytes = int64(65536)
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	payload, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	// Webhook-Secret aus Umgebungsvariable laden
	endpointSecret := os.Getenv("STRIPE_WEBHOOK_SECRET")
	if endpointSecret == "" {
		http.Error(w, "CRITICAL: STRIPE_WEBHOOK_SECRET is not configured", http.StatusInternalServerError)
		return
	}

	// Live-Signaturprüfung via Stripe SDK
	signatureHeader := r.Header.Get("Stripe-Signature")
	event, err := webhook.ConstructEvent(payload, signatureHeader, endpointSecret)
	if err != nil {
		http.Error(w, "Webhook signature verification failed", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Event-Daten aus dem Roh-Payload des validierten Events extrahieren
	var objectMap map[string]interface{}
	if err := json.Unmarshal(event.Data.Raw, &objectMap); err != nil {
		http.Error(w, "Invalid event data JSON", http.StatusBadRequest)
		return
	}

	switch event.Type {
	case "customer.subscription.created", "customer.subscription.updated":
		customerID, _ := objectMap["customer"].(string)
		status, _ := objectMap["status"].(string) // z.B. "active", "past_due", "canceled"

		dbStatus := "inactive"
		if status == "active" {
			dbStatus = "active"
		}

		query := `UPDATE tenants SET subscription_status = $1 WHERE stripe_customer_id = $2`
		_, _ = db.Pool.Exec(ctx, query, dbStatus, customerID)

	case "customer.subscription.deleted":
		customerID, _ := objectMap["customer"].(string)
		query := `UPDATE tenants SET subscription_status = 'inactive' WHERE stripe_customer_id = $2`
		_, _ = db.Pool.Exec(ctx, query, customerID)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"received": true}`))
}
