package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sentinel-core/internal/db"
	"time"
	// Optional oder native JSON-Map parsing
)

// Einfacher Webhook-Empfänger für Stripe Events
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

	// In Produktion: Hier via stripe-go Signature prüfen!
	// event, err := webhook.ConstructEvent(payload, r.Header.Get("Stripe-Signature"), endpointSecret)

	var event map[string]interface{}
	if err := json.Unmarshal(payload, &event); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	eventType, _ := event["type"].(string)
	dataObject, _ := event["data"].(map[string]interface{})
	objectMap, _ := dataObject["object"].(map[string]interface{})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	switch eventType {
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
